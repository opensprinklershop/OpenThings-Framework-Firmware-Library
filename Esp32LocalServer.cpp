#if defined(ESP32)
#include "Esp32LocalServer.h"
#include <lwip/sockets.h>  // For sockaddr_in
#include <mbedtls/error.h>  // For mbedtls_strerror

#ifndef OTF_DEBUG
  #if defined(SERIAL_DEBUG) || defined(OTF_DEBUG_MODE)
    #define OTF_DEBUG(...) Serial.printf(__VA_ARGS__)
  #else
    #define OTF_DEBUG(...)
  #endif
#endif

// ============================================================================
// Custom BIO callbacks for WiFiClient (non-blocking I/O)
// ============================================================================

// Context structure to pass WiFiClient to mbedTLS
struct wifi_client_context {
  WiFiClient* client;
  unsigned long last_activity;
};

// Custom send callback for WiFiClient
static int wifi_client_send(void* ctx, const unsigned char* buf, size_t len) {
  wifi_client_context* wctx = (wifi_client_context*)ctx;
  if (!wctx || !wctx->client) {
    Serial.printf("wifi_client_send: invalid context\n");
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  if (!wctx->client->connected()) {
    Serial.printf("wifi_client_send: client disconnected\n");
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  size_t written = wctx->client->write(buf, len);
  if (written > 0) {
    wctx->last_activity = millis();
    Serial.printf("wifi_client_send: wrote %d bytes\n", written);
    return written;
  }
  
  // If nothing written, check if still connected
  if (!wctx->client->connected()) {
    Serial.printf("wifi_client_send: client disconnected after write attempt\n");
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  Serial.printf("wifi_client_send: write returned 0, returning WANT_WRITE\n");
  return MBEDTLS_ERR_SSL_WANT_WRITE;
}

// Custom receive callback for WiFiClient
static int wifi_client_recv(void* ctx, unsigned char* buf, size_t len) {
  wifi_client_context* wctx = (wifi_client_context*)ctx;
  if (!wctx || !wctx->client) {
    Serial.printf("wifi_client_recv: invalid context\n");
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  if (!wctx->client->connected()) {
    Serial.printf("wifi_client_recv: client disconnected\n");
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  int available = wctx->client->available();
  if (available > 0) {
    size_t to_read = (available < (int)len) ? available : len;
    size_t actually_read = wctx->client->readBytes(buf, to_read);
    if (actually_read > 0) {
      wctx->last_activity = millis();
      Serial.printf("wifi_client_recv: read %d bytes\n", actually_read);
      return actually_read;
    }
  }
  
  // Check for timeout (10 seconds)
  unsigned long idle_time = millis() - wctx->last_activity;
  if (idle_time > 10000) {
    Serial.printf("wifi_client_recv: timeout after %lu ms\n", idle_time);
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  
  // No data available yet
  Serial.printf("wifi_client_recv: no data, returning WANT_READ (idle: %lu ms)\n", idle_time);
  return MBEDTLS_ERR_SSL_WANT_READ;
}

// ============================================================================
// WiFiSecureServer Implementation (SSL/TLS with mbedTLS)
// ============================================================================

WiFiSecureServer::WiFiSecureServer(uint16_t port, unsigned char* cert, uint16_t certLen, 
                                   unsigned char* key, uint16_t keyLen)
  : server(port), port(port),
    certData(cert), certLength(certLen),
    keyData(key), keyLength(keyLen), initialized(false) {
  
  // Initialize mbedTLS structures
  mbedtls_ssl_config_init(&sslConf);
  mbedtls_x509_crt_init(&serverCert);
  mbedtls_pk_init(&serverKey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctrDrbg);
}

WiFiSecureServer::~WiFiSecureServer() {
  mbedtls_ssl_config_free(&sslConf);
  mbedtls_x509_crt_free(&serverCert);
  mbedtls_pk_free(&serverKey);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctrDrbg);
}

bool WiFiSecureServer::setupSSLContext() {
  int ret;
  
  // Seed the random number generator
  const char* pers = "esp32_https_server";
  ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers, strlen(pers));
  if (ret != 0) {
    OTF_DEBUG("mbedtls_ctr_drbg_seed failed: -0x%x\n", -ret);
    return false;
  }
  
  // Setup SSL configuration defaults for server
  ret = mbedtls_ssl_config_defaults(&sslConf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    OTF_DEBUG("mbedtls_ssl_config_defaults failed: -0x%x\n", -ret);
    return false;
  }
  
  // Set random number generator
  mbedtls_ssl_conf_rng(&sslConf, mbedtls_ctr_drbg_random, &ctrDrbg);
  
  // Optional: Disable client authentication (we're a server, don't need client certs)
  mbedtls_ssl_conf_authmode(&sslConf, MBEDTLS_SSL_VERIFY_NONE);
  
  // Optimize for low memory: disable session tickets and cache
  mbedtls_ssl_conf_session_tickets(&sslConf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
  
  OTF_DEBUG("SSL context configured\n");
  return true;
}

bool WiFiSecureServer::setupCertificate() {
  int ret;
  
  Serial.printf("Loading certificate: %d bytes\n", certLength);
  Serial.printf("Loading private key: %d bytes\n", keyLength);
  
  // Parse certificate (DER format)
  ret = mbedtls_x509_crt_parse_der(&serverCert, certData, certLength);
  if (ret != 0) {
    Serial.printf("mbedtls_x509_crt_parse_der failed: -0x%x\n", -ret);
    return false;
  }
  Serial.printf("Certificate parsed successfully\n");
  
  // Parse private key (DER format)
  // Try parsing without RNG first (simpler, works for unencrypted keys)
  ret = mbedtls_pk_parse_key(&serverKey, keyData, keyLength, NULL, 0, NULL, NULL);
  if (ret != 0) {
    Serial.printf("mbedtls_pk_parse_key (no RNG) failed: -0x%x\n", -ret);
    
    // Try with RNG
    ret = mbedtls_pk_parse_key(&serverKey, keyData, keyLength, NULL, 0, mbedtls_ctr_drbg_random, &ctrDrbg);
    if (ret != 0) {
      Serial.printf("mbedtls_pk_parse_key (with RNG) also failed: -0x%x\n", -ret);
      return false;
    }
  }
  Serial.printf("Private key parsed successfully\n");
  
  // Set certificate and key in SSL config
  ret = mbedtls_ssl_conf_own_cert(&sslConf, &serverCert, &serverKey);
  if (ret != 0) {
    Serial.printf("mbedtls_ssl_conf_own_cert failed: -0x%x\n", -ret);
    return false;
  }
  
  Serial.printf("SSL certificate and private key loaded\n");
  return true;
}

bool WiFiSecureServer::begin() {
  Serial.printf("WiFiSecureServer::begin() starting...\n");
  
  // Setup SSL context
  if (!setupSSLContext()) {
    Serial.printf("setupSSLContext() failed!\n");
    return false;
  }
  
  // Load certificate and key
  if (!setupCertificate()) {
    Serial.printf("setupCertificate() failed!\n");
    return false;
  }
  
  // Start underlying WiFi server
  server.begin();
  initialized = true;
  Serial.printf("WiFiSecureServer started on port %d\n", port);
  
  return true;
}

WiFiClient WiFiSecureServer::accept() {
  return server.accept();
}


mbedtls_ssl_context* WiFiSecureServer::createSSL(WiFiClient* wifiClient, wifi_client_context** outContext) {
  if (!initialized) {
    OTF_DEBUG("SSL context not initialized\n");
    return nullptr;
  }
  
  if (!wifiClient || !wifiClient->connected()) {
    OTF_DEBUG("Invalid or disconnected WiFiClient\n");
    return nullptr;
  }
  
  Serial.printf("createSSL: Free heap: %d bytes, largest block: %d bytes\n", 
                ESP.getFreeHeap(), ESP.getMaxAllocHeap());
  
  // Allocate WiFi client context
  wifi_client_context* ctx = new wifi_client_context();
  ctx->client = wifiClient;
  ctx->last_activity = millis();
  
  // Allocate new SSL context
  mbedtls_ssl_context* ssl = new mbedtls_ssl_context();
  mbedtls_ssl_init(ssl);
  
  Serial.printf("After ssl_init: Free heap: %d bytes\n", ESP.getFreeHeap());
  
  Serial.printf("Calling mbedtls_ssl_setup...\n");
  
  // Setup SSL context with config
  int ret = mbedtls_ssl_setup(ssl, &sslConf);
  if (ret != 0) {
    char errBuf[100];
    mbedtls_strerror(ret, errBuf, sizeof(errBuf));
    Serial.printf("mbedtls_ssl_setup failed: -0x%x (%s)\n", -ret, errBuf);
    Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());
    delete ctx;
    mbedtls_ssl_free(ssl);
    delete ssl;
    return nullptr;
  }
  
  Serial.printf("mbedtls_ssl_setup successful\n");
  
  // Set BIO callbacks using WiFiClient
  mbedtls_ssl_set_bio(ssl, ctx, wifi_client_send, wifi_client_recv, NULL);
  
  Serial.printf("BIO callbacks set for WiFiClient\n");
  Serial.printf("Starting SSL handshake...\n");
  
  // Perform SSL handshake with timeout
  unsigned long handshakeStart = millis();
  const unsigned long HANDSHAKE_TIMEOUT = 5000; // 5 seconds
  
  while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      char errBuf[100];
      mbedtls_strerror(ret, errBuf, sizeof(errBuf));
      Serial.printf("mbedtls_ssl_handshake failed: -0x%x (%s)\n", -ret, errBuf);
      delete ctx;
      mbedtls_ssl_free(ssl);
      delete ssl;
      return nullptr;
    }
    
    // Check timeout
    if (millis() - handshakeStart > HANDSHAKE_TIMEOUT) {
      Serial.printf("SSL handshake timeout!\n");
      delete ctx;
      mbedtls_ssl_free(ssl);
      delete ssl;
      return nullptr;
    }
    
    // Small delay to allow other tasks
    delay(10);
  }
  
  Serial.printf("SSL handshake successful!\n");
  
  // Return context to caller for cleanup
  if (outContext) {
    *outContext = ctx;
  }
  
  return ssl;
}

using namespace OTF;

// ============================================================================
// Esp32LocalServer Implementation
// ============================================================================

Esp32LocalServer::Esp32LocalServer(uint16_t port, uint16_t httpsPort) 
  : httpServer(port), 
    httpsServer(nullptr),
    httpPort(port),
    httpsPort(httpsPort) {
  
  OTF_DEBUG("Initializing Esp32LocalServer\n");
  OTF_DEBUG("  HTTP port: %d\n", httpPort);
  OTF_DEBUG("  HTTPS port: %d\n", httpsPort);
  
  // Create HTTPS server with certificate from cert.h
  httpsServer = new WiFiSecureServer(
    httpsPort, 
    opensprinkler_crt_DER, opensprinkler_crt_DER_len,
    opensprinkler_key_DER, opensprinkler_key_DER_len
  );
}

void Esp32LocalServer::begin() {
  // Start HTTP server
  httpServer.begin();
  OTF_DEBUG("HTTP server listening on port %d\n", httpPort);
  
  // Start HTTPS server
  if (httpsServer && httpsServer->begin()) {
    OTF_DEBUG("HTTPS server listening on port %d\n", httpsPort);
  } else {
    OTF_DEBUG("WARNING: HTTPS server failed to start\n");
  }
}

LocalClient *Esp32LocalServer::acceptClient() {
  // Cleanup previous client
  if (activeClient != nullptr) {
    delete activeClient;
    activeClient = nullptr;
  }

  // Check HTTP server first
  WiFiClient httpClient = httpServer.accept();
  if (httpClient) {
    OTF_DEBUG("HTTP client connected\n");
    activeClient = new Esp32HttpClient(httpClient);
    return activeClient;
  }

  // Check HTTPS server
  if (httpsServer) {
    WiFiClient wifiClient = httpsServer->accept();
    if (wifiClient) {
      Serial.printf("HTTPS WiFiClient accepted, connected: %d\n", wifiClient.connected());
      
      // Create SSL connection with handshake
      wifi_client_context* clientContext = nullptr;
      mbedtls_ssl_context* ssl = httpsServer->createSSL(&wifiClient, &clientContext);
      if (ssl) {
        // Create HTTPS client with SSL context
        activeClient = new Esp32HttpsClient(wifiClient, ssl, clientContext);
        return activeClient;
      } else {
        Serial.printf("SSL handshake failed, closing connection\n");
        if (clientContext) {
          delete clientContext;
        }
        wifiClient.stop();
      }
    }
  }

  return nullptr;
}

// ============================================================================
// Esp32HttpClient Implementation (HTTP without SSL)
// ============================================================================

Esp32HttpClient::Esp32HttpClient(WiFiClient wifiClient) 
  : client(wifiClient), isActive(true) {
  OTF_DEBUG("HTTP client initialized\n");
}

Esp32HttpClient::~Esp32HttpClient() {
  if (isActive) {
    stop();
  }
}

bool Esp32HttpClient::dataAvailable() {
  return client.available();
}

size_t Esp32HttpClient::readBytes(char *buffer, size_t length) {
  return client.readBytes(buffer, length);
}

size_t Esp32HttpClient::readBytesUntil(char terminator, char *buffer, size_t length) {
  return client.readBytesUntil(terminator, buffer, length);
}

void Esp32HttpClient::print(const char *data) {
  client.print(data);
}

void Esp32HttpClient::print(const __FlashStringHelper *data) {
  client.print(data);
}

size_t Esp32HttpClient::write(const char *buffer, size_t length) {
  OTF_DEBUG("HTTP write: %d bytes\n", length);
  OTF_DEBUG("Content: %.*s\n", length, buffer);
  return client.write((const uint8_t *)buffer, length);
}

int Esp32HttpClient::peek() {
  return client.peek();
}

void Esp32HttpClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void Esp32HttpClient::flush() {
  OTF_DEBUG("HTTP flush: sending buffered data\n");
  client.clear();
  OTF_DEBUG("HTTP flush: complete\n");
}

void Esp32HttpClient::stop() {
  client.stop();
  isActive = false;
}

// ============================================================================
// Esp32HttpsClient Implementation (HTTPS with SSL/TLS)
// ============================================================================

Esp32HttpsClient::Esp32HttpsClient(WiFiClient wifiClient, mbedtls_ssl_context* sslContext, wifi_client_context* context)
  : client(wifiClient), ssl(sslContext), clientContext(context), isActive(true) {
  OTF_DEBUG("HTTPS client initialized with SSL\n");
}

Esp32HttpsClient::~Esp32HttpsClient() {
  if (isActive) {
    stop();
  }
}

bool Esp32HttpsClient::dataAvailable() {
  return mbedtls_ssl_get_bytes_avail(ssl) > 0 || client.available();
}

size_t Esp32HttpsClient::readBytes(char *buffer, size_t length) {
  int bytesRead = mbedtls_ssl_read(ssl, (unsigned char*)buffer, length);
  return (bytesRead > 0) ? bytesRead : 0;
}

size_t Esp32HttpsClient::readBytesUntil(char terminator, char *buffer, size_t length) {
  size_t index = 0;
  while (index < length) {
    char c;
    int bytesRead = mbedtls_ssl_read(ssl, (unsigned char*)&c, 1);
    if (bytesRead <= 0) break;
    if (c == terminator) break;
    buffer[index++] = c;
  }
  return index;
}

void Esp32HttpsClient::print(const char *data) {
  mbedtls_ssl_write(ssl, (const unsigned char*)data, strlen(data));
}

void Esp32HttpsClient::print(const __FlashStringHelper *data) {
  PGM_P p = reinterpret_cast<PGM_P>(data);
  char c;
  while ((c = pgm_read_byte(p++)) != 0) {
    mbedtls_ssl_write(ssl, (const unsigned char*)&c, 1);
  }
}

size_t Esp32HttpsClient::write(const char *buffer, size_t length) {
  int bytesWritten = mbedtls_ssl_write(ssl, (const unsigned char*)buffer, length);
  return (bytesWritten > 0) ? bytesWritten : 0;
}

int Esp32HttpsClient::peek() {
  return -1;  // Not supported for SSL
}

void Esp32HttpsClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void Esp32HttpsClient::flush() {
  client.clear();
}

void Esp32HttpsClient::stop() {
  OTF_DEBUG("Cleaning up SSL client...\n");
  mbedtls_ssl_close_notify(ssl);
  mbedtls_ssl_free(ssl);
  delete ssl;
  ssl = nullptr;
  
  // Free client context
  if (clientContext) {
    delete clientContext;
    clientContext = nullptr;
  }
  
  client.stop();
  isActive = false;
  OTF_DEBUG("SSL cleanup complete, free heap: %d bytes\n", ESP.getFreeHeap());
}

#endif

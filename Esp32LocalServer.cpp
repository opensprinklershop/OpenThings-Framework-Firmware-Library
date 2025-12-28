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


mbedtls_ssl_context* WiFiSecureServer::createSSL(int socketFd, int** outSocketFdPtr) {
  if (!initialized) {
    OTF_DEBUG("SSL context not initialized\n");
    return nullptr;
  }
  
  Serial.printf("createSSL: Free heap: %d bytes, largest block: %d bytes\n", 
                ESP.getFreeHeap(), ESP.getMaxAllocHeap());
  
  // Allocate new SSL context with persistent socket FD storage
  mbedtls_ssl_context* ssl = new mbedtls_ssl_context();
  mbedtls_ssl_init(ssl);
  
  Serial.printf("After ssl_init: Free heap: %d bytes\n", ESP.getFreeHeap());
  
  // Allocate persistent socket FD (will be freed by caller)
  int* persistentFd = new int(socketFd);
  
  Serial.printf("Calling mbedtls_ssl_setup...\n");
  
  // Setup SSL context with config
  int ret = mbedtls_ssl_setup(ssl, &sslConf);
  if (ret != 0) {
    char errBuf[100];
    mbedtls_strerror(ret, errBuf, sizeof(errBuf));
    Serial.printf("mbedtls_ssl_setup failed: -0x%x (%s)\n", -ret, errBuf);
    Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());
    delete persistentFd;  // Free persistent FD
    mbedtls_ssl_free(ssl);
    delete ssl;
    return nullptr;
  }
  
  Serial.printf("mbedtls_ssl_setup successful\n");
  
  // Set BIO callbacks using mbedTLS built-in socket I/O (like esp32_https_server)
  // Note: mbedtls_net_send/recv expect ctx to point to an int (socket FD)
  mbedtls_ssl_set_bio(ssl, persistentFd, mbedtls_net_send, mbedtls_net_recv, NULL);
  
  Serial.printf("BIO callbacks set, socket FD: %d\n", *persistentFd);
  Serial.printf("Starting SSL handshake...\n");
  
  // Perform SSL handshake with timeout
  unsigned long handshakeStart = millis();
  const unsigned long HANDSHAKE_TIMEOUT = 5000; // 5 seconds
  
  while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      Serial.printf("mbedtls_ssl_handshake failed: -0x%x\n", -ret);
      delete persistentFd;
      mbedtls_ssl_free(ssl);
      delete ssl;
      return nullptr;
    }
    
    // Check timeout
    if (millis() - handshakeStart > HANDSHAKE_TIMEOUT) {
      Serial.printf("SSL handshake timeout!\n");
      delete persistentFd;
      mbedtls_ssl_free(ssl);
      delete ssl;
      return nullptr;
    }
    
    // Small delay to allow other tasks
    delay(10);
    Serial.printf(".");
  }
  
  // Return persistent FD to caller for cleanup
  if (outSocketFdPtr) {
    *outSocketFdPtr = persistentFd;
  }
  
  OTF_DEBUG("SSL handshake successful\n");
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
      int sockFd = wifiClient.fd();
      Serial.printf("HTTPS WiFiClient accepted, FD: %d\n", sockFd);
      
      // Create SSL connection with handshake
      int* persistentFd = nullptr;
      mbedtls_ssl_context* ssl = httpsServer->createSSL(sockFd, &persistentFd);
      if (ssl) {
        // Create HTTPS client with SSL context
        activeClient = new Esp32HttpsClient(wifiClient, ssl, persistentFd);
        return activeClient;
      } else {
        Serial.printf("SSL handshake failed, closing socket\n");
        if (persistentFd) {
          close(*persistentFd);
          delete persistentFd;
        }
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
  return client.write((const uint8_t *)buffer, length);
}

int Esp32HttpClient::peek() {
  return client.peek();
}

void Esp32HttpClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void Esp32HttpClient::flush() {
  client.clear();
}

void Esp32HttpClient::stop() {
  client.stop();
  isActive = false;
}

// ============================================================================
// Esp32HttpsClient Implementation (HTTPS with SSL/TLS)
// ============================================================================

Esp32HttpsClient::Esp32HttpsClient(WiFiClient wifiClient, mbedtls_ssl_context* sslContext, int* socketFd)
  : client(wifiClient), ssl(sslContext), sslSocketFd(socketFd), isActive(true) {
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
  
  // Close and free socket FD
  if (sslSocketFd) {
    close(*sslSocketFd);
    delete sslSocketFd;
    sslSocketFd = nullptr;
  }
  
  client.stop();
  isActive = false;
  OTF_DEBUG("SSL cleanup complete, free heap: %d bytes\n", ESP.getFreeHeap());
}

#endif

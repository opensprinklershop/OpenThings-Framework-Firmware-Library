#if defined(ESP32)
#ifdef __has_include
  #if __has_include("sdkconfig.h")
    #include "sdkconfig.h"  // ESP-IDF configuration - must be first for MBEDTLS defines
  #endif
#endif
#include "Esp32LocalServer.h"
#include "Esp32LocalServer_Config.h"
#include <lwip/sockets.h>  // For sockaddr_in
#include <mbedtls/error.h>  // For mbedtls_strerror
#include <esp_heap_caps.h>  // For heap_caps_malloc/free with PSRAM support

#ifndef OTF_DEBUG
  #if defined(SERIAL_DEBUG) || defined(OTF_DEBUG_MODE)
    #define OTF_DEBUG(...) Serial.printf(__VA_ARGS__)
  #else
    #define OTF_DEBUG(...)
  #endif
#endif


// Use namespace OTF for all class implementations
using namespace OTF;

// ============================================================================
// Memory Optimization Helpers for PSRAM Support
// ============================================================================
inline void* otf_malloc(size_t size, bool preferPSRAM = true) {
#if OTF_USE_PSRAM
  if (preferPSRAM && psramFound()) {
    // Use heap_caps_malloc for better control over PSRAM allocation
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr) {
      #ifdef OTF_DEBUG_MEMORY
      OTF_DEBUG("PSRAM malloc: %u bytes\n", (unsigned)size);
      #endif
      return ptr;
    }
    // PSRAM allocation failed - fall through to DRAM
    #ifdef OTF_DEBUG_MEMORY
    OTF_DEBUG("PSRAM malloc failed, trying DRAM for %u bytes\n", (unsigned)size);
    #endif
  }
#endif
  void* ptr = malloc(size);
  if (ptr) {
    #ifdef OTF_DEBUG_MEMORY
    OTF_DEBUG("DRAM malloc: %u bytes\n", (unsigned)size);
    #endif
  }
  return ptr;
}

inline void otf_free(void* ptr) {
  if (ptr) {
    // heap_caps_free works for both PSRAM and DRAM
    heap_caps_free(ptr);
  }
}

// ============================================================================
// Enhanced HTTP Client with Buffering (supports PSRAM)
// ============================================================================

// NOTE: Esp32HttpClientBuffered removed due to private base constructor.
// If buffered writes are needed later, implement via composition inside Esp32LocalServer
// and keep Esp32HttpClient constructors private for controlled instantiation.
// Note: Buffered client class removed - simplicity preferred for embedded systems

static int wifi_client_send(void *ctx, const unsigned char *buf, size_t len) {
  WiFiClient *client = static_cast<WiFiClient*>(ctx);
  if (!client || !client->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
  int written = client->write(buf, len);
  if (written == 0) return MBEDTLS_ERR_SSL_WANT_WRITE;
  if (written < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
  return written;
}

static int wifi_client_recv(void *ctx, unsigned char *buf, size_t len) {
  WiFiClient *client = static_cast<WiFiClient*>(ctx);
  if (!client || !client->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
  int available = client->available();
  if (available == 0) return MBEDTLS_ERR_SSL_WANT_READ;
  int read = client->read(buf, len);
  if (read < 0) return MBEDTLS_ERR_NET_RECV_FAILED;
  return read;
}

// ============================================================================
// WiFiSecureServer Implementation (SSL/TLS with mbedTLS)
// ============================================================================

WiFiSecureServer::WiFiSecureServer(uint16_t port, const unsigned char* cert, uint16_t certLen, 
                                   const unsigned char* key, uint16_t keyLen)
  : server(port, 1), port(port),
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

  // CRITICAL: TLS 1.3 ONLY - NO FALLBACK TO TLS 1.2
  // Enforces TLS 1.3 exclusively for maximum security (forward secrecy, ECDHE-only)
  // Hardware-accelerated AES-GCM ciphers on ESP32-C5 (3-5x faster)
  // This prevents TLS 1.2 downgrade attacks and reduces cipher overhead
  mbedtls_ssl_conf_min_tls_version(&sslConf, MBEDTLS_SSL_VERSION_TLS1_3);
  mbedtls_ssl_conf_max_tls_version(&sslConf, MBEDTLS_SSL_VERSION_TLS1_3);
  OTF_DEBUG(">>> ENFORCING TLS 1.3 ONLY (NO TLS 1.2 FALLBACK) <<<\n");
  OTF_DEBUG(">>> Using Hardware-Accelerated AES-GCM on ESP32-C5 <<<\n");
  
  // Set random number generator
  mbedtls_ssl_conf_rng(&sslConf, mbedtls_ctr_drbg_random, &ctrDrbg);
  
  // Disable client authentication (server mode, no client certs needed)
  mbedtls_ssl_conf_authmode(&sslConf, MBEDTLS_SSL_VERIFY_NONE);
  
  // Cipher suites are now configured in ESP-IDF at compile time:
  // - Only TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
  // - Hardware-accelerated AES-GCM, SHA-256/384, ECC on ESP32-C5
  // This saves ~2-4KB flash by removing runtime cipher selection code
  OTF_DEBUG("Using ESP-IDF cipher configuration (TLS 1.3 AES-GCM only)\n");
  
  // Critical memory optimizations for ESP32-C5 (400KB SRAM, no PSRAM)
  #if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(&sslConf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
  #endif
  
  // Do not enforce Max Fragment Length extension; many browsers don't negotiate it
  // Keep CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=4096 for RAM savings without handshake failures
  
  // Disable heavyweight features
  #if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    mbedtls_ssl_conf_encrypt_then_mac(&sslConf, MBEDTLS_SSL_ETM_DISABLED);
  #endif
  #if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    mbedtls_ssl_conf_extended_master_secret(&sslConf, MBEDTLS_SSL_EXTENDED_MS_DISABLED);
  #endif
  
  // CRITICAL: TCP Keep-Alive reduces SSL renegotiation overhead
  // Configure read timeout for faster error detection (3s instead of default 60s)
  mbedtls_ssl_conf_read_timeout(&sslConf, 3000);

  // Further runtime feature trimming (even if compiled in)
  #if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&sslConf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
  #endif
  #if defined(MBEDTLS_SSL_CERT_REQ_CA_LIST)
    mbedtls_ssl_conf_cert_req_ca_list(&sslConf, MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
  #endif
  
  // Debug: List supported cipher suites
  /*OTF_DEBUG("Supported cipher suites:\n");
  const int *ciphersuites = mbedtls_ssl_list_ciphersuites();
  if (ciphersuites) {
    int count = 0;
    for (int i = 0; ciphersuites[i] != 0; i++) {
      const char* suite_name = mbedtls_ssl_get_ciphersuite_name(ciphersuites[i]);
      if (suite_name) {
        OTF_DEBUG("  [%d] 0x%04X - %s\n", i, ciphersuites[i], suite_name);
        count++;
      }
    }
    OTF_DEBUG("Total cipher suites available: %d\n", count);
  } else {
    OTF_DEBUG("  ERROR: No cipher suites available!\n");
  }
  */
  return true;
}

bool WiFiSecureServer::setupCertificate() {
  int ret;
  
  OTF_DEBUG("Loading certificate: %d bytes\n", certLength);
  OTF_DEBUG("Loading private key: %d bytes\n", keyLength);
  OTF_DEBUG("setupCertificate: before parse: heap=%d bytes, largest block=%d bytes\n",
            ESP.getFreeHeap(), heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  
  // Certificate and key are in PROGMEM (Flash) to save RAM
  // mbedTLS can read directly from Flash on ESP32
  // Parse certificate (DER format)
  ret = mbedtls_x509_crt_parse_der(&serverCert, certData, certLength);
  if (ret != 0) {
    OTF_DEBUG("mbedtls_x509_crt_parse_der failed: -0x%x\n", -ret);
    return false;
  }
  OTF_DEBUG("Certificate parsed successfully\n");
  OTF_DEBUG("setupCertificate: after cert: heap=%d bytes, largest block=%d bytes\n",
            ESP.getFreeHeap(), heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  
  // Parse private key (DER format)
  // The key in cert.h is in SEC1 format with ECParameters
  // First try standard parsing with NULL password
  ret = mbedtls_pk_parse_key(&serverKey, keyData, keyLength, NULL, 0, mbedtls_ctr_drbg_random, &ctrDrbg);
  
  if (ret != 0) {
    OTF_DEBUG("mbedtls_pk_parse_key failed: -0x%x\n", -ret);
    return false;
  }
  OTF_DEBUG("Private key parsed successfully\n");
  OTF_DEBUG("setupCertificate: after key: heap=%d bytes, largest block=%d bytes\n",
            ESP.getFreeHeap(), heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  
  // Set certificate and key in SSL config
  ret = mbedtls_ssl_conf_own_cert(&sslConf, &serverCert, &serverKey);
  if (ret != 0) {
    OTF_DEBUG("mbedtls_ssl_conf_own_cert failed: -0x%x\n", -ret);
    return false;
  }
  
  OTF_DEBUG("SSL certificate and private key loaded\n");
  return true;
}

bool WiFiSecureServer::begin() {
  OTF_DEBUG("WiFiSecureServer::begin() starting...\n");
  
  // Setup SSL context
  if (!setupSSLContext()) {
    OTF_DEBUG("setupSSLContext() failed!\n");
    return false;
  }
  
  // Load certificate and key
  if (!setupCertificate()) {
    OTF_DEBUG("setupCertificate() failed!\n");
    return false;
  }
  
  // Start underlying WiFi server
  server.begin();
  initialized = true;
  OTF_DEBUG("WiFiSecureServer started on port %d\n", port);
  
  return true;
}

WiFiClient WiFiSecureServer::accept() {
  return server.accept();
}
// Note: Direct buffering removed - simplicity preferred for embedded systems
// Clients are managed directly by Esp32LocalServer

// Helper to enable TCP Keep-Alive on WiFiClient socket (reduces SSL renegotiation)
static bool enableTCPKeepAlive(WiFiClient* wifiClient) {
  if (!wifiClient || !wifiClient->connected()) return false;
  
  // Get socket FD from WiFiClient
  int sockfd = wifiClient->fd();
  if (sockfd < 0) {
    OTF_DEBUG("Invalid socket FD\n");
    return false;
  }
  
  // Enable TCP Keep-Alive (SO_KEEPALIVE)
  int keepalive = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
    OTF_DEBUG("Failed to enable SO_KEEPALIVE: %s\n", strerror(errno));
    return false;
  }
  
  // TCP_KEEPIDLE: Time before sending first keepalive probe (seconds)
  int keepidle = 30;  // 30 seconds idle before first probe
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
    OTF_DEBUG("Failed to set TCP_KEEPIDLE: %s\n", strerror(errno));
  }
  
  // TCP_KEEPINTVL: Interval between keepalive probes (seconds)
  int keepintvl = 10;  // 10 seconds between probes
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
    OTF_DEBUG("Failed to set TCP_KEEPINTVL: %s\n", strerror(errno));
  }
  
  // TCP_KEEPCNT: Number of probes before closing connection
  int keepcnt = 3;  // 3 failed probes = close
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
    OTF_DEBUG("Failed to set TCP_KEEPCNT: %s\n", strerror(errno));
  }
  
  OTF_DEBUG("TCP Keep-Alive enabled (idle=%ds, intvl=%ds, cnt=%d)\n", 
            keepidle, keepintvl, keepcnt);
  return true;
}

mbedtls_ssl_context* WiFiSecureServer::handshakeSSL(WiFiClient* wifiClient) {
  if (!initialized) {
    OTF_DEBUG("SSL context not initialized\n");
    return NULL;
  }
  
  if (!wifiClient || !wifiClient->connected()) {
    OTF_DEBUG("Invalid or disconnected WiFiClient\n");
    return NULL;
  }

  // Fast-path: if the peer sent data already and it doesn't look like a TLS record
  // (TLS record content type for handshake is 0x16), it's likely plain HTTP on the HTTPS port.
  int avail = wifiClient->available();
  if (avail > 0) {
    int first = wifiClient->peek();
    if (first >= 0 && first != 0x16) {
      OTF_DEBUG("Non-TLS traffic on HTTPS port (first byte=0x%02x, avail=%d). Closing.\n", first, avail);
      wifiClient->stop();
      return NULL;
    }
  }
  
  OTF_DEBUG("handshakeSSL: Free heap: %d bytes, largest block: %d bytes\n", 
                ESP.getFreeHeap(), ESP.getMaxAllocHeap());
  
  // CRITICAL: Enable TCP Keep-Alive to reduce SSL renegotiation overhead
  // This keeps TCP connection alive during idle periods, reducing need for
  // expensive SSL session resumption or full handshakes
  enableTCPKeepAlive(wifiClient);
  
  OTF_DEBUG("Starting SSL handshake...\n");
  
  // Perform SSL handshake with timeout
  unsigned long handshakeStart = millis();
  const unsigned long HANDSHAKE_TIMEOUT = 5000; // 5 seconds
  
  int ret = 0;
  mbedtls_ssl_context* ssl = new mbedtls_ssl_context;
  mbedtls_ssl_init(ssl);
  
  OTF_DEBUG("After ssl_init: Free heap: %d bytes\n", ESP.getFreeHeap());
  
  OTF_DEBUG("Calling mbedtls_ssl_setup...\n");
  
  // Setup SSL context with config
  ret = mbedtls_ssl_setup(ssl, &sslConf);
  if (ret != 0) {
    char errBuf[100];
    mbedtls_strerror(ret, errBuf, sizeof(errBuf));
    OTF_DEBUG("mbedtls_ssl_setup failed: -0x%x (%s)\n", -ret, errBuf);
    OTF_DEBUG("Free heap: %d bytes\n", ESP.getFreeHeap());
    mbedtls_ssl_free(ssl);
    delete ssl;
    wifiClient->stop();
    return NULL;
  }

  mbedtls_ssl_set_bio(ssl, wifiClient, wifi_client_send, wifi_client_recv, NULL);
  
  OTF_DEBUG("mbedtls_ssl_setup successful\n");

  OTF_DEBUG("SSL context configured\n");

  while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      // mbedTLS net errors are small negative codes (e.g. -0x0050 for connection reset)
      if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
        OTF_DEBUG("mbedtls_ssl_handshake failed: -0x%x (CONNECTION RESET)\n", -ret);
      } else {
        char errBuf[100];
        mbedtls_strerror(ret, errBuf, sizeof(errBuf));
        OTF_DEBUG("mbedtls_ssl_handshake failed: -0x%x (%s)\n", -ret, errBuf);
      }
      mbedtls_ssl_free(ssl);
      delete ssl;
      wifiClient->stop();
      return NULL;
    }
    
    // Check timeout
    if (millis() - handshakeStart > HANDSHAKE_TIMEOUT) {
      OTF_DEBUG("SSL handshake timeout!\n");
      mbedtls_ssl_free(ssl);
      delete ssl;
      wifiClient->stop();
      return NULL;
    }
    
    // Small delay to allow other tasks
    delay(10);
  }
  
  // Handshake complete: log negotiated parameters
  OTF_DEBUG("TLS negotiated: %s, cipher=%s\n",
            mbedtls_ssl_get_version(ssl),
            mbedtls_ssl_get_ciphersuite(ssl));
  
  OTF_DEBUG("SSL handshake successful!\n");

  return ssl;
}

// ============================================================================
// Esp32LocalServer Implementation with Connection Pool
// ============================================================================

Esp32LocalServer::Esp32LocalServer(uint16_t port, uint16_t httpsPort, uint16_t maxClients) 
  : httpServer(port, 1), 
    httpsServer(nullptr),
    maxConcurrentClients(maxClients),
    httpPort(port),
    httpsPort(httpsPort) {
  
  OTF_DEBUG("Initializing Esp32LocalServer (MultiClient Support)\n");
  OTF_DEBUG("  HTTP port: %d\n", httpPort);
  OTF_DEBUG("  HTTPS port: %d\n", httpsPort);
  OTF_DEBUG("  Max concurrent clients: %d\n", maxConcurrentClients);
  OTF_DEBUG("  PSRAM support: %s\n", psramFound() ? "YES" : "NO");
  OTF_DEBUG("  Free DRAM: %d bytes, Free PSRAM: %d bytes\n", 
            ESP.getFreeHeap(), ESP.getFreePsram());
  
  // Preallocate client pool
  clientPool.reserve(OTF_CLIENT_POOL_SIZE);
  
  // Create HTTPS server with certificate from cert.h
  if (httpsPort == 0) {
    OTF_DEBUG("HTTPS port is 0, skipping HTTPS server setup\n");
    return;
  }
  httpsServer = new WiFiSecureServer(
    httpsPort, 
    opensprinkler_crt_DER, opensprinkler_crt_DER_len,
    opensprinkler_key_DER, opensprinkler_key_DER_len
  );
}

Esp32LocalServer::~Esp32LocalServer() {
  closeAllClients();
  if (httpsServer) {
    delete httpsServer;
    httpsServer = nullptr;
  }
}

void Esp32LocalServer::begin() {
  OTF_DEBUG("[Esp32LocalServer::begin] Called!\n");
  OTF_DEBUG("[Esp32LocalServer::begin] httpPort=%d, httpsPort=%d\n", httpPort, httpsPort);
  
  // Start HTTP server
  OTF_DEBUG("[Esp32LocalServer::begin] Starting HTTP server...\n");
  httpServer.begin();
  OTF_DEBUG("HTTP server listening on port %d\n", httpPort);
  
  // Start HTTPS server
  if (httpsServer) {
    OTF_DEBUG("[Esp32LocalServer::begin] HTTPS server exists, calling begin()...\n");
    if (httpsServer->begin()) {
      OTF_DEBUG("HTTPS server listening on port %d\n", httpsPort);
    } else {
      OTF_DEBUG("WARNING: HTTPS server failed to start\n");
    }
  } else {
    OTF_DEBUG("[Esp32LocalServer::begin] No HTTPS server (httpsPort=%d)\n", httpsPort);
  }
  OTF_DEBUG("[Esp32LocalServer::begin] Completed!\n");
}

size_t Esp32LocalServer::getActiveClientCount() const {
  return clientPool.size();
}

void Esp32LocalServer::removeClient(LocalClient* client) {
  if (!client) return;
  
  for (auto it = clientPool.begin(); it != clientPool.end(); ++it) {
    if (*it == client) {
      delete *it;
      clientPool.erase(it);
      if (currentClient == client) {
        currentClient = nullptr;
      }
      return;
    }
  }
}

void Esp32LocalServer::cleanupInactiveClients() {
  // Remove clients that have been stopped/closed
  for (auto it = clientPool.begin(); it != clientPool.end(); ) {
    LocalClient* client = *it;

    bool shouldRemove = false;
    if (!client) {
      shouldRemove = true;
    } else if (!client->connected()) {
      shouldRemove = true;
    }

    if (shouldRemove) {
      if (client == currentClient) {
        currentClient = nullptr;
      }

      if (client) {
        delete client;
      }
      it = clientPool.erase(it);
    } else {
      ++it;
    }
  }
}

LocalClient* Esp32LocalServer::getNextAvailableClient() {
  if (clientPool.empty()) return nullptr;
  
  // Round-robin selection
  if (nextClientIndex >= clientPool.size()) {
    nextClientIndex = 0;
  }
  
  return clientPool[nextClientIndex++];
}

LocalClient *Esp32LocalServer::acceptClientNonBlocking() {
  // Attempt to accept a new HTTP connection
  WiFiClient httpClient = httpServer.accept();
  if (httpClient) {
    // Check if we've hit the max concurrent clients limit
    if (clientPool.size() >= maxConcurrentClients) {
      OTF_DEBUG("Max clients reached (%d), rejecting new HTTP connection\n", maxConcurrentClients);
      httpClient.stop();
      return nullptr;
    }
    
    OTF_DEBUG("HTTP client connected (pool size: %d)\n", clientPool.size() + 1);
    currentRequestIsHttps = false;
    LocalClient* newClient = new Esp32HttpClient(httpClient);
    clientPool.push_back(newClient);
    currentClient = newClient;
    return newClient;
  }

  // Attempt to accept a new HTTPS connection
  if (httpsServer) {    
    WiFiClient wifiClient = httpsServer->accept();
    if (wifiClient) {
      // Check if we've hit the max concurrent clients limit
      if (clientPool.size() >= maxConcurrentClients) {
        OTF_DEBUG("Max clients reached (%d), rejecting new HTTPS connection\n", maxConcurrentClients);
        wifiClient.stop();
        return nullptr;
      }
      
      OTF_DEBUG("HTTPS WiFiClient accepted, connected: %d (pool size: %d)\n", 
                wifiClient.connected(), clientPool.size() + 1);
      currentRequestIsHttps = true;
      LocalClient* newClient = new Esp32HttpsClient(wifiClient, httpsServer);

      if (!static_cast<Esp32HttpsClient*>(newClient)->isUsable()) {
        delete newClient;
        return nullptr;
      }
      
      clientPool.push_back(newClient);
      currentClient = newClient;
      return newClient;
    }
  }

  return nullptr;
}

LocalClient *Esp32LocalServer::acceptClient() {
  // For backward compatibility: cleanup old single client pattern
  // But now support multiple concurrent clients
  
  cleanupInactiveClients();
  
  // Try to accept a new client
  LocalClient* newClient = acceptClientNonBlocking();
  if (newClient) {
    return newClient;
  }
  
  // Return current/next active client if available
  if (!clientPool.empty()) {
    currentClient = getNextAvailableClient();
    return currentClient;
  }
  
  return nullptr;
}

LocalClient *Esp32LocalServer::getClientAtIndex(uint16_t index) {
  if (index < clientPool.size()) {
    return clientPool[index];
  }
  return nullptr;
}

void Esp32LocalServer::closeAllClients() {
  for (auto client : clientPool) {
    if (client) {
      client->stop();
      delete client;
    }
  }
  clientPool.clear();
  currentClient = nullptr;
  nextClientIndex = 0;
}

// ============================================================================
// Esp32HttpClient Implementation (HTTP without SSL)
// ============================================================================

Esp32HttpClient::Esp32HttpClient(WiFiClient wifiClient) 
  : client(wifiClient), isActive(true) {
  OTF_DEBUG("HTTP client initialized\n");
  client.setNoDelay(true);
  
  // Enable TCP Keep-Alive for HTTP clients to maintain connection
  // during idle periods (reduces connection overhead)
  enableTCPKeepAlive(&client);
}

OTF::Esp32HttpClient::~Esp32HttpClient() {
  if (isActive) {
    stop();
  }
}

bool OTF::Esp32HttpClient::dataAvailable() {
  return client.available();
}

size_t OTF::Esp32HttpClient::readBytes(char *buffer, size_t length) {
  return client.readBytes(buffer, length);
}

size_t OTF::Esp32HttpClient::readBytesUntil(char terminator, char *buffer, size_t length) {
  return client.readBytesUntil(terminator, buffer, length);
}

void OTF::Esp32HttpClient::print(const char *data) {
  client.print(data);
}

void OTF::Esp32HttpClient::print(const __FlashStringHelper *data) {
  client.print(data);
}

size_t OTF::Esp32HttpClient::write(const char *buffer, size_t length) {
  OTF_DEBUG("HTTP write: %d bytes\n", length);
  OTF_DEBUG("Content: %.*s\n", length, buffer);
  return client.write((const uint8_t *)buffer, length);
}

int OTF::Esp32HttpClient::peek() {
  return client.peek();
}

void OTF::Esp32HttpClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void OTF::Esp32HttpClient::flush() {
  // No-op.
  // NOTE: Arduino Client::flush() is often implemented as "discard received data".
  // Response streaming uses flush as a "push out" hint; clearing RX here can block
  // and severely slow down large streamed responses.
}

void OTF::Esp32HttpClient::stop() {
  client.stop();
  isActive = false;
}

// ============================================================================
// Esp32HttpsClient Implementation (HTTPS with SSL/TLS)
// ============================================================================

OTF::Esp32HttpsClient::Esp32HttpsClient(WiFiClient wifiClient, WiFiSecureServer* httpsServer)
  : client(wifiClient), isActive(true), ssl(nullptr)
{
  OTF_DEBUG("initialized HTTPS client with SSL\n");
  client.setNoDelay(true);
  client.setTimeout((int)timeoutMs);

  // Create SSL connection with handshake
  ssl = httpsServer->handshakeSSL(&client);
  if (!ssl) isActive = false;
}

OTF::Esp32HttpsClient::~Esp32HttpsClient() {
  OTF_DEBUG("destroyed HTTPS client with SSL\n");
  client.stop();
  if (ssl) {
    mbedtls_ssl_free(ssl);
    delete ssl;
    ssl = nullptr;
  }
  isActive = false;
}

bool OTF::Esp32HttpsClient::dataAvailable() {
  if (!ssl) return false;
  return mbedtls_ssl_get_bytes_avail(ssl) > 0 || client.available();
}

size_t OTF::Esp32HttpsClient::readBytes(char *buffer, size_t length) {
  if (!ssl || !buffer || length == 0) return 0;
  uint32_t start = millis();
  size_t total = 0;
  while (total < length) {
    int r = mbedtls_ssl_read(ssl, (unsigned char*)buffer + total, length - total);
    if (r > 0) {
      total += (size_t)r;
      continue;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if ((millis() - start) >= timeoutMs) break;
      delay(1);
      continue;
    }
    break;
  }
  return total;
}

size_t OTF::Esp32HttpsClient::readBytesUntil(char terminator, char *buffer, size_t length) {
  if (!ssl || !buffer || length == 0) return 0;
  uint32_t start = millis();
  size_t index = 0;
  while (index < length) {
    unsigned char c;
    int r = mbedtls_ssl_read(ssl, &c, 1);
    if (r > 0) {
      if ((char)c == terminator) break;
      buffer[index++] = (char)c;
      continue;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if ((millis() - start) >= timeoutMs) break;
      delay(1);
      continue;
    }
    break;
  }
  return index;
}

void OTF::Esp32HttpsClient::print(const char *data) {
  if (!data) return;
  write(data, strlen(data));
}

void OTF::Esp32HttpsClient::print(const __FlashStringHelper *data) {
  const char* p = reinterpret_cast<const char*>(data);
  write(p, strlen(p));
}

size_t OTF::Esp32HttpsClient::write(const char *buffer, size_t length) {
  if (!ssl || !buffer || length == 0) return 0;
  uint32_t start = millis();
  size_t total = 0;
  while (total < length) {
    int w = mbedtls_ssl_write(ssl, (const unsigned char*)buffer + total, length - total);
    if (w > 0) {
      total += (size_t)w;
      continue;
    }
    if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if ((millis() - start) >= timeoutMs) break;
      delay(1);
      continue;
    }
    break;
  }
  uint32_t elapsed = millis() - start;
  if (elapsed > 50) {
    OTF_DEBUG("HTTPS write slow: %u ms for %d bytes (sent %d)\n", elapsed, (int)length, (int)total);
  }
  return total;
}

int OTF::Esp32HttpsClient::peek() {
  return -1;  // Not supported for SSL
}

void OTF::Esp32HttpsClient::setTimeout(int timeout) {
  if (timeout < 0) timeout = 0;
  timeoutMs = (uint32_t)timeout;
  client.setTimeout(timeout);
}

void OTF::Esp32HttpsClient::flush() {
  // No-op.
  // For TLS, writes are pushed via mbedtls_ssl_write(); there is no separate
  // outbound flush. Avoid draining/clearing RX here because Response streaming
  // can call flush frequently.
}

void OTF::Esp32HttpsClient::stop() {
  OTF_DEBUG("stop HTTPS client with SSL\n");
  uint32_t stopStart = millis();
  if (ssl && isActive) {
    // Best-effort close_notify: some browsers/clients don't read it, which can
    // stall in WANT_WRITE for seconds. Keep it short to avoid blocking OTF loop.
    const uint32_t closeTimeoutMs = 200;
    uint32_t start = millis();
    while (true) {
      int r = mbedtls_ssl_close_notify(ssl);
      if (r == 0) break;
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        if ((millis() - start) >= closeTimeoutMs) break;
        delay(1);
        continue;
      }
      break;
    }
    OTF_DEBUG("HTTPS close_notify elapsed: %u ms\n", (unsigned)(millis() - start));
  }
  if (ssl) {
    mbedtls_ssl_free(ssl);
    delete ssl;
    ssl = nullptr;
  }
  client.stop();
  isActive = false;
  OTF_DEBUG("SSL cleanup complete, free heap: %d bytes, stop elapsed: %u ms\n", ESP.getFreeHeap(), (unsigned)(millis() - stopStart));
}

#endif

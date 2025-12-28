#if defined(ESP32)
#ifndef OTF_ESP32LOCALSERVER_H
#define OTF_ESP32LOCALSERVER_H

#include "LocalServer.h"

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <errno.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

// Include self-signed certificate data
#include "cert.h"

// WiFiSecureServer: SSL/TLS wrapper für WiFiServer mit mbedTLS
class WiFiSecureServer {
private:
  WiFiServer server;
  mbedtls_ssl_config sslConf;
  mbedtls_x509_crt serverCert;
  mbedtls_pk_context serverKey;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctrDrbg;
  uint16_t port;
  unsigned char* certData;
  uint16_t certLength;
  unsigned char* keyData;
  uint16_t keyLength;
  bool initialized;
  
  bool setupSSLContext();
  bool setupCertificate();
  
public:
  WiFiSecureServer(uint16_t port, unsigned char* cert, uint16_t certLen, unsigned char* key, uint16_t keyLen);
  ~WiFiSecureServer();
  
  bool begin();
  WiFiClient accept();
  mbedtls_ssl_context* createSSL(int socketFd, int** outSocketFdPtr);
  
  mbedtls_ssl_config* getSSLConfig() { return &sslConf; }
};

namespace OTF {
  // HTTP Client (non-secure)
  class Esp32HttpClient : public LocalClient {
    friend class Esp32LocalServer;

  private:
    WiFiClient client;
    bool isActive;

    Esp32HttpClient(WiFiClient wifiClient);
    ~Esp32HttpClient();

  public:
    bool dataAvailable();
    size_t readBytes(char *buffer, size_t length);
    size_t readBytesUntil(char terminator, char *buffer, size_t length);
    void print(const char *data);
    void print(const __FlashStringHelper *data);
    size_t write(const char *buffer, size_t length);
    int peek();
    void setTimeout(int timeout);
    void flush();
    void stop();
  };

  // HTTPS Client (secure with SSL/TLS)
  class Esp32HttpsClient : public LocalClient {
    friend class Esp32LocalServer;

  private:
    WiFiClient client;           // Base WiFiClient
    mbedtls_ssl_context* ssl;    // SSL context for TLS
    int* sslSocketFd;            // Persistent socket FD for SSL BIO
    bool isActive;

    Esp32HttpsClient(WiFiClient wifiClient, mbedtls_ssl_context* sslContext, int* socketFd);
    ~Esp32HttpsClient();

  public:
    bool dataAvailable();
    size_t readBytes(char *buffer, size_t length);
    size_t readBytesUntil(char terminator, char *buffer, size_t length);
    void print(const char *data);
    void print(const __FlashStringHelper *data);
    size_t write(const char *buffer, size_t length);
    int peek();
    void setTimeout(int timeout);
    void flush();
    void stop();
  };

  class Esp32LocalServer : public LocalServer {
  private:
    WiFiServer httpServer;              // HTTP server on port 80
    WiFiSecureServer* httpsServer;      // HTTPS server on port 443 with SSL/TLS
    LocalClient *activeClient = nullptr;
    uint16_t httpPort;
    uint16_t httpsPort;

  public:
    Esp32LocalServer(uint16_t port = 80, uint16_t httpsPort = 443);

    LocalClient *acceptClient();
    void begin();
  };
}// namespace OTF

#endif
#endif

#if defined(ESP32)
#ifndef OTF_ESP32LOCALSERVER_H
#define OTF_ESP32LOCALSERVER_H

#include "LocalServer.h"

#include <Arduino.h>
#include <WiFi.h>
#include <string>

// Inlcudes for setting up the server
#include <HTTPSServer.hpp>

// Define the certificate data for the server (Certificate and private key)
#include <SSLCert.hpp>

// Includes to define request handler callbacks
#include <HTTPRequest.hpp>
#include <HTTPResponse.hpp>

// Required do define ResourceNodes
#include <ResourceNode.hpp>

// Include self-signed certificate data
extern const unsigned char example_crt_DER[];
extern const unsigned int example_crt_DER_len;
extern const unsigned char example_key_DER[];
extern const unsigned int example_key_DER_len;

namespace OTF {
  class Esp32LocalClient : public LocalClient {
    friend class Esp32LocalServer;

  private:
    WiFiClient client;
    Esp32LocalClient(WiFiClient client);

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
    httpsserver::SSLCert *cert;
    httpsserver::HTTPSServer *secureServer;
    httpsserver::HTTPServer *insecureServer;
    Esp32LocalClient *activeClient = nullptr;
    uint16_t httpPort;
    uint16_t httpsPort;
    bool useHTTPS;

  public:
    Esp32LocalServer(uint16_t port = 80, bool enableHTTPS = true, uint16_t httpsPort = 443);
    ~Esp32LocalServer();

    LocalClient *acceptClient();
    void begin();
    void setHTTPS(bool enable);
    httpsserver::HTTPSServer* getHTTPSServer() { return secureServer; }
    httpsserver::HTTPServer* getHTTPServer() { return insecureServer; }
  };
}// namespace OTF

#endif
#endif

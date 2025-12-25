#if defined(ESP32)
#include "Esp32LocalServer.h"

// Easier access to the classes of the server
using namespace httpsserver;

using namespace OTF;

Esp32LocalServer::Esp32LocalServer(uint16_t port, bool enableHTTPS, uint16_t httpsPort) 
  : httpPort(port), httpsPort(httpsPort), useHTTPS(enableHTTPS) {
  
  // Create HTTP server
  insecureServer = new HTTPServer(httpPort);
  
  // Create HTTPS server if enabled
  if (useHTTPS) {
    cert = new SSLCert(
      example_crt_DER, example_crt_DER_len,
      example_key_DER, example_key_DER_len
    );
    secureServer = new HTTPSServer(cert, httpsPort);
  } else {
    cert = nullptr;
    secureServer = nullptr;
  }
}

Esp32LocalServer::~Esp32LocalServer() {
  if (activeClient != nullptr) {
    delete activeClient;
  }
  if (insecureServer != nullptr) {
    delete insecureServer;
  }
  if (secureServer != nullptr) {
    delete secureServer;
  }
  if (cert != nullptr) {
    delete cert;
  }
}

LocalClient *Esp32LocalServer::acceptClient() {
  if (activeClient != nullptr) {
    delete activeClient;
    activeClient = nullptr;
  }

  // Check HTTP server first
  if (insecureServer != nullptr) {
    WiFiClient wiFiClient = insecureServer->accept();
    if (wiFiClient) {
      activeClient = new Esp32LocalClient(wiFiClient);
      return activeClient;
    }
  }
  
  // Check HTTPS server if enabled
  if (secureServer != nullptr) {
    WiFiClient wiFiClient = secureServer->accept();
    if (wiFiClient) {
      activeClient = new Esp32LocalClient(wiFiClient);
      return activeClient;
    }
  }
  
  return nullptr;
}

void Esp32LocalServer::begin() {
  // Start HTTP server
  if (insecureServer != nullptr) {
    insecureServer->begin();
  }
  
  // Start HTTPS server if enabled
  if (secureServer != nullptr) {
    secureServer->begin();
  }
}

void Esp32LocalServer::setHTTPS(bool enable) {
  useHTTPS = enable;
  
  // If enabling HTTPS and not yet created
  if (enable && secureServer == nullptr) {
    cert = new SSLCert(
      example_crt_DER, example_crt_DER_len,
      example_key_DER, example_key_DER_len
    );
    secureServer = new HTTPSServer(cert, httpsPort);
    secureServer->begin();
  }
  // If disabling HTTPS and exists
  else if (!enable && secureServer != nullptr) {
    delete secureServer;
    secureServer = nullptr;
    if (cert != nullptr) {
      delete cert;
      cert = nullptr;
    }
  }
}


Esp32LocalClient::Esp32LocalClient(WiFiClient client) {
  this->client = client;
}

bool Esp32LocalClient::dataAvailable() {
  return client.available();
}

size_t Esp32LocalClient::readBytes(char *buffer, size_t length) {
  return client.readBytes(buffer, length);
}

size_t Esp32LocalClient::readBytesUntil(char terminator, char *buffer, size_t length) {
  return client.readBytesUntil(terminator, buffer, length);
}

void Esp32LocalClient::print(const char *data) {
  client.print(data);
}

void Esp32LocalClient::print(const __FlashStringHelper *data) {
  client.print(data);
}

size_t Esp32LocalClient::write(const char *buffer, size_t length) {
  return client.write((const uint8_t *)buffer, length);
}

int Esp32LocalClient::peek() {
  return client.peek();
}

void Esp32LocalClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void Esp32LocalClient::flush() {
  client.clear();
}

void Esp32LocalClient::stop() {
  client.stop();
}

#endif

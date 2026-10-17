#if !defined(ARDUINO)
#include "LinuxLocalServer.h"
#include <sys/socket.h>
#include <netinet/in.h>

using namespace OTF;

LinuxLocalServer::LinuxLocalServer(uint16_t port) : server(port) {}

LinuxLocalServer::~LinuxLocalServer() {
  if (activeClient != nullptr) {
    activeClient->stop();
    delete activeClient;
  }
}


LocalClient *LinuxLocalServer::acceptClient() {
  if (activeClient != nullptr) {
    activeClient->stop();
    delete activeClient;
  }

  EthernetClient client = server.available();
  if (client) {
    activeClient = new LinuxLocalClient(client);
  } else {
    activeClient = nullptr;
  }
  return activeClient;
}


void LinuxLocalServer::begin() {
  server.begin();
}


LinuxLocalClient::LinuxLocalClient(EthernetClient client) {
  this->client = client;
}

bool LinuxLocalClient::dataAvailable() {
  return client.available();
}

size_t LinuxLocalClient::readBytes(char *buffer, size_t length) {
  return client.read((uint8_t*) buffer, length);
}

size_t LinuxLocalClient::readBytesUntil(char terminator, char *buffer, size_t length) {
    return client.readBytesUntil(terminator, buffer, length);
}

void LinuxLocalClient::print(const char *data) {
  client.write((uint8_t*)data, strlen(data));
}

size_t LinuxLocalClient::write(const char *buffer, size_t size) {
  return client.write((uint8_t*)buffer, size);
}

/*int LinuxLocalClient::peek() {
  return client.peek();
}*/

void LinuxLocalClient::setTimeout(int timeout) {
  client.setTimeout(timeout);
}

void LinuxLocalClient::flush() {
	client.flush();
}

void LinuxLocalClient::stop() {
	client.stop();
}

uint32_t OTF::LinuxLocalClient::remoteIP() {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  if (getpeername(client.GetSocket(), (struct sockaddr *)&addr, &len) != 0) return 0;
  if (addr.sin_family != AF_INET) return 0;
  return (uint32_t)addr.sin_addr.s_addr;
}
#endif

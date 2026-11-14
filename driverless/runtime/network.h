#pragma once
#include "driverless/runtime/base.h"

namespace nb::runtime {
struct Proxy {
    std::string address;
    unsigned short port = 0;
    std::string protocol;
    std::string username;
    std::string password;
    DWORD timeoutMs = 5000;
};
int routeBlockingIpv4(SOCKET socket, const sockaddr_in &destination, const Proxy &proxy);
}

#include "driverless/runtime/network.h"
#include <array>

namespace nb::runtime {
namespace {
struct SocketFailure {
    int code;
};
void checked(bool value, int error = 0) {
    if (!value)
        throw SocketFailure{error ? error : WSAGetLastError()};
}
void sendAll(SOCKET socket, const void *data, size_t size, ULONGLONG deadline) {
    auto bytes = static_cast<const char *>(data);
    while (size) {
        checked(GetTickCount64() < deadline, WSAETIMEDOUT);
        auto count = send(socket, bytes, int(size), 0);
        checked(count > 0, count == 0 ? WSAECONNRESET : 0);
        size -= size_t(count);
        bytes += count;
    }
}
void receive(SOCKET socket, void *data, size_t size, ULONGLONG deadline) {
    auto bytes = static_cast<char *>(data);
    while (size) {
        checked(GetTickCount64() < deadline, WSAETIMEDOUT);
        auto count = recv(socket, bytes, int(size), 0);
        checked(count > 0, count == 0 ? WSAECONNRESET : 0);
        size -= size_t(count);
        bytes += count;
    }
}
std::string base64(const std::string &text) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    unsigned bits = 0;
    int count = -6;
    for (unsigned char value : text) {
        bits = (bits << 8) | value;
        count += 8;
        while (count >= 0) {
            result += alphabet[(bits >> count) & 63];
            count -= 6;
        }
    }
    if (count > -6)
        result += alphabet[((bits << 8) >> (count + 8)) & 63];
    while (result.size() % 4)
        result += '=';
    return result;
}
void socks(SOCKET socket, const sockaddr_in &destination, const Proxy &proxy, ULONGLONG deadline) {
    std::array<BYTE, 3> greeting{5, 1, BYTE(proxy.username.empty() ? 0 : 2)};
    sendAll(socket, greeting.data(), greeting.size(), deadline);
    std::array<BYTE, 2> response{};
    receive(socket, response.data(), response.size(), deadline);
    checked(response[0] == 5 && response[1] == greeting[2], WSAEACCES);
    if (!proxy.username.empty()) {
        checked(proxy.username.size() <= 255 && proxy.password.size() <= 255, WSAEINVAL);
        std::vector<BYTE> credentials{1, BYTE(proxy.username.size())};
        credentials.insert(credentials.end(), proxy.username.begin(), proxy.username.end());
        credentials.push_back(BYTE(proxy.password.size()));
        credentials.insert(credentials.end(), proxy.password.begin(), proxy.password.end());
        try {
            sendAll(socket, credentials.data(), credentials.size(), deadline);
        } catch (...) {
            SecureZeroMemory(credentials.data(), credentials.size());
            throw;
        }
        SecureZeroMemory(credentials.data(), credentials.size());
        receive(socket, response.data(), response.size(), deadline);
        checked(response[0] == 1 && response[1] == 0, WSAEACCES);
    }
    std::array<BYTE, 10> request{5, 1, 0, 1};
    memcpy(request.data() + 4, &destination.sin_addr, 4);
    memcpy(request.data() + 8, &destination.sin_port, 2);
    sendAll(socket, request.data(), request.size(), deadline);
    std::array<BYTE, 4> reply{};
    receive(socket, reply.data(), reply.size(), deadline);
    checked(reply[0] == 5 && reply[1] == 0 && reply[2] == 0, WSAECONNREFUSED);
    size_t remaining = 0;
    if (reply[3] == 1)
        remaining = 4;
    else if (reply[3] == 4)
        remaining = 16;
    else if (reply[3] == 3) {
        BYTE size = 0;
        receive(socket, &size, 1, deadline);
        remaining = size;
    } else
        throw SocketFailure{WSAEPROTONOSUPPORT};
    std::array<BYTE, 257> tail{};
    receive(socket, tail.data(), remaining + 2, deadline);
}
void http(SOCKET socket, const sockaddr_in &destination, const Proxy &proxy, ULONGLONG deadline) {
    char address[INET_ADDRSTRLEN]{};
    checked(InetNtopA(AF_INET, &destination.sin_addr, address, DWORD(sizeof(address))) != nullptr, WSAEINVAL);
    std::string endpoint = std::string(address) + ':' + std::to_string(ntohs(destination.sin_port));
    std::string request = "CONNECT " + endpoint + " HTTP/1.1\r\nHost: " + endpoint + "\r\n";
    if (!proxy.username.empty()) {
        auto secret = proxy.username + ':' + proxy.password;
        auto encoded = base64(secret);
        request += "Proxy-Authorization: Basic " + encoded + "\r\n";
        SecureZeroMemory(secret.data(), secret.size());
        SecureZeroMemory(encoded.data(), encoded.size());
    }
    request += "\r\n";
    try {
        sendAll(socket, request.data(), request.size(), deadline);
    } catch (...) {
        SecureZeroMemory(request.data(), request.size());
        throw;
    }
    SecureZeroMemory(request.data(), request.size());
    std::string response;
    while (!response.ends_with("\r\n\r\n") && response.size() < 8192) {
        char value = 0;
        receive(socket, &value, 1, deadline);
        response += value;
    }
    checked(response.ends_with("\r\n\r\n"), WSAEMSGSIZE);
    checked(response.starts_with("HTTP/1.0 200 ") || response.starts_with("HTTP/1.1 200 "), WSAEACCES);
}
}
int routeBlockingIpv4(SOCKET socket, const sockaddr_in &destination, const Proxy &proxy) {
    try {
        checked(destination.sin_family == AF_INET && destination.sin_port != 0 && proxy.port != 0 &&
                    proxy.timeoutMs >= 10 && proxy.timeoutMs <= 30000 &&
                    (proxy.protocol == "http" || proxy.protocol == "socks5"),
                WSAEINVAL);
        int type = 0, size = sizeof(type);
        checked(getsockopt(socket, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&type), &size) == 0 &&
                    type == SOCK_STREAM,
                WSAEOPNOTSUPP);
        sockaddr_in upstream{};
        upstream.sin_family = AF_INET;
        upstream.sin_port = htons(proxy.port);
        checked(InetPtonA(AF_INET, proxy.address.c_str(), &upstream.sin_addr) == 1, WSAEINVAL);
        u_long nonblocking = 1;
        checked(ioctlsocket(socket, FIONBIO, &nonblocking) == 0);
        struct Blocking {
            SOCKET socket;
            ~Blocking() {
                u_long value = 0;
                ioctlsocket(socket, FIONBIO, &value);
            }
        } blocking{socket};
        int connected = connect(socket, reinterpret_cast<sockaddr *>(&upstream), sizeof(upstream));
        if (connected == SOCKET_ERROR) {
            checked(WSAGetLastError() == WSAEWOULDBLOCK);
            fd_set writable, errors;
            FD_ZERO(&writable);
            FD_ZERO(&errors);
            FD_SET(socket, &writable);
            FD_SET(socket, &errors);
            timeval timeout{long(proxy.timeoutMs / 1000), long((proxy.timeoutMs % 1000) * 1000)};
            checked(select(0, nullptr, &writable, &errors, &timeout) > 0, WSAETIMEDOUT);
            int code = 0;
            size = sizeof(code);
            checked(getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&code), &size) == 0);
            checked(code == 0, code);
        }
        nonblocking = 0;
        checked(ioctlsocket(socket, FIONBIO, &nonblocking) == 0);
        DWORD receiveTimeout = 0, sendTimeout = 0;
        size = sizeof(DWORD);
        checked(getsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&receiveTimeout),
                           &size) == 0);
        size = sizeof(DWORD);
        checked(getsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&sendTimeout), &size) ==
                0);
        struct Timeouts {
            SOCKET socket;
            DWORD receive, send;
            ~Timeouts() {
                setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&receive),
                           sizeof(receive));
                setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&send),
                           sizeof(send));
            }
        } restore{socket, receiveTimeout, sendTimeout};
        checked(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&proxy.timeoutMs),
                           sizeof(DWORD)) == 0);
        checked(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&proxy.timeoutMs),
                           sizeof(DWORD)) == 0);
        auto deadline = GetTickCount64() + proxy.timeoutMs;
        if (proxy.protocol == "socks5")
            socks(socket, destination, proxy, deadline);
        else
            http(socket, destination, proxy, deadline);
        return 0;
    } catch (const SocketFailure &failure) {
        shutdown(socket, SD_BOTH);
        WSASetLastError(failure.code);
        return SOCKET_ERROR;
    }
}
}

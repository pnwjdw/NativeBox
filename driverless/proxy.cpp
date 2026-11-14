#include "driverless/proxy.h"
#include "driverless/credentials.h"
#include <QHostAddress>

namespace nb {
QJsonObject probeProxy(const QJsonObject &profile, const QString &sandbox, const QJsonObject &request) {
    auto network = profile.value("network").toObject();
    if (network.value("mode").toString() != "managed_proxy")
        fail("network_mode", "Choose and save a ManagedProxy route before testing it");
    auto address = request.value("destination").toString();
    int port = request.value("port").toInt();
    if (QHostAddress(address).protocol() != QAbstractSocket::IPv4Protocol || port < 1 || port > 65535)
        fail("destination", "The connector test requires an explicit numeric IPv4 destination and port");
    auto proxy = proxyConfiguration(network, sandbox);
    proxy.timeoutMs = qMin(proxy.timeoutMs, DWORD(3000));
    auto wipe = qScopeGuard([&] {
        SecureZeroMemory(proxy.username.data(), proxy.username.size());
        SecureZeroMemory(proxy.password.data(), proxy.password.size());
    });
    WSADATA startup{};
    if (WSAStartup(MAKEWORD(2, 2), &startup))
        fail("network", "Winsock startup failed");
    auto cleanup = qScopeGuard([] { WSACleanup(); });
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET)
        fail("network", "Cannot create a connector test socket");
    auto close = qScopeGuard([&] { closesocket(socket); });
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(static_cast<unsigned short>(port));
    auto bytes = address.toLatin1();
    if (InetPtonA(AF_INET, bytes.constData(), &destination.sin_addr) != 1)
        fail("destination", "Destination must be a numeric IPv4 address");
    QElapsedTimer timer;
    timer.start();
    if (runtime::routeBlockingIpv4(socket, destination, proxy) == SOCKET_ERROR)
        fail("proxy_connect", "Proxy connector failed (Winsock " + QString::number(WSAGetLastError()) + ')');
    return {{"latencyMs", timer.elapsed()},
            {"destination", address},
            {"port", port},
            {"timeoutMs", qint64(proxy.timeoutMs)},
            {"proof", "connector_only"},
            {"runtimeTargetVerified", false},
            {"dns", "local"}};
}
}

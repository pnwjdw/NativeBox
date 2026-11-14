#include "driverless/ipc.h"
#include "driverless/store.h"
#include <QLocalServer>
#include <QLocalSocket>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("NativeBox");
    QCoreApplication::setApplicationName("NativeBox");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOption({"root", "Private data root", "path", nb::defaultRoot()});
    parser.process(app);
    try {
        HANDLE tokenValue = nullptr;
        nb::wincheck(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenValue),
                     "Inspect broker privileges");
        nb::Handle token(tokenValue);
        TOKEN_ELEVATION elevation{};
        DWORD tokenBytes = 0;
        nb::wincheck(
            GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &tokenBytes),
            "Read broker elevation");
        if (elevation.TokenIsElevated)
            nb::fail(
                "broker_elevated",
                "Start Driverless from a standard user session; elevated application launch is unsupported");
        auto root = nb::privatePath(QFileInfo(parser.value("root")).absoluteFilePath());
        nb::rejectReparse(root);
        if (!QDir().mkpath(root))
            nb::fail("storage", "Cannot create broker root");
        QLockFile lock(root + "/driverless-broker.lock");
        if (!lock.tryLock(0))
            return 0;
        nb::Store store(root);
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        if (!server.listen(nb::brokerName(root)))
            nb::fail("ipc_listen", server.errorString());
        QElapsedTimer activity;
        activity.start();
        QTimer idle;
        QObject::connect(&idle, &QTimer::timeout, &app, [&] {
            if (activity.elapsed() > 300000) {
                const auto status = store.execute({{"op", "status"}});
                if (status.value("activeProcesses").toInt() == 0 && status.value("activeExports").toInt() == 0)
                    app.quit();
            }
        });
        idle.start(10000);
        QObject::connect(&server, &QLocalServer::newConnection, &app, [&] {
            while (server.hasPendingConnections()) {
                auto socket = server.nextPendingConnection();
                try {
                    ULONG clientPid = 0;
                    nb::wincheck(GetNamedPipeClientProcessId(
                                     reinterpret_cast<HANDLE>(socket->socketDescriptor()), &clientPid),
                                 "Inspect client identity");
                    nb::Handle peer(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid));
                    nb::wincheck(bool(peer), "Open client identity");
                    if (nb::ownerSid(peer.get()) != nb::ownerSid() ||
                        nb::ownerSession(peer.get()) != nb::ownerSession())
                        nb::fail("ipc_identity", "Client identity mismatch");
                } catch (...) {
                    socket->abort();
                    socket->deleteLater();
                    continue;
                }
                auto buffer = std::make_shared<QByteArray>();
                auto handled = std::make_shared<bool>(false);
                auto deadline = new QTimer(socket);
                deadline->setSingleShot(true);
                QObject::connect(deadline, &QTimer::timeout, socket, [socket] {
                    socket->abort();
                    socket->deleteLater();
                });
                deadline->start(15000);
                QObject::connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
                QObject::connect(
                    socket, &QLocalSocket::readyRead, socket, [&, socket, buffer, handled, deadline] {
                        if (*handled)
                            return;
                        *buffer += socket->readAll();
                        if (buffer->size() > 1024 * 1024) {
                            socket->abort();
                            return;
                        }
                        if (!buffer->contains('\n'))
                            return;
                        *handled = true;
                        deadline->stop();
                        QJsonObject response;
                        bool shutdown = false;
                        try {
                            auto request = nb::parseObject(buffer->trimmed());
                            shutdown = request.value("op").toString() == "broker.shutdown";
                            response = shutdown ? QJsonObject{{"ok", true}} : store.execute(request);
                        } catch (const nb::Error &error) {
                            response = {{"ok", false},
                                        {"code", error.code},
                                        {"error", QString::fromUtf8(error.what())}};
                        }
                        activity.restart();
                        auto bytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
                        if (bytes.size() > 1024 * 1024)
                            bytes = "{\"ok\":false,\"code\":\"frame\",\"error\":\"Response exceeds the IPC "
                                    "limit; request a smaller page\"}";
                        socket->write(bytes + '\n');
                        socket->disconnectFromServer();
                        if (shutdown)
                            QTimer::singleShot(100, &app, &QCoreApplication::quit);
                    });
            }
        });
        return app.exec();
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << Qt::endl;
        return 1;
    }
}

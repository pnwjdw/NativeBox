#include "driverless/ipc.h"
#include "driverless/process.h"
#include <QLocalSocket>

namespace nb {
QString brokerName(const QString &root) {
    auto identity =
        ownerSid() + ':' + ownerSession() + ':' + privatePath(QFileInfo(root).absoluteFilePath()).toUpper();
    return "NativeBox.Driverless." +
           QString::fromLatin1(
               QCryptographicHash::hash(identity.toUtf8(), QCryptographicHash::Sha256).toHex());
}
QJsonObject driverlessRequest(const QString &root, const QJsonObject &request) {
    auto bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
    if (bytes.size() > 1024 * 1024)
        fail("frame", "Request exceeds the IPC limit");
    QLocalSocket socket;
    socket.connectToServer(brokerName(root));
    if (!socket.waitForConnected(200)) {
        auto executable = QCoreApplication::applicationDirPath() + "/nativebox_broker.exe";
        if (!QFileInfo::exists(executable))
            fail("broker_missing", "Driverless broker is missing");
        auto command =
            (quoteArgument(QDir::toNativeSeparators(executable)) + " --root " + quoteArgument(root))
                .toStdWString();
        auto image = QDir::toNativeSeparators(executable).toStdWString();
        auto directory = QCoreApplication::applicationDirPath().toStdWString();
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION information{};
        wincheck(CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                                nullptr, directory.c_str(), &startup, &information),
                 "Start same-user broker without inherited handles");
        Handle process(information.hProcess), thread(information.hThread);
        QDeadlineTimer deadline(5000);
        while (!deadline.hasExpired()) {
            socket.abort();
            socket.connectToServer(brokerName(root));
            if (socket.waitForConnected(100))
                break;
            QThread::msleep(50);
        }
        if (socket.state() != QLocalSocket::ConnectedState)
            fail("broker_connect", "Driverless broker did not become available");
    }
    ULONG serverPid = 0;
    wincheck(GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(socket.socketDescriptor()), &serverPid),
             "Inspect broker peer");
    Handle peer(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, serverPid));
    wincheck(bool(peer), "Open broker identity");
    if (ownerSid(peer.get()) != ownerSid() || ownerSession(peer.get()) != ownerSession())
        fail("broker_identity", "Broker peer does not belong to the current user and logon session");
    bytes.append('\n');
    if (socket.write(bytes) != bytes.size() ||
        (socket.bytesToWrite() && !socket.waitForBytesWritten(5000) && socket.bytesToWrite()))
        fail("ipc_write", "Cannot send bounded IPC frame");
    QByteArray response;
    QDeadlineTimer deadline(15000);
    while (!response.contains('\n') && !deadline.hasExpired()) {
        if (socket.bytesAvailable() || socket.waitForReadyRead(qMin(500, int(deadline.remainingTime()))))
            response += socket.readAll();
        else if (socket.state() == QLocalSocket::UnconnectedState)
            break;
        if (response.size() > 2 * 1024 * 1024)
            fail("frame", "Broker response exceeds the IPC limit");
    }
    if (!response.endsWith('\n'))
        fail("ipc_read", "Broker response was incomplete or timed out");
    return parseObject(response.trimmed());
}
}

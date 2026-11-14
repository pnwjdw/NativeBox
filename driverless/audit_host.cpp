#include "driverless/audit_etw.h"
#include "driverless/audit_protocol.h"
#include <QLocalServer>
#include <QLocalSocket>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOption({"pipe", "Private observer channel", "name"});
    parser.addOption({"nonce", "Channel nonce", "hex"});
    parser.addOption({"owner-pid", "Standard broker PID", "pid"});
    parser.addOption({"owner-created", "Standard broker creation identity", "filetime"});
    parser.process(app);
    try {
        const auto nonce = nb::audit::validateNonce(parser.value("nonce"));
        const auto endpoint = "NativeBox.Audit." + nonce;
        if (parser.value("pipe") != endpoint)
            nb::fail("audit_channel", "Observer endpoint does not match its nonce");
        bool validPid = false;
        const auto ownerPid = parser.value("owner-pid").toUInt(&validPid);
        if (!validPid || !ownerPid)
            nb::fail("audit_identity", "Observer requires a valid broker identity");
        const auto created = nb::audit::unsignedText(parser.value("owner-created"), "owner-created");
        nb::Handle owner(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | SYNCHRONIZE,
                                     FALSE, ownerPid));
        nb::wincheck(bool(owner), "Open observer broker identity");
        const auto ownerIdentity = nb::audit::readProcessIdentity(owner.get());
        if (ownerIdentity.creationTime != created ||
            !nb::audit::sameLogonOwner(ownerIdentity, nb::audit::readProcessIdentity(GetCurrentProcess())))
            nb::fail("audit_identity", "Observer and broker must share the exact logon owner");
        // Only the verified broker can submit process registrations. No output path, command line,
        // arbitrary handle operation, or privileged filesystem operation is accepted over this pipe.
        nb::AuditEtw observer;
        observer.start();
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        if (!server.listen(endpoint))
            nb::fail("audit_listen", "Cannot open the private observer channel");
        QJsonArray pending;
        QString pendingId, lastAck;
        QTimer ownerTimer;
        QObject::connect(&ownerTimer, &QTimer::timeout, &app, [&] {
            if (WaitForSingleObject(owner.get(), 0) == WAIT_OBJECT_0)
                app.quit();
        });
        ownerTimer.start(250);
        QObject::connect(&server, &QLocalServer::newConnection, &app, [&] {
            while (server.hasPendingConnections()) {
                auto socket = server.nextPendingConnection();
                ULONG peerPid = 0;
                if (!GetNamedPipeClientProcessId(reinterpret_cast<HANDLE>(socket->socketDescriptor()), &peerPid) ||
                    peerPid != ownerPid || !nb::audit::processMatches(peerPid, created)) {
                    socket->abort();
                    socket->deleteLater();
                    continue;
                }
                auto bytes = std::make_shared<QByteArray>();
                auto handled = std::make_shared<bool>(false);
                auto timeout = new QTimer(socket);
                timeout->setSingleShot(true);
                QObject::connect(timeout, &QTimer::timeout, socket, [socket] { socket->abort(); socket->deleteLater(); });
                timeout->start(5000);
                QObject::connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
                QObject::connect(socket, &QLocalSocket::readyRead, socket, [&, socket, bytes, handled, timeout] {
                    if (*handled) return;
                    *bytes += socket->readAll();
                    if (bytes->size() > nb::audit::MaxFrameBytes) { socket->abort(); return; }
                    if (!bytes->contains('\n')) return;
                    *handled = true;
                    timeout->stop();
                    QJsonObject response;
                    bool quit = false;
                    try {
                        const auto request = nb::audit::validateRequest(nb::audit::decodeFrame(*bytes));
                        if (request.value("nonce").toString() != nonce)
                            nb::fail("audit_nonce", "Observer channel authentication failed");
                        const auto operation = request.value("op").toString();
                        response = {{"ok", true}, {"contract", nb::audit::Contract}};
                        if (operation == "register") {
                            const auto registration = nb::audit::validateRegistration(request);
                            const auto pid = DWORD(registration.value("pid").toInteger());
                            const auto start = nb::audit::unsignedText(registration.value("creationTime"), "creationTime");
                            const auto raw = nb::audit::unsignedText(registration.value("jobHandle"), "jobHandle");
                            HANDLE copied = nullptr;
                            nb::wincheck(DuplicateHandle(owner.get(), reinterpret_cast<HANDLE>(quintptr(raw)),
                                                         GetCurrentProcess(), &copied, JOB_OBJECT_QUERY, FALSE, 0),
                                         "Duplicate query-only broker job");
                            nb::Handle job(copied);
                            nb::Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
                            nb::wincheck(bool(process), "Open audited process identity");
                            const auto identity = nb::audit::readProcessIdentity(process.get());
                            if (identity.creationTime != start || !nb::audit::sameLogonOwner(identity, ownerIdentity) ||
                                !nb::audit::processMatches(pid, start, job.get()))
                                nb::fail("audit_identity", "Audited process does not belong to the broker job and owner");
                            QString reason;
                            if (!observer.watch(pid, start, registration.value("sandbox").toString(),
                                                registration.value("runId").toString(), job.get(), &reason))
                                nb::fail("audit_register", reason);
                        } else if (operation == "unregister") {
                            if (!pending.isEmpty())
                                nb::fail("audit_pending", "Acknowledge the pending batch before retiring a run");
                            observer.unwatchSession(request.value("sandbox").toString(),
                                                    request.value("runId").toString());
                        } else if (operation == "poll") {
                            if (pending.isEmpty()) {
                                pending = observer.drain(qBound(1, request.value("limit").toInt(512), 512));
                                if (!pending.isEmpty()) pendingId = nb::id();
                            }
                            response["events"] = pending;
                            response["batchId"] = pendingId;
                            response["more"] = !pending.isEmpty();
                        } else if (operation == "ack") {
                            const auto batch = request.value("batchId").toString();
                            if (batch == pendingId && !pendingId.isEmpty()) {
                                lastAck = pendingId;
                                pending = {};
                                pendingId.clear();
                            } else if (batch != lastAck)
                                nb::fail("audit_ack", "Acknowledgement does not match the durable pending batch");
                        } else if (operation == "stop") {
                            observer.stop();
                        } else if (operation == "shutdown") {
                            observer.stop();
                            if (!pending.isEmpty() || observer.status().value("queuedRecords").toInteger() != 0)
                                nb::fail("audit_pending", "Audit records remain; persist and acknowledge the tail before shutdown");
                            quit = true;
                        } else if (operation != "hello" && operation != "status")
                            nb::fail("audit_operation", "Unsupported observer operation");
                        response["status"] = observer.status();
                    } catch (const nb::Error &error) {
                        response = {{"ok", false}, {"contract", nb::audit::Contract},
                                    {"code", error.code}, {"error", QString::fromUtf8(error.what())}};
                    } catch (const std::exception &error) {
                        response = {{"ok", false}, {"contract", nb::audit::Contract},
                                    {"code", "audit_error"}, {"error", QString::fromUtf8(error.what())}};
                    }
                    socket->write(nb::audit::encodeFrame(response));
                    socket->disconnectFromServer();
                    if (quit) QTimer::singleShot(100, &app, &QCoreApplication::quit);
                });
            }
        });
        const auto result = app.exec();
        observer.stop();
        return result;
    } catch (const nb::Error &error) {
        QTextStream(stderr) << error.what() << Qt::endl;
        if (error.code == "audit_identity") return 11;
        if (error.code == "audit_listen") return 12;
        if (error.code == "audit_channel" || error.code == "audit_nonce") return 13;
        return 14;
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << Qt::endl;
        return 1;
    }
}

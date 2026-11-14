#include "driverless/audit_client.h"
#include "driverless/process.h"
#include <objbase.h>
#include <shellapi.h>

namespace nb {
AuditClient::AuditClient(QString storageRoot) : root_(std::move(storageRoot)) {
    state_ = {{"status", "not_started"}, {"active", false}, {"completeAudit", false}};
    worker_.setObjectName("NativeBox.AuditArchive");
    context_.moveToThread(&worker_);
    worker_.start();
    try {
        onWorker([&] {
            const auto result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            if (FAILED(result) && result != RPC_E_CHANGED_MODE)
                fail("audit_thread", "Cannot initialize the audit worker COM apartment");
            comInitialized_ = SUCCEEDED(result);
            timer_ = new QTimer(&context_);
            timer_->setTimerType(Qt::PreciseTimer);
            timer_->setInterval(25);
            QObject::connect(timer_, &QTimer::timeout, &context_, [this] { pollImpl(64); });
            timer_->start();
        });
    } catch (...) {
        const auto owner = QThread::currentThread();
        onWorker([&] {
            delete timer_;
            timer_ = nullptr;
            if (comInitialized_) CoUninitialize();
            comInitialized_ = false;
            context_.moveToThread(owner);
        });
        worker_.quit();
        worker_.wait();
        throw;
    }
}
AuditClient::~AuditClient() {
    const auto owner = QThread::currentThread();
    onWorker([&] {
        if (timer_) timer_->stop();
        try { disableImpl(); } catch (...) {}
        delete timer_;
        timer_ = nullptr;
        // Keep every archive handle and all socket/timer destruction on their owning worker.
        sink_.reset();
        host_ = Handle();
        if (comInitialized_) CoUninitialize();
        comInitialized_ = false;
        context_.moveToThread(owner);
    });
    worker_.quit();
    worker_.wait();
}
QJsonObject AuditClient::enable(bool elevated) { return onWorker([&] { return enableImpl(elevated); }); }
QJsonObject AuditClient::disable() { return onWorker([&] { return disableImpl(); }); }
QJsonObject AuditClient::status(const QString &sandbox) const {
    return onWorker([&] { return statusImpl(sandbox); });
}
bool AuditClient::enabled() const { return onWorker([&] { return connected_; }); }
bool AuditClient::ready() const {
    return onWorker([&] { return connected_ && state_.value("allRequestedProvidersReady").toBool() &&
                                state_.value("systemCallsReady").toBool() && error_.isEmpty(); });
}
void AuditClient::watch(HANDLE process, HANDLE job, const QString &sandbox, const QString &runId) {
    onWorker([&] { watchImpl(process, job, sandbox, runId); });
}
void AuditClient::forget(const QString &sandbox) { onWorker([&] { forgetImpl(sandbox); }); }
QJsonArray AuditClient::poll(int batches) { return onWorker([&] { return pollImpl(batches); }); }
void AuditClient::verifyPeer(QLocalSocket &socket) {
    ULONG pid = 0;
    wincheck(GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(socket.socketDescriptor()), &pid),
             "Read audit observer identity");
    if (!host_ || pid != GetProcessId(host_.get()))
        fail("audit_identity", "Audit observer pipe does not belong to the launched process");
    const auto peer = audit::readProcessIdentity(host_.get());
    if (!audit::sameLogonOwner(peer, audit::readProcessIdentity(GetCurrentProcess())))
        fail("audit_identity", "Audit observer belongs to another Windows identity");
}
QJsonObject AuditClient::call(QJsonObject request) {
    request["contract"] = audit::Contract;
    request["nonce"] = nonce_;
    QLocalSocket socket;
    socket.connectToServer(endpoint_);
    if (!socket.waitForConnected(2000))
        fail("audit_disconnected", "System observer is unavailable");
    verifyPeer(socket);
    const auto frame = audit::encodeFrame(request);
    if (socket.write(frame) != frame.size())
        fail("audit_write", "Cannot send observer request");
    if (socket.bytesToWrite() && !socket.waitForBytesWritten(2000) && socket.bytesToWrite())
        fail("audit_write", "Observer request timed out");
    QByteArray bytes;
    QDeadlineTimer deadline(5000);
    while (!bytes.contains('\n') && !deadline.hasExpired()) {
        if (socket.bytesAvailable() || socket.waitForReadyRead(qMin(250, int(deadline.remainingTime()))))
            bytes += socket.readAll();
        else if (socket.state() == QLocalSocket::UnconnectedState)
            break;
        if (bytes.size() > audit::MaxFrameBytes)
            fail("audit_frame", "Observer response exceeds the protocol bound");
    }
    if (!bytes.endsWith('\n'))
        fail("audit_timeout", "Observer response was incomplete");
    auto response = audit::decodeFrame(bytes);
    if (response.value("contract").toString() != audit::Contract)
        fail("audit_contract", "Observer returned another protocol contract");
    if (!response.value("ok").toBool())
        fail(response.value("code").toString("audit_error"), response.value("error").toString());
    if (response.contains("status"))
        state_ = response.value("status").toObject();
    state_["active"] = state_.value("running").toBool();
    return response;
}
QJsonObject AuditClient::enableImpl(bool elevated) {
    if (connected_)
        return statusImpl();
    if (host_) disableImpl();
    if (host_)
        fail("audit_stop_pending", "Previous observer still has unarchived records; retry the audit stop first");
    nonce_ = id().remove('-') + id().remove('-');
    endpoint_ = "NativeBox.Audit." + nonce_;
    const auto executable = QCoreApplication::applicationDirPath() + "/nativebox_audit.exe";
    rejectReparse(executable);
    if (!QFileInfo(executable).isFile())
        fail("audit_missing", "System observer executable is missing");
    const auto identity = audit::readProcessIdentity(GetCurrentProcess());
    QString parameters = "--pipe " + quoteArgument(endpoint_) + " --owner-pid " + QString::number(identity.pid) +
                         " --owner-created " + QString::number(identity.creationTime) + " --nonce " + nonce_;
    auto file = QDir::toNativeSeparators(executable).toStdWString();
    auto args = parameters.toStdWString();
    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    launch.lpVerb = elevated ? L"runas" : L"open";
    launch.lpFile = file.c_str();
    launch.lpParameters = args.c_str();
    launch.nShow = SW_HIDE;
    if (!ShellExecuteExW(&launch)) {
        const auto code = GetLastError();
        error_ = "Windows could not start the system observer (" + QString::number(code) + ')';
        state_ = {{"active", false}, {"status", code == ERROR_CANCELLED ? "elevation_cancelled" : "start_failed"},
                  {"win32Error", qint64(code)}, {"completeAudit", false}};
        return statusImpl();
    }
    host_ = Handle(launch.hProcess);
    if (!host_)
        fail("audit_identity", "Windows did not return the observer process identity");
    QDeadlineTimer deadline(10000);
    bool ready = false;
    while (!deadline.hasExpired()) {
        QLocalSocket probe;
        probe.connectToServer(endpoint_);
        if (probe.waitForConnected(100)) {
            verifyPeer(probe);
            ready = true;
            break;
        }
        if (WaitForSingleObject(host_.get(), 0) == WAIT_OBJECT_0)
            break;
        QThread::msleep(25);
    }
    if (!ready) {
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(host_.get(), &exitCode);
        error_ = "Observer did not become available";
        state_ = {{"active", false}, {"status", "start_failed"}, {"completeAudit", false},
                  {"observerExitCode", qint64(exitCode)}};
        return statusImpl();
    }
    call({{"op", "hello"}});
    connected_ = state_.value("running").toBool();
    error_.clear();
    if (!connected_)
        return statusImpl();
    sink_ = std::make_unique<audit::AuditLogSink>(root_);
    return statusImpl();
}
QJsonObject AuditClient::statusImpl(const QString &sandbox) const {
    auto result = state_;
    result["connected"] = connected_;
    result["error"] = error_;
    result["sink"] = sink_ ? sink_->status(sandbox) : QJsonObject();
    result["privilegeSeparation"] = "standard_user_targets_elevated_read_only_etw_observer";
    return result;
}
void AuditClient::watchImpl(HANDLE process, HANDLE job, const QString &sandbox, const QString &runId) {
    if (!connected_)
        return;
    const auto identity = audit::readProcessIdentity(process);
    call({{"op", "register"}, {"sandbox", validateId(sandbox)}, {"runId", validateId(runId)},
          {"pid", qint64(identity.pid)}, {"creationTime", QString::number(identity.creationTime)},
          {"jobHandle", QString::number(quintptr(job))}});
    registrations_[sandbox].insert(runId);
    roots_[sandbox][runId] = identity;
    archiveHealth(true);
}
void AuditClient::archiveHealth(bool force) {
    if (!sink_) return;
    QJsonObject health;
    for (const auto &key : {"running", "allRequestedProvidersReady", "systemCallsReady", "eventsLost",
                            "buffersLost", "queueDropped", "decodeErrors", "callbackErrors",
                            "shutdownTailMayBeIncomplete", "pendingTargetDropped", "pendingUnattributedEvicted",
                            "cpuOrderAmbiguous", "unwatchDiscarded", "status", "observerExitCode",
                            "realtimeLostEventNotifications", "realtimeLostBufferNotifications",
                            "realtimeLostFileNotifications", "liveLossCountersProvisional",
                            "lossCountersFinal", "pendingEvictionsMayIncludeOwnedTraffic", "queuedRecords",
                            "pendingTargetRecords", "pendingUnattributedSystemCalls"})
        health[key] = state_.value(key);
    health["counterScope"] = "whole_observer_sessions";
    health["archiveFailures"] = sink_->status().value("archiveFailures");
    if (!error_.isEmpty()) health["lastObserverOrArchiveError"] = error_.left(1024);
    const auto fingerprint = QJsonDocument(health).toJson(QJsonDocument::Compact);
    if (!force && fingerprint == healthFingerprint_) return;
    const auto currentMs = QDateTime::currentMSecsSinceEpoch();
    if (!force && currentMs >= lastHealthMs_ && currentMs - lastHealthMs_ < 1000) return;
    health["healthSamplingIntervalMs"] = 1000;
    health["providers"] = state_.value("providers");
    health["sessions"] = state_.value("sessions");
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    const auto stamp = (quint64(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    QJsonArray records;
    for (auto sandbox = roots_.cbegin(); sandbox != roots_.cend(); ++sandbox)
        for (auto run = sandbox.value().cbegin(); run != sandbox.value().cend(); ++run)
            records.append(QJsonObject{{"schema", 2}, {"source", "windows_etw"},
                {"sandbox", sandbox.key()}, {"runId", run.key()}, {"pid", qint64(run.value().pid)},
                {"creationTime", QString::number(run.value().creationTime)}, {"threadId", 0},
                {"fileTime", QString::number(stamp)}, {"category", "telemetry"},
                {"operation", "AuditCoverage"}, {"provider", "NativeBox.Observer.Health"},
                {"eventId", 0}, {"opcode", 0}, {"properties", health}});
    // One record per run so the shared frame bound also applies to a broker with many sandboxes.
    for (const auto &record : records) sink_->append(record.toObject());
    healthFingerprint_ = fingerprint;
    lastHealthMs_ = currentMs;
}
void AuditClient::forgetImpl(const QString &sandbox) {
    pollImpl(64);
    if (!error_.isEmpty() || !pendingAck_.isEmpty())
        fail("audit_pending", "Cannot remove a sandbox while its audit archive has an uncommitted batch");
    const auto runs = registrations_.value(sandbox);
    for (const auto &run : runs)
        call({{"op", "unregister"}, {"sandbox", sandbox}, {"runId", run}});
    if (sink_) sink_->closeSandbox(sandbox);
    registrations_.remove(sandbox);
    roots_.remove(sandbox);
}
QJsonArray AuditClient::pollImpl(int batches) {
    QJsonArray collected;
    if (!connected_)
        return collected;
    try {
        QElapsedTimer budget;
        budget.start();
        for (int index = 0; index < batches; ++index) {
            if (!pendingAck_.isEmpty()) {
                call({{"op", "ack"}, {"batchId", pendingAck_}});
                pendingAck_.clear();
            }
            auto response = call({{"op", "poll"}, {"limit", audit::MaxBatchRecords}});
            auto events = audit::validateBatch(response.value("events").toArray());
            const auto batch = response.value("batchId").toString();
            if (!events.isEmpty()) {
                validateId(batch);
                for (qsizetype eventIndex = 0; eventIndex < events.size(); ++eventIndex) {
                    auto event = events[eventIndex].toObject();
                    event["auditBatchId"] = batch;
                    event["auditBatchIndex"] = qint64(eventIndex);
                    events[eventIndex] = event;
                }
            }
            sink_->appendBatch(events);
            archiveHealth();
            if (!events.isEmpty()) {
                pendingAck_ = batch;
                call({{"op", "ack"}, {"batchId", pendingAck_}});
                pendingAck_.clear();
            }
            for (const auto &event : events)
                collected.append(event);
            error_.clear();
            if (events.isEmpty() || !response.value("more").toBool() || budget.elapsed() > 150)
                break;
        }
    } catch (const std::exception &error) {
        error_ = QString::fromUtf8(error.what());
        state_["status"] = "observer_or_sink_error";
        state_["completeAudit"] = false;
        // Preserve a durable gap marker when transport fails but the archive remains writable.
        // A failed marker must never replace the original error or acknowledge pending data.
        try { archiveHealth(true); } catch (...) {}
        // Do not disable or silently forget the observer's queue on transient sink errors.
    }
    return collected;
}
QJsonObject AuditClient::disableImpl() {
    if (host_ && WaitForSingleObject(host_.get(), 0) == WAIT_OBJECT_0 && connected_) {
        DWORD code = 0;
        GetExitCodeProcess(host_.get(), &code);
        error_ = QString("Observer exited unexpectedly (%1); its unread tail is unavailable").arg(code);
        state_["status"] = "observer_exited";
        state_["running"] = false;
        state_["active"] = false;
        state_["observerExitCode"] = qint64(code);
        state_["completeAudit"] = false;
        try { archiveHealth(true); } catch (...) {}
    }
    if (host_ && WaitForSingleObject(host_.get(), 0) != WAIT_OBJECT_0) {
        try {
            call({{"op", "stop"}});
            // Stopped producers leave a finite queue. Disk speed or a preceding burst must not
            // decide which accepted records survive broker shutdown: keep committing and ACKing
            // while the queue shrinks, and retain stop_pending on an actual failure or stalled IPC.
            auto queued = state_.value("queuedRecords").toInteger(-1);
            if (queued < 0)
                fail("audit_protocol", "Stopped observer omitted its remaining record count");
            // A previous append failure can leave a host-owned batch after it was removed from
            // the raw queue, before pendingAck_ was set. Always recover that batch once as well.
            bool firstPass = connected_ && bool(sink_);
            while (firstPass || queued || !pendingAck_.isEmpty()) {
                firstPass = false;
                if (!connected_ || !sink_)
                    fail("audit_pending", "Audit records remain without an available archive connection");
                const auto before = queued;
                const auto hadPendingAck = !pendingAck_.isEmpty();
                const auto records = pollImpl(64);
                if (!error_.isEmpty())
                    fail("audit_pending", error_);
                queued = state_.value("queuedRecords").toInteger(-1);
                if (queued < 0)
                    fail("audit_protocol", "Observer omitted its remaining record count while draining");
                const bool acknowledged = hadPendingAck && pendingAck_.isEmpty();
                if (queued && records.isEmpty() && queued >= before && !acknowledged)
                    fail("audit_pending", "Stopped observer made no progress while archiving its remaining records");
            }
            archiveHealth(true);
            if (sink_) sink_->flush();
            call({{"op", "shutdown"}});
        } catch (const std::exception &error) {
            error_ = QString::fromUtf8(error.what());
            state_["status"] = "stop_pending";
            state_["completeAudit"] = false;
            try { archiveHealth(true); } catch (...) {}
            return statusImpl();
        }
    }
    connected_ = false;
    registrations_.clear();
    roots_.clear();
    pendingAck_.clear();
    sink_.reset();
    state_["active"] = false;
    state_["status"] = "stopped";
    host_ = Handle();
    return statusImpl();
}
}

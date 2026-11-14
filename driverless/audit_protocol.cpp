#include "driverless/runtime/base.h"
#include "driverless/audit_protocol.h"
#include <sddl.h>
#include <cmath>
#include <limits>
#include <map>

namespace nb::audit {
namespace {
QString textField(const QJsonObject &object, const QString &field, qsizetype maximum,
                  bool required = true) {
    const auto item = object.value(field);
    if (!item.isString() || (required && item.toString().isEmpty()) ||
        item.toString().size() > maximum || item.toString().contains(QChar(0)))
        fail("audit_shape", "Invalid audit text field: " + field);
    return item.toString();
}
quint64 integerField(const QJsonObject &object, const QString &field, quint64 maximum,
                     bool zero = true) {
    const auto item = object.value(field);
    if (!item.isDouble())
        fail("audit_shape", "Audit field is not an integer: " + field);
    const auto number = item.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number || number < (zero ? 0.0 : 1.0) ||
        number > double(maximum))
        fail("audit_shape", "Audit integer is outside its range: " + field);
    return quint64(number);
}
void boundedJson(const QJsonValue &value, unsigned depth = 0) {
    if (depth > 32)
        fail("audit_shape", "Audit event nesting exceeds the supported depth");
    if (value.isObject()) {
        const auto object = value.toObject();
        if (object.size() > 512)
            fail("audit_shape", "Audit object has too many properties");
        for (auto it = object.begin(); it != object.end(); ++it) {
            if (it.key().size() > 512 || it.key().contains(QChar(0)))
                fail("audit_shape", "Invalid audit property name");
            boundedJson(it.value(), depth + 1);
        }
    } else if (value.isArray()) {
        const auto array = value.toArray();
        if (array.size() > 4096)
            fail("audit_shape", "Audit array has too many items");
        for (const auto &entry : array)
            boundedJson(entry, depth + 1);
    } else if (value.isString() && value.toString().size() > MaxEventBytes / 2)
        fail("audit_shape", "Audit property text exceeds the supported size");
}
void onlyFields(const QJsonObject &object, const QStringList &allowed) {
    for (auto it = object.begin(); it != object.end(); ++it)
        if (!allowed.contains(it.key()))
            fail("audit_shape", "Unsupported audit request field: " + it.key());
}
std::wstring nativePhysical(const QString &path) {
    return runtime::extendedPath(QDir::toNativeSeparators(path).toStdWString());
}
struct TokenIdentity {
    QString sid;
    DWORD session = 0;
    LUID authentication{};
    TOKEN_ELEVATION_TYPE elevation = TokenElevationTypeDefault;
};
TokenIdentity tokenIdentity(HANDLE token) {
    TokenIdentity identity;
    TOKEN_STATISTICS statistics{};
    DWORD count = 0;
    wincheck(GetTokenInformation(token, TokenStatistics, &statistics, sizeof(statistics), &count),
             "Read audit token authentication identity");
    identity.authentication = statistics.AuthenticationId;
    wincheck(GetTokenInformation(token, TokenSessionId, &identity.session, sizeof(identity.session), &count),
             "Read audit token Windows session");
    wincheck(GetTokenInformation(token, TokenElevationType, &identity.elevation, sizeof(identity.elevation), &count),
             "Read audit token elevation type");
    GetTokenInformation(token, TokenUser, nullptr, 0, &count);
    if (!count || count > 65536)
        fail("audit_identity", "Invalid audit token user information size");
    QByteArray bytes(count, Qt::Uninitialized);
    wincheck(GetTokenInformation(token, TokenUser, bytes.data(), count, &count),
             "Read audit token user identity");
    LPWSTR text = nullptr;
    wincheck(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(bytes.data())->User.Sid, &text),
             "Format audit token user identity");
    auto release = qScopeGuard([&] { LocalFree(text); });
    identity.sid = QString::fromWCharArray(text);
    return identity;
}
QString logonKey(const TokenIdentity &token) {
    return QString::number(token.session) + ':' + QString::number(quint32(token.authentication.HighPart)) +
           ':' + QString::number(token.authentication.LowPart);
}
bool identicalOwner(const TokenIdentity &first, const TokenIdentity &second) {
    return first.sid == second.sid && first.session == second.session &&
           first.authentication.LowPart == second.authentication.LowPart &&
           first.authentication.HighPart == second.authentication.HighPart;
}
}

QJsonObject ProcessIdentity::json() const {
    return {{"pid", qint64(pid)}, {"creationTime", QString::number(creationTime)},
            {"sid", sid}, {"logonSession", logonSession},
            {"windowsSessionId", qint64(windowsSessionId)},
            {"linkedLogonSession", linkedLogonSession}, {"linkedTokenVerified", linkedTokenVerified},
            {"linkedTokenStatus", linkedTokenStatus}};
}
ProcessIdentity readProcessIdentity(HANDLE process) {
    ProcessIdentity result;
    result.pid = GetProcessId(process);
    if (!result.pid)
        wincheck(false, "Read audit process ID");
    FILETIME created{}, exited{}, kernel{}, user{};
    wincheck(GetProcessTimes(process, &created, &exited, &kernel, &user),
             "Read audit process creation time");
    result.creationTime = (quint64(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    HANDLE tokenValue = nullptr;
    wincheck(OpenProcessToken(process, TOKEN_QUERY, &tokenValue), "Open audit process identity token");
    Handle token(tokenValue);
    const auto own = tokenIdentity(token.get());
    DWORD windowsSession = 0;
    wincheck(ProcessIdToSessionId(result.pid, &windowsSession), "Read audit process Windows session");
    if (own.session != windowsSession)
        fail("audit_identity", "Process and token Windows sessions do not agree");
    result.sid = own.sid;
    result.logonSession = logonKey(own);
    result.windowsSessionId = own.session;
    result.linkedTokenStatus = "not_linked";
    TOKEN_LINKED_TOKEN linkedValue{};
    DWORD count = 0;
    if (GetTokenInformation(token.get(), TokenLinkedToken, &linkedValue, sizeof(linkedValue), &count)) {
        Handle linked(linkedValue.LinkedToken);
        try {
            const auto peer = tokenIdentity(linked.get());
            TOKEN_LINKED_TOKEN backValue{};
            wincheck(GetTokenInformation(linked.get(), TokenLinkedToken, &backValue, sizeof(backValue), &count),
                     "Verify reciprocal linked-token identity");
            Handle back(backValue.LinkedToken);
            const auto reciprocal = tokenIdentity(back.get());
            const bool splitElevation =
                (own.elevation == TokenElevationTypeLimited && peer.elevation == TokenElevationTypeFull) ||
                (own.elevation == TokenElevationTypeFull && peer.elevation == TokenElevationTypeLimited);
            // A UAC split token can have another AuthenticationId. Accept that relation only when
            // Windows supplied the linked token and its reciprocal points back to the original
            // SID, Windows session and authentication LUID. Same-account runas logons are not enough.
            if (splitElevation && peer.sid == own.sid && peer.session == own.session &&
                identicalOwner(own, reciprocal) && reciprocal.elevation == own.elevation) {
                result.linkedLogonSession = logonKey(peer);
                result.linkedTokenVerified = true;
                result.linkedTokenStatus = "reciprocal_uac_split_token";
            } else
                result.linkedTokenStatus = "linked_identity_mismatch";
        } catch (const Error &) {
            // A missing/denied linked-token query must retain the strict exact-LUID path.
            result.linkedTokenStatus = "linked_query_unavailable";
        }
    }
    return result;
}
bool processMatches(DWORD pid, quint64 creationTime, HANDLE job) noexcept {
    const DWORD saved = GetLastError();
    bool match = false;
    try {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        if (process && WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT) {
            FILETIME created{}, exited{}, kernel{}, user{};
            if (GetProcessTimes(process.get(), &created, &exited, &kernel, &user) &&
                ((quint64(created.dwHighDateTime) << 32) | created.dwLowDateTime) == creationTime) {
                BOOL member = FALSE;
                match = !job || (IsProcessInJob(process.get(), job, &member) && member);
            }
        }
    } catch (...) {
    }
    SetLastError(saved);
    return match;
}
bool sameLogonOwner(const ProcessIdentity &first, const ProcessIdentity &second) noexcept {
    if (first.sid.isEmpty() || first.logonSession.isEmpty() || second.logonSession.isEmpty() ||
        first.sid != second.sid || first.windowsSessionId != second.windowsSessionId)
        return false;
    if (first.logonSession == second.logonSession)
        return true;
    return (first.linkedTokenVerified && first.linkedLogonSession == second.logonSession) ||
           (second.linkedTokenVerified && second.linkedLogonSession == first.logonSession);
}
quint64 unsignedText(const QJsonValue &value, const QString &field, bool allowZero) {
    if (!value.isString())
        fail("audit_shape", "Audit integer must be encoded as decimal text: " + field);
    const auto string = value.toString();
    if (string.isEmpty() || string.size() > 20 ||
        (string.size() > 1 && string.front() == '0'))
        fail("audit_shape", "Invalid audit decimal text: " + field);
    for (QChar character : string)
        if (character < '0' || character > '9')
            fail("audit_shape", "Invalid audit decimal digit: " + field);
    bool converted = false;
    auto result = string.toULongLong(&converted, 10);
    if (!converted || (!allowZero && !result))
        fail("audit_shape", "Audit decimal value is outside its range: " + field);
    return result;
}
QString validateNonce(const QString &nonce) {
    static const QRegularExpression pattern("^[a-f0-9]{64}$");
    if (!pattern.match(nonce).hasMatch())
        fail("audit_nonce", "Invalid audit channel nonce");
    return nonce;
}
QJsonObject validateRegistration(const QJsonObject &request) {
    const auto sandbox = validateId(textField(request, "sandbox", 36));
    const auto run = validateId(textField(request, "runId", 36));
    auto pid = integerField(request, "pid", MAXDWORD, false);
    auto creation = unsignedText(request.value("creationTime"), "creationTime");
    auto handle = unsignedText(request.value("jobHandle"), "jobHandle");
    if (handle > quint64(std::numeric_limits<quintptr>::max()))
        fail("audit_shape", "Audit job handle cannot fit in this process");
    return {{"sandbox", sandbox}, {"runId", run}, {"pid", qint64(pid)},
            {"creationTime", QString::number(creation)}, {"jobHandle", QString::number(handle)}};
}
QJsonObject validateRequest(const QJsonObject &request) {
    if (request.value("contract").toString() != Contract)
        fail("audit_contract", "Unsupported audit protocol contract");
    validateNonce(textField(request, "nonce", 64));
    const auto operation = textField(request, "op", 32);
    const QStringList base{"contract", "nonce", "op"};
    if (operation == "register") {
        onlyFields(request, base + QStringList{"sandbox", "runId", "pid", "creationTime", "jobHandle"});
        auto normalized = validateRegistration(request);
        for (const auto &field : base)
            normalized[field] = request.value(field);
        return normalized;
    }
    if (operation == "unregister") {
        onlyFields(request, base + QStringList{"sandbox", "runId"});
        validateId(textField(request, "sandbox", 36));
        validateId(textField(request, "runId", 36));
    } else if (operation == "ack") {
        onlyFields(request, base + QStringList{"batchId"});
        validateId(textField(request, "batchId", 36));
    } else if (operation == "poll") {
        onlyFields(request, base + QStringList{"after", "limit"});
        if (request.contains("after"))
            unsignedText(request.value("after"), "after", true);
        if (request.contains("limit"))
            integerField(request, "limit", MaxBatchRecords, false);
    } else if (operation == "hello" || operation == "status" || operation == "stop" || operation == "shutdown")
        onlyFields(request, base);
    else
        fail("audit_operation", "Unsupported audit observer operation");
    if (QJsonDocument(request).toJson(QJsonDocument::Compact).size() > MaxFrameBytes)
        fail("audit_frame", "Audit request exceeds its frame limit");
    return request;
}
QJsonObject validateEvent(const QJsonObject &event) {
    if (event.value("schema").toInt() != 2 || event.value("source").toString() != "windows_etw")
        fail("audit_event", "Unsupported audit event schema or source");
    validateId(textField(event, "sandbox", 36));
    validateId(textField(event, "runId", 36));
    const auto category = textField(event, "category", 32);
    if (!QStringList{"wmi", "file", "registry", "network", "process", "syscall", "telemetry"}.contains(category))
        fail("audit_event", "Unsupported audit category");
    auto pid = integerField(event, "pid", MAXDWORD);
    auto creation = unsignedText(event.value("creationTime"), "creationTime", category == "telemetry");
    if ((!pid || !creation) && category != "telemetry")
        fail("audit_event", "An attributed audit event requires a process identity");
    integerField(event, "threadId", MAXDWORD);
    auto time = unsignedText(event.value("fileTime"), "fileTime");
    if (time < 116444736000000000ULL || time > quint64(std::numeric_limits<qint64>::max()))
        fail("audit_event", "Invalid audit timestamp");
    textField(event, "operation", 256);
    if (event.contains("provider"))
        textField(event, "provider", 512, false);
    if (event.contains("providerGuid"))
        textField(event, "providerGuid", 64);
    if (!event.contains("provider") && !event.contains("providerGuid"))
        fail("audit_event", "Audit event has no provider identity");
    if (event.contains("eventId"))
        integerField(event, "eventId", 65535);
    if (event.contains("opcode"))
        integerField(event, "opcode", 255);
    if (event.contains("path"))
        textField(event, "path", 32760, false);
    if (!event.value("properties").isObject())
        fail("audit_event", "Audit properties must be an object");
    if (event.contains("auditBatchId") || event.contains("auditBatchIndex")) {
        validateId(textField(event, "auditBatchId", 36));
        integerField(event, "auditBatchIndex", MaxBatchRecords - 1);
    }
    boundedJson(event);
    if (QJsonDocument(event).toJson(QJsonDocument::Compact).size() > MaxEventBytes - 1024)
        fail("audit_event", "Audit event exceeds its archive record budget");
    auto normalized = event;
    normalized["timeUtc"] = QDateTime::fromMSecsSinceEpoch(qint64((time - 116444736000000000ULL) / 10000),
                                                        QTimeZone::UTC).toString(Qt::ISODateWithMs);
    return normalized;
}
QJsonArray validateBatch(const QJsonArray &events) {
    if (events.size() > MaxBatchRecords)
        fail("audit_frame", "Audit batch has too many events");
    QJsonArray result;
    for (const auto &entry : events) {
        if (!entry.isObject())
            fail("audit_event", "Audit batch contains a non-object event");
        result.append(validateEvent(entry.toObject()));
    }
    if (QJsonDocument(result).toJson(QJsonDocument::Compact).size() > MaxBatchBytes)
        fail("audit_frame", "Audit batch exceeds its byte limit");
    return result;
}
QByteArray encodeFrame(const QJsonObject &object) {
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (bytes.size() > MaxFrameBytes)
        fail("audit_frame", "Audit frame exceeds one MiB");
    return bytes + '\n';
}
QJsonObject decodeFrame(const QByteArray &bytes) {
    if (bytes.isEmpty() || bytes.size() > MaxFrameBytes + 1 || !bytes.endsWith('\n') ||
        bytes.indexOf('\n') != bytes.size() - 1)
        fail("audit_frame", "Expected exactly one complete audit JSON frame");
    return parseObject(bytes.first(bytes.size() - 1));
}

struct AuditLogSink::Impl {
    struct Stream {
        QString sandbox, run, directory, filename;
        Handle file;
        quint64 sequence = 0;
        qint64 bytes = 0;
        quint64 segment = 0;
        quint64 rows = 0;
        bool dirty = false;
    };
    QString root;
    const QString writer = id();
    qint64 segmentBytes;
    quint64 rows = 0, segments = 0, failures = 0;
    QString lastError;
    bool rollbackFailed = false;
    std::map<QString, Stream> streams;
    struct BatchState { QByteArray fingerprint; bool committed = false; };
    std::map<QString, BatchState> committedBatches;
    QStringList committedOrder;
    struct FileCheckpoint {
        Handle file;
        qint64 bytes = 0;
    };
    struct StreamCheckpoint {
        bool existed = false;
        Handle file;
        QString filename;
        quint64 sequence = 0, segment = 0, rows = 0;
        qint64 bytes = 0;
        bool dirty = false;
    };
    std::map<QString, FileCheckpoint> *fileCheckpoints = nullptr;

    static Handle duplicate(HANDLE file) {
        HANDLE value = nullptr;
        wincheck(DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &value, 0, FALSE,
                                 DUPLICATE_SAME_ACCESS), "Checkpoint passive audit archive handle");
        return Handle(value);
    }

    Impl(QString storageRoot, qint64 size) : root(privatePath(storageRoot)), segmentBytes(size) {
        if (segmentBytes < MaxEventBytes || segmentBytes > 256 * 1024 * 1024)
            fail("audit_storage", "Invalid audit archive segment limit");
    }
    void open(Stream &stream) {
        try {
            runtime::directories(QDir::toNativeSeparators(stream.directory).toStdWString());
            for (unsigned attempt = 0; attempt < 10000; ++attempt) {
                const auto name = stream.run + '_' + writer + '_' + QString::number(stream.segment) + ".jsonl";
                auto destination = QDir(stream.directory).filePath(name);
                Handle file(CreateFileW(nativePhysical(destination).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                        nullptr));
                if (!file) {
                    const auto error = GetLastError();
                    if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
                        // A rolled-back rotation may leave an empty segment. Never overwrite it.
                        ++stream.segment;
                        continue;
                    }
                    wincheck(false, "Create passive audit archive segment");
                }
                stream.file = std::move(file);
                stream.filename = destination;
                stream.bytes = 0;
                ++segments;
                return;
            }
            fail("audit_storage", "Audit segment collision limit exceeded");
        } catch (const runtime::Error &error) {
            fail("audit_storage", QString::fromUtf8(error.what()) + " (" + QString::number(error.code) + ')');
        }
    }
    void flush(Stream &stream) {
        if (stream.file && stream.dirty) {
            wincheck(FlushFileBuffers(stream.file.get()), "Flush passive audit archive");
            stream.dirty = false;
        }
    }
    void append(const QJsonObject &original) {
        const auto sandbox = original.value("sandbox").toString(), run = original.value("runId").toString();
        const auto key = sandbox + '/' + run;
        auto &stream = streams[key];
        if (stream.sandbox.isEmpty()) {
            stream.sandbox = sandbox;
            stream.run = run;
            stream.directory = privatePath(root + "/driverless/sandboxes/" + sandbox + "/audit");
        }
        if (!stream.file)
            open(stream);
        auto event = original;
        event["writerId"] = writer;
        event["archiveSequence"] = QString::number(stream.sequence);
        event["segment"] = qint64(stream.segment);
        auto bytes = QJsonDocument(event).toJson(QJsonDocument::Compact) + '\n';
        if (stream.bytes && stream.bytes + bytes.size() > segmentBytes) {
            flush(stream);
            ++stream.segment;
            open(stream);
            event["segment"] = qint64(stream.segment);
            bytes = QJsonDocument(event).toJson(QJsonDocument::Compact) + '\n';
        }
        if (bytes.size() > MaxEventBytes)
            fail("audit_storage", "Encoded passive audit record exceeds its archive limit");
        if (fileCheckpoints && !fileCheckpoints->contains(stream.filename)) {
            FileCheckpoint checkpoint{duplicate(stream.file.get()), stream.bytes};
            fileCheckpoints->emplace(stream.filename, std::move(checkpoint));
        }
        qsizetype offset = 0;
        while (offset < bytes.size()) {
            DWORD written = 0;
            wincheck(WriteFile(stream.file.get(), bytes.constData() + offset, DWORD(bytes.size() - offset),
                               &written, nullptr) && written != 0, "Append passive audit archive");
            offset += written;
        }
        stream.bytes += bytes.size();
        stream.dirty = true;
        ++stream.sequence;
        ++stream.rows;
        ++rows;
    }
};
AuditLogSink::AuditLogSink(QString storageRoot, qint64 segmentBytes)
    : impl_(std::make_unique<Impl>(std::move(storageRoot), segmentBytes)) {}
AuditLogSink::~AuditLogSink() {
    try { flush(); } catch (...) {}
}
void AuditLogSink::append(const QJsonObject &event) { appendBatch(QJsonArray{event}); }
void AuditLogSink::appendBatch(const QJsonArray &events) {
    if (impl_->rollbackFailed)
        fail("audit_storage", "Audit archive rollback failed; reopen the broker before accepting more batches");
    auto normalized = validateBatch(events);
    QString batchId;
    for (qsizetype index = 0; index < normalized.size(); ++index) {
        const auto event = normalized[index].toObject();
        const auto value = event.value("auditBatchId").toString();
        if (index == 0)
            batchId = value;
        if (value != batchId || (!value.isEmpty() && event.value("auditBatchIndex").toInt(-1) != index))
            fail("audit_event", "Audit batch IDs or contiguous indexes do not match");
    }
    const auto fingerprint = QCryptographicHash::hash(QJsonDocument(normalized).toJson(QJsonDocument::Compact),
                                                     QCryptographicHash::Sha256);
    if (!batchId.isEmpty()) {
        const auto found = impl_->committedBatches.find(batchId);
        if (found != impl_->committedBatches.end()) {
            if (found->second.fingerprint != fingerprint)
                fail("audit_event", "A committed audit batch was replayed with different contents");
            if (found->second.committed)
                return;
        } else {
            // Allocate replay tracking before touching archive bytes. The final commit is only a
            // boolean store, so allocation failure after a successful flush cannot cause replay.
            impl_->committedBatches.emplace(batchId, Impl::BatchState{fingerprint, false});
            impl_->committedOrder.append(batchId);
        }
    }
    // Save handles as well as offsets: rotation closes the stream's old segment, but the duplicate
    // keeps every touched file available for rollback until all writes and flushes have succeeded.
    std::map<QString, Impl::StreamCheckpoint> streamCheckpoints;
    std::map<QString, Impl::FileCheckpoint> fileCheckpoints;
    const auto initialRows = impl_->rows;
    for (const auto &value : normalized) {
        const auto event = value.toObject();
        const auto key = event.value("sandbox").toString() + '/' + event.value("runId").toString();
        if (streamCheckpoints.contains(key))
            continue;
        Impl::StreamCheckpoint checkpoint;
        const auto found = impl_->streams.find(key);
        if (found != impl_->streams.end()) {
            const auto &stream = found->second;
            checkpoint.existed = true;
            if (stream.file)
                checkpoint.file = Impl::duplicate(stream.file.get());
            checkpoint.filename = stream.filename;
            checkpoint.sequence = stream.sequence;
            checkpoint.segment = stream.segment;
            checkpoint.rows = stream.rows;
            checkpoint.bytes = stream.bytes;
            checkpoint.dirty = stream.dirty;
        }
        streamCheckpoints.emplace(key, std::move(checkpoint));
    }
    impl_->fileCheckpoints = &fileCheckpoints;
    try {
        for (const auto &event : normalized)
            impl_->append(event.toObject());
        flush();
        impl_->fileCheckpoints = nullptr;
    } catch (const std::exception &error) {
        impl_->fileCheckpoints = nullptr;
        ++impl_->failures;
        impl_->lastError = QString::fromUtf8(error.what());
        for (auto &[filename, checkpoint] : fileCheckpoints) {
            Q_UNUSED(filename);
            LARGE_INTEGER offset{};
            offset.QuadPart = checkpoint.bytes;
            if (!SetFilePointerEx(checkpoint.file.get(), offset, nullptr, FILE_BEGIN) ||
                !SetEndOfFile(checkpoint.file.get()) || !FlushFileBuffers(checkpoint.file.get()))
                impl_->rollbackFailed = true;
        }
        for (auto &[key, checkpoint] : streamCheckpoints) {
            const auto found = impl_->streams.find(key);
            if (found == impl_->streams.end())
                continue;
            auto &stream = found->second;
            if (!checkpoint.existed) {
                // Keep an opened new stream at offset zero so retry need not overwrite its file.
                stream.sequence = stream.rows = 0;
                stream.bytes = 0;
                stream.dirty = false;
            } else {
                stream.file = std::move(checkpoint.file);
                stream.filename = checkpoint.filename;
                stream.sequence = checkpoint.sequence;
                stream.segment = checkpoint.segment;
                stream.rows = checkpoint.rows;
                stream.bytes = checkpoint.bytes;
                stream.dirty = checkpoint.dirty;
            }
        }
        impl_->rows = initialRows;
        throw;
    }
    if (!batchId.isEmpty()) {
        impl_->committedBatches.at(batchId).committed = true;
        while (impl_->committedOrder.size() > 256)
            impl_->committedBatches.erase(impl_->committedOrder.takeFirst());
    }
}
void AuditLogSink::flush() {
    for (auto &[key, stream] : impl_->streams) {
        Q_UNUSED(key);
        impl_->flush(stream);
    }
}
void AuditLogSink::closeSandbox(const QString &sandbox) {
    const auto validated = validateId(sandbox);
    // Flush all affected streams before closing any of them. If persistence fails the caller must
    // keep the sandbox in place and report that error, rather than removing unflushed evidence.
    for (auto &[key, stream] : impl_->streams) {
        Q_UNUSED(key);
        if (stream.sandbox == validated)
            impl_->flush(stream);
    }
    for (auto found = impl_->streams.begin(); found != impl_->streams.end();) {
        if (found->second.sandbox == validated)
            found = impl_->streams.erase(found);
        else
            ++found;
    }
}
QString AuditLogSink::path(const QString &sandbox) const {
    return privatePath(impl_->root + "/driverless/sandboxes/" + validateId(sandbox) + "/audit");
}
QJsonObject AuditLogSink::status(const QString &sandbox) const {
    quint64 rows = 0, sources = 0;
    for (const auto &[key, stream] : impl_->streams) {
        Q_UNUSED(key);
        if (sandbox.isEmpty() || stream.sandbox == sandbox) {
            rows += stream.rows;
            ++sources;
        }
    }
    const auto directory = sandbox.isEmpty() ? QString() : path(sandbox);
    return {{"writerId", impl_->writer}, {"archivedEvents", QString::number(rows)},
            {"archiveStreams", qint64(sources)}, {"archiveSegments", QString::number(impl_->segments)},
            {"archiveFailures", QString::number(impl_->failures)}, {"archiveLastError", impl_->lastError},
            {"archiveRollbackFailed", impl_->rollbackFailed},
            {"rawLogDirectory", directory},
            {"rawLogUrl", directory.isEmpty() ? QString() : QUrl::fromLocalFile(directory).toString()},
            {"retention", "Passive audit JSONL segments are retained; the observer never deletes them"}};
}
}

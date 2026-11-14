#pragma once
#include "driverless/common.h"

namespace nb::audit {
inline constexpr auto Contract = "nativebox.audit/1";
inline constexpr qsizetype MaxFrameBytes = 1024 * 1024;
inline constexpr qsizetype MaxEventBytes = 256 * 1024;
inline constexpr qsizetype MaxBatchBytes = 512 * 1024;
inline constexpr int MaxBatchRecords = 512;

struct ProcessIdentity {
    DWORD pid = 0;
    quint64 creationTime = 0;
    QString sid;
    QString logonSession;
    DWORD windowsSessionId = 0;
    QString linkedLogonSession;
    bool linkedTokenVerified = false;
    QString linkedTokenStatus;
    QJsonObject json() const;
};
ProcessIdentity readProcessIdentity(HANDLE process);
bool processMatches(DWORD pid, quint64 creationTime, HANDLE job = nullptr) noexcept;
bool sameLogonOwner(const ProcessIdentity &first, const ProcessIdentity &second) noexcept;
quint64 unsignedText(const QJsonValue &value, const QString &field, bool allowZero = false);
QString validateNonce(const QString &nonce);
QJsonObject validateRegistration(const QJsonObject &request);
QJsonObject validateRequest(const QJsonObject &request);
QJsonObject validateEvent(const QJsonObject &event);
QJsonArray validateBatch(const QJsonArray &events);
QByteArray encodeFrame(const QJsonObject &object);
QJsonObject decodeFrame(const QByteArray &bytes);

// This sink belongs only to the ordinary broker. The elevated observer never receives a storage
// path and never opens a sandbox file. appendBatch flushes each affected file before returning.
class AuditLogSink {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    explicit AuditLogSink(QString storageRoot, qint64 segmentBytes = 8 * 1024 * 1024);
    ~AuditLogSink();
    AuditLogSink(const AuditLogSink &) = delete;
    AuditLogSink &operator=(const AuditLogSink &) = delete;
    void append(const QJsonObject &event);
    void appendBatch(const QJsonArray &events);
    void flush();
    // Call only after observer unregister and durable queue drain, before explicit storage removal.
    void closeSandbox(const QString &sandbox);
    QString path(const QString &sandbox) const;
    QJsonObject status(const QString &sandbox = {}) const;
};
}

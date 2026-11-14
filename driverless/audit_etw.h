#pragma once
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QString>
#include <windows.h>
#include <memory>

namespace nb {
// Passive OS observation. This object never injects a DLL, changes a target, enables an Event Log
// channel, or changes another program's ETW session. Administrative ETW rights may be required.
class AuditEtw {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    explicit AuditEtw(bool systemCalls = true);
    ~AuditEtw();
    AuditEtw(const AuditEtw &) = delete;
    AuditEtw &operator=(const AuditEtw &) = delete;
    QJsonObject start();
    void stop();
    // Register the suspended root before it executes. A query-only duplicate of job is retained;
    // Descendants require creation-time proof and actual membership, or kernel parent-sequence
    // proof together with the verified job's mandatory non-breakaway inheritance policy.
    bool watch(quint32 pid, quint64 expectedCreationTime, const QString &sandbox, const QString &runId,
               HANDLE job = nullptr, QString *error = nullptr);
    void unwatch(quint32 pid, quint64 creationTime);
    void unwatchSession(const QString &sandbox, const QString &runId);
    QJsonArray drain(int maxRecords = 512);
    QJsonObject status();
};
}

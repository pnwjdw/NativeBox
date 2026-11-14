#pragma once
#include "driverless/audit_protocol.h"
#include <QLocalSocket>
#include <exception>
#include <functional>
#include <optional>
#include <type_traits>

namespace nb {
class AuditClient {
    QThread worker_;
    mutable QObject context_;
    QTimer *timer_ = nullptr;
    bool comInitialized_ = false;
    QString root_, endpoint_, nonce_;
    Handle host_;
    std::unique_ptr<audit::AuditLogSink> sink_;
    QJsonObject state_;
    QString error_;
    QString pendingAck_;
    bool connected_ = false;
    QMap<QString, QSet<QString>> registrations_;
    QMap<QString, QMap<QString, audit::ProcessIdentity>> roots_;
    QByteArray healthFingerprint_;
    qint64 lastHealthMs_ = 0;
    QJsonObject call(QJsonObject request);
    void verifyPeer(QLocalSocket &socket);
    void archiveHealth(bool force = false);
    QJsonObject enableImpl(bool elevated);
    QJsonObject disableImpl();
    QJsonObject statusImpl(const QString &sandbox = {}) const;
    void watchImpl(HANDLE process, HANDLE job, const QString &sandbox, const QString &runId);
    void forgetImpl(const QString &sandbox);
    QJsonArray pollImpl(int batches);

    template <class Function>
    auto onWorker(Function &&function) const -> std::invoke_result_t<Function> {
        using Result = std::invoke_result_t<Function>;
        static_assert(!std::is_reference_v<Result>);
        if (QThread::currentThread() == &worker_)
            return std::invoke(std::forward<Function>(function));
        std::exception_ptr error;
        if constexpr (std::is_void_v<Result>) {
            const auto accepted = QMetaObject::invokeMethod(&context_, [&] {
                try { std::invoke(function); }
                catch (...) { error = std::current_exception(); }
            }, Qt::BlockingQueuedConnection);
            if (!accepted) fail("audit_thread", "Cannot dispatch to the audit worker");
            if (error) std::rethrow_exception(error);
        } else {
            std::optional<Result> result;
            const auto accepted = QMetaObject::invokeMethod(&context_, [&] {
                try { result.emplace(std::invoke(function)); }
                catch (...) { error = std::current_exception(); }
            }, Qt::BlockingQueuedConnection);
            if (!accepted) fail("audit_thread", "Cannot dispatch to the audit worker");
            if (error) std::rethrow_exception(error);
            return std::move(*result);
        }
    }

  public:
    explicit AuditClient(QString storageRoot);
    ~AuditClient();
    QJsonObject enable(bool elevated = true);
    QJsonObject disable();
    QJsonObject status(const QString &sandbox = {}) const;
    bool enabled() const;
    bool ready() const;
    void watch(HANDLE process, HANDLE job, const QString &sandbox, const QString &runId);
    void forget(const QString &sandbox);
    QJsonArray poll(int batches = 8);
};
}

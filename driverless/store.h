#pragma once
#include "driverless/profile.h"
#include "driverless/process.h"
#include "driverless/audit_client.h"
#include <map>

namespace nb {
class Store {
    QString root_;
    std::unique_ptr<Database> db_;
    std::map<QString, std::unique_ptr<RuntimeSession>> sessions_;
    std::map<QString, QJsonObject> lastLaunches_;
    std::unique_ptr<AuditClient> audit_;
    struct JournalExport { QString sandbox; QFuture<QJsonObject> future; };
    QMap<QString, JournalExport> exports_;
    QStringList exportOrder_;
    QJsonObject profile(const QString &sandbox);
    void saveProfile(const QString &sandbox, const QJsonObject &profile);
    void event(const QString &sandbox, const QString &action, const QJsonObject &details = {},
               const QString &category = "broker");
    QJsonObject collectTelemetry(const QString &sandbox);
    QJsonObject dispatch(const QJsonObject &request);
    void migrateLegacy();
    bool active(const QString &sandbox) const;

  public:
    explicit Store(QString root);
    ~Store();
    QJsonObject execute(const QJsonObject &request) noexcept;
};
}

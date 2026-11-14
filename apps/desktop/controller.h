#pragma once
#include "driverless/common.h"

class Controller : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList sandboxes READ sandboxes NOTIFY changed)
    Q_PROPERTY(QVariantList events READ events NOTIFY changed)
    Q_PROPERTY(QVariantList snapshots READ snapshots NOTIFY changed)
    Q_PROPERTY(QVariantMap status READ status NOTIFY changed)
    Q_PROPERTY(QVariantMap telemetry READ telemetry NOTIFY changed)
    Q_PROPERTY(QVariantMap eventPage READ eventPage NOTIFY changed)
    Q_PROPERTY(QVariantMap registryAudit READ registryAudit NOTIFY changed)
    Q_PROPERTY(QVariantMap filePage READ filePage NOTIFY changed)
    Q_PROPERTY(QVariantMap fileMetadata READ fileMetadata NOTIFY changed)
    Q_PROPERTY(QVariantMap devices READ devices NOTIFY changed)
    Q_PROPERTY(QString selected READ selected WRITE setSelected NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString message READ message NOTIFY changed)
    Q_PROPERTY(bool failed READ failed NOTIFY changed)
    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY changed)
    Q_PROPERTY(bool dark READ dark WRITE setDark NOTIFY changed)
    Q_PROPERTY(QString buildScope READ buildScope CONSTANT)
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(QString buildIdentity READ buildIdentity CONSTANT)
    QString root_, selected_, message_, language_ = "ru";
    QVariantList sandboxes_, events_, snapshots_;
    QVariantMap status_, registryAudit_, filePage_, fileMetadata_, devices_;
    QVariantMap telemetry_;
    QVariantMap eventPage_;
    QVariantMap eventFilter_;
    bool busy_ = false, failed_ = false, dark_ = true;
    bool systemService_ = false;
    QThreadPool pool_;
    void persist();

  public:
    explicit Controller(QString root, bool systemService = false, QObject *parent = nullptr);
    QVariantList sandboxes() const { return sandboxes_; }
    QVariantList events() const { return events_; }
    QVariantList snapshots() const { return snapshots_; }
    QVariantMap status() const { return status_; }
    QVariantMap telemetry() const { return telemetry_; }
    QVariantMap eventPage() const { return eventPage_; }
    QVariantMap registryAudit() const { return registryAudit_; }
    QVariantMap filePage() const { return filePage_; }
    QVariantMap fileMetadata() const { return fileMetadata_; }
    QVariantMap devices() const { return devices_; }
    QString selected() const { return selected_; }
    bool busy() const { return busy_; }
    QString message() const { return message_; }
    bool failed() const { return failed_; }
    QString language() const { return language_; }
    bool dark() const { return dark_; }
    QString buildScope() const;
    QString buildIdentity() const;
    QString version() const { return QStringLiteral(NB_PRODUCT_VERSION); }
    void setSelected(const QString &value);
    void setLanguage(const QString &value);
    void setDark(bool value);
    Q_INVOKABLE void perform(const QString &operation, const QVariantMap &arguments = {});
    Q_INVOKABLE QVariantMap selectedProfile() const;
    Q_INVOKABLE QString pretty(const QVariant &value) const;
    Q_INVOKABLE QString localPath(const QString &url) const { return QUrl(url).toLocalFile(); }
  signals:
    void changed();
};

#include "apps/desktop/controller.h"
#include "driverless/ipc.h"
#include <QtConcurrent>
#include <QJSValue>

Controller::Controller(QString root, bool systemService, QObject *parent)
    : QObject(parent), root_(std::move(root)), systemService_(systemService) {
    pool_.setMaxThreadCount(1);
    QSettings settings(root_ + "/desktop.ini", QSettings::IniFormat);
    language_ = settings.value("language", "ru").toString();
    dark_ = settings.value("dark", true).toBool();
    perform("refresh");
}
QString Controller::buildScope() const {
    return QStringLiteral("driverless");
}
QString Controller::buildIdentity() const {
    QFile image(QCoreApplication::applicationFilePath());
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!image.open(QIODevice::ReadOnly) || image.size() > 256 * 1024 * 1024 || !hash.addData(&image))
        return QStringLiteral("unavailable");
    return QString::fromLatin1(hash.result().toHex().left(16));
}
void Controller::persist() {
    QSettings settings(root_ + "/desktop.ini", QSettings::IniFormat);
    settings.setValue("language", language_);
    settings.setValue("dark", dark_);
}
void Controller::setSelected(const QString &value) {
    if (selected_ != value) {
        selected_ = value;
        events_.clear();
        eventFilter_.clear();
        snapshots_.clear();
        registryAudit_.clear();
        filePage_.clear();
        fileMetadata_.clear();
        emit changed();
        perform("refresh");
    }
}
void Controller::setLanguage(const QString &value) {
    if (value == "ru" || value == "en") {
        static const QString russian = QStringLiteral("Операция выполнена");
        static const QString english = QStringLiteral("Operation completed");
        const auto &from = value == "ru" ? english : russian;
        if (!failed_ && message_.startsWith(from))
            message_ = (value == "ru" ? russian : english) + message_.mid(from.size());
        language_ = value;
        persist();
        emit changed();
    }
}
void Controller::setDark(bool value) {
    dark_ = value;
    persist();
    emit changed();
}
QVariantMap Controller::selectedProfile() const {
    for (const auto &value : sandboxes_)
        if (value.toMap().value("id").toString() == selected_)
            return value.toMap();
    return {};
}
QString Controller::pretty(const QVariant &value) const {
    return QString::fromUtf8(QJsonDocument::fromVariant(value.metaType() == QMetaType::fromType<QJSValue>()
                                                            ? value.value<QJSValue>().toVariant()
                                                            : value)
                                 .toJson(QJsonDocument::Indented));
}
void Controller::perform(const QString &operation, const QVariantMap &arguments) {
    if (busy_)
        return;
    if (operation == "events.query")
        eventFilter_ = arguments;
    busy_ = true;
    failed_ = false;
    if (operation == "devices")
        devices_.clear();
    if (operation == "file.list") {
        filePage_.clear();
        fileMetadata_.clear();
    } else if (operation == "file.stat")
        fileMetadata_.clear();
    if (operation != "refresh") {
        message_.clear();
        registryAudit_.clear();
    }
    emit changed();
    QString root = root_, selected = selected_;
    auto eventFilter = eventFilter_;
    bool systemService = systemService_;
    auto watcher = new QFutureWatcher<QJsonObject>(this);
    connect(watcher, &QFutureWatcher<QJsonObject>::finished, this,
            [this, watcher, operation, selected, arguments] {
                bool refreshSelection = selected_ != selected;
                auto bundle = watcher->result();
                auto response = bundle.value("response").toObject();
                if (operation == "registry.identity.audit" && selected_ == selected &&
                    response.value("ok").toBool())
                    registryAudit_ = response.toVariantMap();
                if (selected_ == selected && response.value("ok").toBool()) {
                    if (operation == "file.list") {
                        filePage_ = response.toVariantMap();
                        filePage_["path"] =
                            response.value("source").toString(arguments.value("path").toString());
                        filePage_["scope"] =
                            response.value("scope").toString(arguments.value("scope", "host").toString());
                    } else if (operation == "file.stat")
                        fileMetadata_ = response.toVariantMap();
                }
                if (bundle.contains("sandboxes"))
                    sandboxes_ = bundle.value("sandboxes").toArray().toVariantList();
                if (bundle.contains("events"))
                    events_ = bundle.value("events").toArray().toVariantList();
                telemetry_ = bundle.value("telemetry").toObject().toVariantMap();
                eventPage_ = bundle.value("eventPage").toObject().toVariantMap();
                if (bundle.contains("snapshots"))
                    snapshots_ = bundle.value("snapshots").toArray().toVariantList();
                status_ = bundle.value("status").toObject().toVariantMap();
                busy_ = false;
                failed_ = !response.value("ok").toBool();
                if (failed_)
                    message_ = response.value("error").toString();
                else if (operation != "refresh")
                    message_ = language_ == "ru" ? "Операция выполнена" : "Operation completed";
                if (operation == "network.probe" && !failed_)
                    message_ += QString(" · %1 ms").arg(response.value("latencyMs").toInteger());
                if (operation == "events.rawExportFile" && !failed_)
                    message_ = (language_ == "ru"
                        ? QString("Экспортировано строк: %1 · %2 МиБ · Незавершённых строк пропущено: %3")
                        : QString("Exported rows: %1 · %2 MiB · Incomplete rows skipped: %3"))
                        .arg(response.value("rows").toInteger())
                        .arg(double(response.value("bytes").toInteger()) / (1024 * 1024), 0, 'f', 1)
                        .arg(response.value("partialFragments").toInteger());
                if (operation == "devices" && !failed_)
                    devices_ = response.toVariantMap();
                if (selected_.isEmpty() && !sandboxes_.isEmpty()) {
                    selected_ = sandboxes_.first().toMap().value("id").toString();
                    refreshSelection = true;
                }
                if (!selected_.isEmpty()) {
                    bool exists = false;
                    for (const auto &box : sandboxes_)
                        if (box.toMap().value("id").toString() == selected_)
                            exists = true;
                    if (!exists) {
                        refreshSelection = true;
                        selected_.clear();
                        registryAudit_.clear();
                        snapshots_.clear();
                        filePage_.clear();
                        fileMetadata_.clear();
                    }
                }
                if (refreshSelection) {
                    events_.clear();
                    snapshots_.clear();
                    registryAudit_.clear();
                    filePage_.clear();
                    fileMetadata_.clear();
                    watcher->deleteLater();
                    perform("refresh");
                    return;
                }
                emit changed();
                watcher->deleteLater();
            });
    watcher->setFuture(QtConcurrent::run(&pool_, [root, selected, operation, arguments, systemService,
                                                  eventFilter] {
        QJsonObject bundle;
        try {
            auto execute = [&](const QJsonObject &value) {
                if (systemService)
                    nb::fail("unsupported_transport", "Driverless uses a same-user broker");
                return nb::driverlessRequest(root, value);
            };
            auto request = QJsonObject::fromVariantMap(arguments);
            request["op"] = operation;
            if (!request.contains("sandbox"))
                request["sandbox"] = selected;
            QJsonObject response{{"ok", true}};
            if (operation == "profile.importFile") {
                auto profile = nb::parseObject(
                    nb::readFile(QUrl(arguments.value("url").toString()).toLocalFile(), 1024 * 1024));
                response = execute({{"op", "profile.import"},
                                    {"profile", profile.value("profile").isObject() ? profile.value("profile")
                                                                                    : QJsonValue(profile)}});
            } else if (operation == "events.rawExportFile") {
                auto started = execute({{"op", "logs.export.start"}, {"sandbox", selected},
                                        {"destination", QUrl(arguments.value("url").toString()).toLocalFile()}});
                if (!started.value("ok").toBool())
                    nb::fail("export", started.value("error").toString());
                const auto exportId = started.value("exportId").toString();
                for (;;) {
                    auto state = execute({{"op", "logs.export.status"}, {"exportId", exportId}});
                    if (!state.value("ok").toBool()) nb::fail("export", state.value("error").toString());
                    if (state.value("done").toBool()) {
                        response = state.value("result").toObject();
                        break;
                    }
                    QThread::msleep(100);
                }
            } else if (operation == "events.exportFile") {
                auto page = QJsonObject::fromVariantMap(eventFilter);
                page.remove("after");
                page.remove("before");
                page["op"] = "events.export";
                page["sandbox"] = selected;
                page["limit"] = 200;
                bool csvFormat = arguments.value("format").toString() == "csv";
                QJsonArray rows;
                QByteArray csv;
                qsizetype bytes = 0;
                qint64 count = 0, cursor = 0;
                bool more = true;
                while (more) {
                    auto result = execute(page);
                    if (!result.value("ok").toBool())
                        nb::fail("export", result.value("error").toString());
                    auto batch = result.value("json").toArray();
                    count += batch.size();
                    bytes += QJsonDocument(batch).toJson(QJsonDocument::Compact).size();
                    if (count > 50000 || bytes > 64 * 1024 * 1024)
                        nb::fail("export_budget",
                                 "Event export exceeds 50000 records or 64 MiB; narrow the filters");
                    if (csvFormat) {
                        auto part = result.value("csv").toString().toUtf8();
                        if (!csv.isEmpty())
                            part.remove(0, part.indexOf('\n') + 1);
                        csv += part;
                    } else
                        for (const auto &row : batch)
                            rows.append(row);
                    more = result.value("hasMore").toBool();
                    if (more) {
                        auto next = result.value("nextAfter").toInteger();
                        if (batch.isEmpty() || next == cursor)
                            nb::fail("export_cursor", "Event export cursor did not advance");
                        cursor = next;
                        page[page.value("sort").toString() == "descending" ? "before" : "after"] = next;
                    }
                }
                nb::atomicWrite(QUrl(arguments.value("url").toString()).toLocalFile(),
                                csvFormat ? csv : QJsonDocument(rows).toJson());
                response = {{"ok", true},
                            {"exportedEvents", count},
                            {"scope", "bounded event stream; not an atomic live snapshot"}};
            } else if (operation == "profile.exportFile") {
                request["op"] = "profile.export";
                response = execute(request);
                if (response.value("ok").toBool()) {
                    nb::atomicWrite(QUrl(arguments.value("url").toString()).toLocalFile(),
                                    QJsonDocument(response).toJson());
                }
            } else if (operation == "profile.editJson") {
                request["op"] = "profile.edit";
                request["profile"] = nb::parseObject(arguments.value("json").toString().toUtf8());
                response = execute(request);
            } else if (operation == "application.add") {
                auto profile =
                    execute({{"op", "profile.get"}, {"sandbox", selected}}).value("profile").toObject();
                auto applications = profile.value("applications").toArray();
                applications.append(
                    QJsonObject{{"path", QUrl(arguments.value("url").toString()).toLocalFile()},
                                {"arguments", arguments.value("arguments").toString()},
                                {"favorite", true}});
                profile["applications"] = applications;
                response = execute({{"op", "profile.edit"}, {"sandbox", selected}, {"profile", profile}});
            } else if (operation == "events.query") {
                request["op"] = "events";
                response = execute(request);
            } else if (operation != "refresh")
                response = execute(request);
            bundle["response"] = response;
            bundle["sandboxes"] = execute({{"op", "list"}}).value("sandboxes");
            bundle["status"] = execute({{"op", "status"}});
            auto eventRequest = QJsonObject::fromVariantMap(eventFilter);
            eventRequest["op"] = "events";
            if (!eventRequest.contains("limit"))
                eventRequest["limit"] = 200;
            if (!selected.isEmpty())
                eventRequest["sandbox"] = selected;
            auto eventResponse = operation == "events.query" ? response : execute(eventRequest);
            bundle["events"] = eventResponse.value("events");
            bundle["telemetry"] = eventResponse.value("telemetry");
            bundle["eventPage"] = QJsonObject{{"hasMore", eventResponse.value("hasMore")},
                                              {"nextAfter", eventResponse.value("nextAfter")}};
            if (!selected.isEmpty())
                bundle["snapshots"] =
                    execute({{"op", "snapshot.list"}, {"sandbox", selected}}).value("snapshots");
        } catch (const std::exception &error) {
            bundle["response"] = QJsonObject{{"ok", false}, {"error", QString::fromUtf8(error.what())}};
        }
        return bundle;
    }));
}

#include "driverless/store.h"

namespace nb {
QJsonObject Store::collectTelemetry(const QString &sandbox) {
    audit_->poll();
    QStringList profiles;
    if (!sandbox.isEmpty())
        profiles.append(validateId(sandbox));
    else {
        QSqlQuery query(db_->get());
        if (!query.exec("SELECT id FROM profiles ORDER BY id LIMIT 128"))
            fail("database", query.lastError().text());
        while (query.next())
            profiles.append(validateId(query.value(0).toString()));
    }
    int sources = 0, imported = 0, rejected = 0, incomplete = 0, capped = 0, batches = 0;
    bool bounded = false;
    const QRegularExpression filename("^[a-f0-9-]{36}_[0-9]+_[0-9]+(?:_[1-9][0-9]*)?\\.jsonl$");
    const QRegularExpression auditFilename("^[a-f0-9-]{36}_[a-f0-9-]{36}_[0-9]+\\.jsonl$");
    for (const auto &profileId : profiles) {
        auto directory = inside(root_, "driverless/sandboxes/" + profileId + "/telemetry");
        rejectReparse(directory);
        auto files = QDir(directory).entryInfoList({"*.jsonl"}, QDir::Files, QDir::Time | QDir::Reversed);
        auto passiveDirectory = inside(root_, "driverless/sandboxes/" + profileId + "/audit");
        rejectReparse(passiveDirectory);
        files.append(QDir(passiveDirectory).entryInfoList({"*.jsonl"}, QDir::Files, QDir::Time | QDir::Reversed));
        // Raw logs are the persistent archive; the database is a bounded search cache. Never remove
        // stopped processes' files here: they may not even have been imported yet.
        for (const auto &info : files) {
            const bool passive = info.absolutePath() == passiveDirectory;
            if (!(passive ? auditFilename : filename).match(info.fileName()).hasMatch()) {
                ++rejected;
                continue;
            }
            ++sources;
            rejectReparse(info.absoluteFilePath());
            auto key = profileId + '/' + (passive ? QString("audit/") : QString()) + info.fileName();
            QSqlQuery offsetQuery(db_->get());
            offsetQuery.prepare("SELECT offset FROM runtime_offsets WHERE source=?");
            offsetQuery.addBindValue(key);
            sql(offsetQuery);
            qint64 offset = offsetQuery.next() ? offsetQuery.value(0).toLongLong() : 0;
            if (offset > info.size()) {
                ++rejected;
                continue;
            }
            if (offset == info.size())
                continue;
            if (batches >= 32) {
                bounded = true;
                continue;
            }
            ++batches;
            QFile file(info.absoluteFilePath());
            if (!file.open(QIODevice::ReadOnly) || !file.seek(offset)) {
                ++incomplete;
                continue;
            }
            auto bytes = file.read(1024 * 1024);
            if (file.error() != QFileDevice::NoError) {
                ++incomplete;
                bounded = true;
                continue;
            }
            int end = int(bytes.lastIndexOf('\n')) + 1;
            if (end < bytes.size()) {
                ++incomplete;
                bounded = true;
            }
            if (!end) {
                // An oversized corrupt record must not pin the import cursor forever. Keep its raw
                // bytes on disk and advance one bounded chunk; the next newline restores framing.
                if (bytes.size() == 1024 * 1024)
                    end = int(bytes.size());
                else
                    continue;
            }
            bounded = bounded || file.pos() < info.size();
            if (!db_->get().transaction())
                fail("database", "Cannot begin runtime event import");
            auto rollback = qScopeGuard([&] { db_->get().rollback(); });
            for (const auto &line : bytes.first(end).split('\n')) {
                if (line.isEmpty())
                    continue;
                try {
                    if (line.size() > 256 * 1024)
                        fail("telemetry", "Oversized runtime event");
                    auto record = parseObject(line);
                    if (passive) {
                        record = audit::validateEvent(record);
                        const auto expected = record.value("runId").toString() + '_' +
                                              validateId(record.value("writerId").toString()) + '_' +
                                              QString::number(record.value("segment").toInteger(-1)) + ".jsonl";
                        if (record.value("sandbox").toString() != profileId || expected != info.fileName())
                            fail("telemetry", "Passive event archive identity mismatch");
                        event(profileId, record.value("operation").toString(), record,
                              record.value("category").toString());
                        ++imported;
                        continue;
                    }
                    auto category = record.value("category").toString();
                    auto run = validateId(record.value("runId").toString());
                    auto expectedName = run + '_' + QString::number(record.value("pid").toInteger()) + '_' +
                                        record.value("creationTime").toString();
                    auto segment = record.value("segment").toInteger(0);
                    if (segment > 0)
                        expectedName += '_' + QString::number(segment);
                    expectedName += ".jsonl";
                    if (record.value("schema").toInt() != 1 ||
                        record.value("sandbox").toString() != profileId ||
                        record.value("source").toString() != "runtime_win32_hooks" ||
                        expectedName != info.fileName() || segment < 0 ||
                        !QStringList{"file", "registry", "process", "network", "telemetry"}.contains(
                            category) ||
                        record.value("operation").toString().size() > 64 ||
                        record.value("path").toString().size() > 32760)
                        fail("telemetry", "Runtime event identity or shape mismatch");
                    if (category == "telemetry")
                        ++capped;
                    bool validTime = false;
                    auto fileTime = record.value("fileTime").toString().toLongLong(&validTime);
                    if (!validTime || fileTime < 116444736000000000LL)
                        fail("telemetry", "Invalid runtime event timestamp");
                    record["timeUtc"] = QDateTime::fromMSecsSinceEpoch(
                                            (fileTime - 116444736000000000LL) / 10000, QTimeZone::UTC)
                                            .toString(Qt::ISODateWithMs);
                    event(profileId, record.value("operation").toString(), record, category);
                    ++imported;
                } catch (const Error &error) {
                    if (error.code == "database")
                        throw;
                    ++rejected;
                }
            }
            QSqlQuery update(db_->get());
            update.prepare("INSERT INTO runtime_offsets VALUES(?,?) ON CONFLICT(source) DO UPDATE SET "
                           "offset=excluded.offset");
            update.addBindValue(key);
            update.addBindValue(offset + end);
            sql(update);
            if (!db_->get().commit())
                fail("database", "Cannot commit runtime event import");
            rollback.dismiss();
        }
    }
    QSqlQuery limits(db_->get());
    limits.prepare("SELECT COUNT(*) FROM events WHERE category='telemetry' AND action='event_limit_reached' "
                   "AND (?='' OR sandbox=?)");
    auto selected = sandbox.isEmpty() ? QStringLiteral("") : sandbox;
    limits.addBindValue(selected);
    limits.addBindValue(selected);
    sql(limits);
    if (limits.next())
        capped = limits.value(0).toInt();
    QSqlQuery observed(db_->get());
    observed.prepare("SELECT category,COUNT(*) FROM events WHERE category IN ('wmi','network','syscall') "
                     "AND details LIKE '%\"source\":\"windows_etw\"%' AND (?='' OR sandbox=?) GROUP BY category");
    observed.addBindValue(selected);
    observed.addBindValue(selected);
    sql(observed);
    QJsonObject observedCounts;
    while (observed.next()) observedCounts[observed.value(0).toString()] = observed.value(1).toLongLong();
    auto rawLogDirectory = sandbox.isEmpty()
                               ? QString()
                               : inside(root_, "driverless/sandboxes/" + validateId(sandbox) + "/telemetry");
    return {
        {"source", "runtime_win32_hooks"},
        {"sources", sources},
        {"imported", imported},
        {"rejected", rejected},
        {"incompleteChunks", incomplete},
        {"limitMarkers", capped},
        {"rotatedSources", 0},
        {"moreDataPending", bounded},
        {"completeAudit", false},
        {"status", sources ? "observed_selected_calls" : "no_sources_observed"},
        {"retention", "Raw JSONL segments retained until the sandbox is removed; database search cache: 50000 events"},
        {"rawLogsRetained", true},
        {"rawLogDirectory", rawLogDirectory},
        {"rawLogUrl", rawLogDirectory.isEmpty() ? QString() : QUrl::fromLocalFile(rawLogDirectory).toString()},
        {"wmiObserved", observedCounts.value("wmi").toInteger() > 0},
        {"directNetworkObserved", observedCounts.value("network").toInteger() > 0},
        {"nativeSyscallsObserved", observedCounts.value("syscall").toInteger() > 0},
        {"observedSystemEventCounts", observedCounts},
        {"systemAudit", audit_->status(sandbox)},
        {"auditLogUrl", sandbox.isEmpty() ? QString() : QUrl::fromLocalFile(
            inside(root_, "driverless/sandboxes/" + validateId(sandbox) + "/audit")).toString()},
        {"limitations",
         "Win32 runtime events plus passive Windows ETW when the system observer is active. "
         "See systemAudit for per-provider readiness, lost events and attribution limits. "
         "Asynchronous results may be pending; telemetry failures may omit events. "
         "The target can alter its own logs; this is not a tamper-resistant audit."}};
}
}

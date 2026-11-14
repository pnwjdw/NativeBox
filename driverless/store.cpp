#include "driverless/store.h"
#include "driverless/snapshot.h"
#include "driverless/redirected.h"
#include "driverless/credentials.h"
#include "driverless/proxy.h"
#include "driverless/audit_export.h"
#include <QtConcurrent>

namespace nb {
Store::Store(QString root) : root_(privatePath(QFileInfo(root).absoluteFilePath())) {
    rejectReparse(root_);
    if (!QDir().mkpath(root_ + "/driverless/sandboxes"))
        fail("storage", "Cannot create driverless storage");
    db_ = std::make_unique<Database>(root_ + "/driverless/nativebox.sqlite");
    QSqlQuery version(db_->get());
    if (!version.exec("PRAGMA user_version") || !version.next() || version.value(0).toInt() > 3)
        fail("schema", "Unsupported driverless database schema");
    for (auto statement :
         {"CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY, json TEXT NOT NULL)",
          "CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
          "time TEXT NOT NULL, sandbox TEXT, category TEXT, action TEXT, details TEXT)",
          "CREATE TABLE IF NOT EXISTS legacy_sources(id TEXT PRIMARY KEY, raw BLOB NOT "
          "NULL, sha256 TEXT NOT NULL)",
          "CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
          "CREATE TABLE IF NOT EXISTS runtime_offsets(source TEXT PRIMARY KEY,offset INTEGER NOT NULL)",
          "PRAGMA user_version=3"}) {
        QSqlQuery query(db_->get());
        if (!query.exec(statement))
            fail("database", query.lastError().text());
    }
    migrateLegacy();
    audit_ = std::make_unique<AuditClient>(root_);
}
Store::~Store() {
    // Keep the process/job handles and observer alive through target shutdown so native exit-time
    // activity reaches the archive before the observer's producers and consumer are stopped.
    for (const auto &[sandbox, session] : sessions_) {
        Q_UNUSED(sandbox);
        try { if (session->active()) session->stop(); } catch (...) {}
    }
    QElapsedTimer deadline;
    deadline.start();
    while (deadline.elapsed() < 5000) {
        bool any = false;
        for (const auto &[sandbox, session] : sessions_) {
            Q_UNUSED(sandbox);
            try { any = any || session->active(); } catch (...) {}
        }
        if (!any) break;
        QThread::msleep(10);
    }
    try { if (audit_) audit_->disable(); } catch (...) {}
    for (auto &job : exports_) job.future.waitForFinished();
}
void Store::migrateLegacy() {
    QSqlQuery marker(db_->get());
    if (!marker.exec("SELECT value FROM metadata WHERE key='legacy_import'"))
        fail("database", marker.lastError().text());
    if (marker.next())
        return;
    auto path = root_ + "/nativebox.sqlite";
    if (!QFileInfo::exists(path))
        return;
    Database source(path, true);
    QSqlQuery version(source.get());
    if (!version.exec("PRAGMA user_version") || !version.next() || version.value(0).toInt() != 1)
        fail("legacy_schema", "Legacy database is preserved; its schema requires review");
    QSqlQuery rows(source.get());
    if (!rows.exec("SELECT id,json FROM profiles"))
        fail("legacy_schema", "Legacy profiles cannot be read; original database is unchanged");
    if (!db_->get().transaction())
        fail("database", "Cannot begin migration transaction");
    auto rollback = qScopeGuard([&] { db_->get().rollback(); });
    while (rows.next()) {
        auto sandbox = validateId(rows.value(0).toString());
        auto bytes = rows.value(1).toByteArray();
        auto data = parseObject(bytes);
        data["id"] = sandbox;
        data["backend"] = "legacy_kernel";
        data["executionMode"] = "legacy_read_only";
        data["readOnly"] = true;
        data["legacySource"] =
            "Original data and snapshots are preserved without treating native mounts as directories";
        QSqlQuery insert(db_->get());
        insert.prepare("INSERT OR IGNORE INTO profiles VALUES(?,?)");
        insert.addBindValue(sandbox);
        insert.addBindValue(QString::fromUtf8(QJsonDocument(data).toJson(QJsonDocument::Compact)));
        sql(insert);
        insert.prepare("INSERT OR IGNORE INTO legacy_sources VALUES(?,?,?)");
        insert.addBindValue(sandbox);
        insert.addBindValue(bytes);
        insert.addBindValue(
            QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()));
        sql(insert);
    }
    QSqlQuery done(db_->get());
    if (!done.exec("INSERT INTO metadata VALUES('legacy_import','read_only_reference_v1')") ||
        !db_->get().commit())
        fail("migration", "Legacy import transaction failed");
    rollback.dismiss();
}
QJsonObject Store::profile(const QString &sandbox) {
    QSqlQuery query(db_->get());
    query.prepare("SELECT json FROM profiles WHERE id=?");
    query.addBindValue(validateId(sandbox));
    sql(query);
    if (!query.next())
        fail("not_found", "Profile does not exist");
    return parseObject(query.value(0).toByteArray());
}
void Store::saveProfile(const QString &sandbox, const QJsonObject &data) {
    QSqlQuery query(db_->get());
    query.prepare("INSERT INTO profiles VALUES(?,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json");
    query.addBindValue(validateId(sandbox));
    query.addBindValue(QString::fromUtf8(QJsonDocument(data).toJson(QJsonDocument::Compact)));
    sql(query);
}
void Store::event(const QString &sandbox, const QString &action, const QJsonObject &details,
                  const QString &category) {
    QSqlQuery query(db_->get());
    query.prepare("INSERT INTO events(time,sandbox,category,action,details) VALUES(?,?,?,?,?)");
    query.addBindValue(now());
    query.addBindValue(sandbox);
    query.addBindValue(category);
    query.addBindValue(action);
    query.addBindValue(QString::fromUtf8(QJsonDocument(details).toJson(QJsonDocument::Compact)));
    sql(query);
    if (!query.exec(
            "DELETE FROM events WHERE sequence < (SELECT COALESCE(MAX(sequence),0)-50000 FROM events)"))
        fail("database", query.lastError().text());
}
bool Store::active(const QString &sandbox) const {
    auto found = sessions_.find(sandbox);
    return found != sessions_.end() && found->second->active();
}
QJsonObject Store::dispatch(const QJsonObject &request) {
    auto op = request.value("op").toString();
    if (op == "audit.enable")
        return {{"audit", audit_->enable(request.value("elevated").toBool(true))}};
    if (op == "audit.disable")
        return {{"audit", audit_->disable()}};
    if (op == "audit.poll") {
        const auto records = audit_->poll(32);
        return {{"audit", audit_->status()}, {"persistedEvents", records.size()}};
    }
    if (op == "audit.status")
        return {{"audit", audit_->status()}};
    if (op == "logs.export.status") {
        auto found = exports_.find(validateId(request.value("exportId").toString()));
        if (found == exports_.end()) fail("export_missing", "Journal export job is unavailable");
        const bool done = found->future.isFinished();
        auto result = done ? found->future.result() : QJsonObject();
        // The archive itself is unlimited. Bound only the optional per-file receipt details so
        // thousands of rotated segments cannot overflow the broker's response frame.
        const auto files = result.value("files").toArray();
        if (files.size() > 128) {
            QJsonArray listed;
            for (qsizetype index = 0; index < 128; ++index) listed.append(files[index]);
            result["files"] = listed;
            result["fileDetailsOmitted"] = qint64(files.size() - listed.size());
        }
        return {{"done", done},
                {"result", result}};
    }
    if (op == "status") {
        int running = 0;
        int exporting = 0;
        for (const auto &job : exports_) exporting += !job.future.isFinished();
        for (const auto &[sandbox, session] : sessions_)
            running += int(session->activeCount());
        return {{"root", root_},
                {"version", NB_PRODUCT_VERSION},
                {"backend", "driverless"},
                {"contract", "nativebox.driverless/2"},
                {"activeProcesses", running},
                {"activeExports", exporting},
                {"runtimeAvailable", inspectRuntimeBundle().available()},
                {"systemAudit", audit_->status()},
                {"releaseReady", false},
                {"networkConfinementLevel", "NOT_SUPPORTED"},
                {"kernelRequirements", "RETIRED_REQUIREMENT"}};
    }
    if (op == "list") {
        QJsonArray profiles;
        QSqlQuery query(db_->get());
        if (!query.exec("SELECT id,json FROM profiles ORDER BY id"))
            fail("database", query.lastError().text());
        while (query.next()) {
            auto data = parseObject(query.value(1).toByteArray());
            auto sandbox = validateId(query.value(0).toString());
            data["id"] = sandbox;
            data["readiness"] =
                runtimeReadiness(data, inside(root_, "driverless/sandboxes/" + sandbox + "/data"), sandbox);
            data["running"] = active(sandbox);
            data["canRestart"] = lastLaunches_.contains(sandbox);
            profiles.append(data);
        }
        return {{"sandboxes", profiles}};
    }
    if (op == "create" || op == "profile.import") {
        auto data = validateDriverlessProfile(request.value("profile").toObject());
        auto sandbox = id();
        data.remove("id");
        auto path = inside(root_, "driverless/sandboxes/" + sandbox + "/data");
        if (!QDir().mkpath(path))
            fail("storage", "Cannot create profile data directory");
        saveProfile(sandbox, data);
        event(sandbox, op);
        return {{"sandbox", sandbox}, {"profile", data}};
    }
    if (op == "events" || op == "events.export") {
        int limit = qBound(1, request.value("limit").toInt(500), 5000);
        auto sandbox = request.value("sandbox").toString(QStringLiteral(""));
        if (!sandbox.isEmpty())
            profile(sandbox);
        auto telemetry = collectTelemetry(sandbox);
        auto search = request.value("search").toString(QStringLiteral("")).left(256);
        auto category = request.value("category").toString(QStringLiteral("")).left(32);
        if (search.isEmpty())
            search = QStringLiteral("");
        if (category.isEmpty())
            category = QStringLiteral("");
        bool descending = request.value("sort").toString() == "descending";
        QSqlQuery query(db_->get());
        query.prepare("SELECT sequence,time,sandbox,category,action,details FROM events WHERE (?='' OR "
                      "sandbox=?) AND sequence>? AND (?=0 OR sequence<?) AND (?='' OR category=?) "
                      "AND (?='' OR action LIKE ? OR details LIKE ?) ORDER BY sequence " +
                      QString(descending ? "DESC" : "ASC") + " LIMIT ?");
        query.addBindValue(sandbox);
        query.addBindValue(sandbox);
        query.addBindValue(request.value("after").toInteger(0));
        auto before = request.value("before").toInteger(0);
        query.addBindValue(before);
        query.addBindValue(before);
        query.addBindValue(category);
        query.addBindValue(category);
        query.addBindValue(search);
        query.addBindValue('%' + search + '%');
        query.addBindValue('%' + search + '%');
        query.addBindValue(limit);
        sql(query);
        QJsonArray rows;
        qsizetype rowBytes = 0;
        bool byteLimit = false;
        QString csv = "sequence,time,sandbox,category,action,details\r\n";
        while (query.next()) {
            QJsonObject row{{"sequence", query.value(0).toLongLong()},
                            {"time", query.value(1).toString()},
                            {"sandbox", query.value(2).toString()},
                            {"category", query.value(3).toString()},
                            {"action", query.value(4).toString()},
                            {"details", parseObject(query.value(5).toByteArray())}};
            auto size = QJsonDocument(row).toJson(QJsonDocument::Compact).size();
            if (!rows.isEmpty() && rowBytes + size > 128 * 1024) {
                byteLimit = true;
                break;
            }
            rowBytes += size;
            rows.append(row);
            QStringList fields;
            for (int i = 0; i < 6; ++i) {
                auto value = query.value(i).toString();
                value.replace('"', "\"\"");
                fields.append('"' + value + '"');
            }
            csv += fields.join(',') + "\r\n";
        }
        return {
            {"events", rows},
            {"json", rows},
            {"csv", csv},
            {"telemetry", telemetry},
            {"nextAfter", rows.isEmpty() ? request.value("after") : rows.last().toObject().value("sequence")},
            {"hasMore", byteLimit || rows.size() == limit},
            {"scope", "broker and selected runtime Win32 hooks; bounded, incomplete observation; target can "
                      "bypass user-mode hooks"}};
    }
    auto sandbox = request.value("sandbox").toString();
    auto data = profile(sandbox);
    auto base = inside(root_, "driverless/sandboxes/" + sandbox);
    auto dataPath = inside(base, "data");
    if (op == "logs.export.start") {
        int pending = 0;
        for (const auto &job : exports_) pending += !job.future.isFinished();
        if (pending >= 2) fail("export_busy", "Two journal exports are already running");
        while (exportOrder_.size() >= 32) {
            const auto old = exportOrder_.first();
            if (!exports_.value(old).future.isFinished()) fail("export_busy", "Journal export history is full");
            exports_.remove(old);
            exportOrder_.removeFirst();
        }
        audit_->poll(32);
        const auto exportId = id();
        const auto destination = request.value("destination").toString();
        auto future = QtConcurrent::run([root = root_, sandbox, destination] {
            try {
                auto result = exportJournal(root, sandbox, destination);
                result["ok"] = true;
                return result;
            } catch (const Error &error) {
                return QJsonObject{{"ok", false}, {"code", error.code}, {"error", QString::fromUtf8(error.what())}};
            } catch (const std::exception &error) {
                return QJsonObject{{"ok", false}, {"code", "export_failed"}, {"error", QString::fromUtf8(error.what())}};
            }
        });
        exports_.insert(exportId, JournalExport{sandbox, std::move(future)});
        exportOrder_.append(exportId);
        return {{"exportId", exportId}};
    }
    bool legacy = data.value("backend").toString() != "driverless";
    if (op == "profile.get")
        return {{"profile", data}};
    if (op == "readiness")
        return runtimeReadiness(data, dataPath, sandbox);
    if (op == "profile.export") {
        if (legacy) {
            QSqlQuery original(db_->get());
            original.prepare("SELECT raw,sha256 FROM legacy_sources WHERE id=?");
            original.addBindValue(sandbox);
            sql(original);
            if (!original.next())
                fail("legacy_source", "Original profile bytes are unavailable");
            return {{"profile", parseObject(original.value(0).toByteArray())},
                    {"originalBytesBase64", QString::fromLatin1(original.value(0).toByteArray().toBase64())},
                    {"sha256", original.value(1).toString()},
                    {"readOnly", true},
                    {"reason", data.value("legacySource")}};
        }
        return {{"profile", data}};
    }
    if (op == "snapshot.list") {
        QJsonArray result;
        if (!legacy) {
            QDir parent(inside(base, "snapshots"));
            for (const auto &entry : parent.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
                if (entry.endsWith(".pending"))
                    continue;
                validateId(entry);
                auto manifest = verifyPrivateSnapshot(inside(parent.absolutePath(), entry));
                result.append(QJsonObject{{"id", entry}, {"created", manifest.value("created")}});
            }
        }
        return {{"snapshots", result},
                {"scope", legacy ? "legacy snapshots preserved; native mount conversion unavailable"
                                 : "private data only"}};
    }
    if (legacy)
        fail("legacy_read_only",
             "Legacy native data is preserved read-only; export it before creating a new driverless profile");
    if (op == "credential.status")
        return {{"present", hasProxyCredential(sandbox)}, {"storage", "Windows Credential Manager"}};
    if (op == "network.probe") {
        auto result = probeProxy(data, sandbox, request);
        event(sandbox, op, result);
        return result;
    }
    if (op == "credential.set" || op == "credential.clear") {
        if (active(sandbox))
            fail("running", "Stop the profile before changing route credentials");
        if (op == "credential.set")
            saveProxyCredential(sandbox, request.value("username").toString(),
                                request.value("password").toString());
        else
            clearProxyCredential(sandbox);
        event(sandbox, op);
        return {{"present", op == "credential.set"}, {"storage", "Windows Credential Manager"}};
    }
    if (!active(sandbox))
        recoverPrivateRestore(base);
    if (op == "processes") {
        QJsonArray rows;
        auto found = sessions_.find(sandbox);
        if (found != sessions_.end())
            rows.append(found->second->status());
        return {{"processes", rows}};
    }
    if (op == "restart") {
        auto previous = lastLaunches_.find(sandbox);
        if (previous == lastLaunches_.end())
            fail("restart_unavailable", "Launch an application in this broker session before restarting it");
        if (active(sandbox)) {
            sessions_.at(sandbox)->stop();
            QElapsedTimer timer;
            timer.start();
            while (active(sandbox) && timer.elapsed() < 5000)
                QThread::msleep(10);
            if (active(sandbox))
                fail("stop_timeout", "The owned application tree has not stopped");
        }
        auto launch = previous->second;
        for (const auto &field : {"executable", "arguments", "directory"})
            if (request.contains(field))
                launch[field] = request.value(field);
        launch["op"] = "launch";
        launch["sandbox"] = sandbox;
        event(sandbox, "restart");
        return dispatch(launch);
    }
    if (op == "stop") {
        auto found = sessions_.find(sandbox);
        if (found != sessions_.end())
            found->second->stop();
        event(sandbox, "stop");
        return {};
    }
    if (op == "launch") {
        const bool auditRequired = request.value("auditRequired").toBool() ||
                                   data.value("audit").toObject().value("required").toBool();
        if (auditRequired && !audit_->ready()) audit_->enable();
        if (auditRequired && !audit_->ready())
            fail("audit_required", "Windows system audit is unavailable; inspect the observer's provider and privilege status");
        if (active(sandbox))
            fail("already_running", "This profile already has an active root or child process");
        auto ready = runtimeReadiness(data, dataPath, sandbox);
        if (!ready.value("launchReady").toBool())
            fail(ready.value("reason").toString(), "Launch refused: " + ready.value("reason").toString());
        if (data.value("executionMode").toString() == "usermode_redirected") {
            auto executable = privatePath(request.value("executable").toString());
            auto native = QDir::toNativeSeparators(executable).toStdWString();
            Handle pin(CreateFileW(native.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr));
            wincheck(bool(pin), "Pin explicitly selected redirected target");
            QStringList arguments;
            auto requested = request.value("arguments");
            if (requested.isString())
                arguments = parseArguments(requested.toString());
            else if (requested.isArray())
                for (const auto &value : requested.toArray()) {
                    if (!value.isString() || value.toString().contains(QChar(0)))
                        fail("argument", "Redirected launch arguments must be strings without NUL");
                    arguments.append(value.toString());
                }
            else if (!requested.isUndefined() && !requested.isNull())
                fail("argument", "Arguments must be an array or a Windows command-line string");
            auto directory = request.value("directory").toString(QFileInfo(executable).absolutePath());
            if (directory.isEmpty())
                directory = QFileInfo(executable).absolutePath();
            directory = privatePath(directory);
            if (!QFileInfo(directory).isDir())
                fail("directory", "Working directory is unavailable");
            auto bundle = inspectRuntimeBundle();
            auto configuration = prepareRedirected(data, sandbox, dataPath, bundle);
            sessions_[sandbox] = std::make_unique<RuntimeSession>(
                executable, arguments, directory, configuration.get(), bundle.library64, bundle.sha64,
                [this, sandbox, auditRequired, run = QString::fromWCharArray(configuration->runId)](HANDLE process, HANDLE job) {
                    audit_->watch(process, job, sandbox, run);
                    if (auditRequired && !audit_->ready())
                        fail("audit_required", "System observer lost a requested source before target execution");
                });
            auto state = sessions_[sandbox]->status();
            state["executionMode"] = "usermode_redirected";
            state["runtimeVersion"] = "nativebox.runtime/1";
            state["dataDirectory"] = dataPath;
            state["proxyRequested"] = configuration->managedProxy != 0;
            state["compatibilityValidated"] = false;
            event(sandbox, "launch", state);
            QJsonObject previous;
            for (const auto &field : {"executable", "arguments", "directory"})
                if (request.contains(field))
                    previous[field] = request.value(field);
            lastLaunches_[sandbox] = previous;
            return state;
        }
        auto adapter = data.value("adapter").toObject();
        auto executable = adapter.value("executable").toString();
        auto requested = request.value("executable").toString(executable);
        if (privatePath(requested).compare(executable, Qt::CaseInsensitive) != 0)
            fail("adapter_target", "Executable differs from the explicitly configured adapter");
        if ((request.value("arguments").isArray() && !request.value("arguments").toArray().isEmpty()) ||
            (request.value("arguments").isString() && !request.value("arguments").toString().isEmpty()))
            fail("adapter_arguments", "Configure APP_PROFILE arguments in the adapter; launch cannot "
                                      "override data-directory arguments");
        auto nativeExecutable = QDir::toNativeSeparators(executable).toStdWString();
        Handle executablePin(CreateFileW(nativeExecutable.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        wincheck(bool(executablePin), "Pin adapter executable against concurrent replacement");
        if (digest(executable) != adapter.value("sha256").toString())
            fail("adapter_hash", "Executable bytes differ from the configured adapter");
        QStringList arguments;
        for (const auto &value : adapter.value("arguments").toArray()) {
            auto text = value.toString();
            text.replace("{dataDir}", QDir::toNativeSeparators(dataPath));
            arguments.append(text);
        }
        auto directory = request.value("directory").toString();
        if (directory.isEmpty())
            directory = QFileInfo(executable).absolutePath();
        if (!QFileInfo(directory).isDir())
            fail("directory", "Working directory is not available");
        sessions_[sandbox] = std::make_unique<RuntimeSession>(
            executable, arguments, directory, nullptr, QString(), QString(),
            [this, sandbox, auditRequired, run = id()](HANDLE process, HANDLE job) {
                audit_->watch(process, job, sandbox, run);
                if (auditRequired && !audit_->ready())
                    fail("audit_required", "System observer lost a requested source before target execution");
            });
        auto state = sessions_[sandbox]->status();
        state["executionMode"] = "app_profile";
        state["runtimeAttached"] = false;
        state["dataDirectory"] = dataPath;
        event(sandbox, "launch", state);
        lastLaunches_[sandbox] = {{"directory", directory}};
        return state;
    }
    if (op == "profile.edit") {
        if (active(sandbox))
            fail("running", "Stop the profile before changing execution configuration");
        auto updated = validateDriverlessProfile(request.value("profile").toObject());
        saveProfile(sandbox, updated);
        event(sandbox, op);
        return {{"profile", updated}};
    }
    if (op == "clone") {
        if (active(sandbox))
            fail("running", "Stop the source profile before cloning");
        auto copyId = id();
        auto copyBase = inside(root_, "driverless/sandboxes/" + copyId);
        if (!QDir().mkpath(copyBase))
            fail("clone", "Cannot create cloned profile storage");
        copyPrivateTree(dataPath, inside(copyBase, "data"),
                        qint64(data.value("quotaMiB").toInt(1024)) * 1024 * 1024);
        auto copied = data;
        copied["name"] = data.value("name").toString().left(90) + " (copy)";
        saveProfile(copyId, validateDriverlessProfile(copied));
        event(copyId, "clone");
        return {{"sandbox", copyId}};
    }
    if (op == "snapshot.create" || op == "snapshot.restore" || op == "snapshot.verify" ||
        op == "snapshot.delete") {
        if (active(sandbox))
            fail("running", "Stop all profile processes before snapshot operations");
        auto quota = qint64(data.value("quotaMiB").toInt(1024)) * 1024 * 1024;
        if (op == "snapshot.create") {
            auto manifest = createPrivateSnapshot(base, quota);
            event(sandbox, op, {{"snapshot", manifest.value("id")}});
            return {{"snapshot", manifest.value("id")}};
        }
        auto snapshotId = validateId(request.value("snapshot").toString());
        auto snapshot = inside(base, "snapshots/" + snapshotId);
        if (op == "snapshot.verify")
            return {{"manifest", verifyPrivateSnapshot(snapshot)}};
        if (op == "snapshot.restore")
            restorePrivateSnapshot(base, snapshotId, quota);
        else {
            verifyPrivateSnapshot(snapshot);
            if (!QDir(snapshot).removeRecursively())
                fail("snapshot_delete", "Cannot delete verified private snapshot");
        }
        event(sandbox, op, {{"snapshot", snapshotId}});
        return {};
    }
    if (op == "delete" || op == "reset") {
        for (const auto &job : exports_)
            if (job.sandbox == sandbox && !job.future.isFinished())
                fail("export_running", "Wait for this sandbox's journal export before removing application data");
        if (active(sandbox))
            fail("running", "Stop the profile before deleting private data");
        // Reset preserves audit history, including late buffered events of the stopped run. Keep
        // that run's identity until the observer drains it; explicit deletion retires its history.
        if (op == "delete" && audit_->enabled()) audit_->forget(sandbox);
        QDirIterator check(base, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
                           QDirIterator::Subdirectories);
        while (check.hasNext())
            rejectReparse(check.next());
        if (op == "reset") {
            // Reset application state without erasing the evidence needed to diagnose that state.
            const auto children = QDir(base).entryInfoList(
                QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
            for (const auto &child : children) {
                if ((child.fileName() == "telemetry" || child.fileName() == "audit") && child.isDir())
                    continue;
                const bool removed = child.isDir() ? QDir(child.absoluteFilePath()).removeRecursively()
                                                   : QFile::remove(child.absoluteFilePath());
                if (!removed)
                    fail("storage", "Cannot reset private profile data");
            }
            if (!QDir().mkpath(dataPath))
                fail("storage", "Cannot recreate private data");
        } else {
            if (!QDir(base).removeRecursively())
                fail("storage", "Cannot remove private profile data");
            QSqlQuery query(db_->get());
            query.prepare("DELETE FROM profiles WHERE id=?");
            query.addBindValue(sandbox);
            sql(query);
            sessions_.erase(sandbox);
            lastLaunches_.erase(sandbox);
            clearProxyCredential(sandbox);
        }
        event(sandbox, op);
        return {};
    }
    if (op == "file.list" || op == "file.stat") {
        auto relative = request.value("path").toString();
        if (QDir::isAbsolutePath(relative))
            fail("inspection_scope", "Inspect private data using a relative path");
        auto path = relative.isEmpty() ? dataPath : inside(dataPath, relative);
        if (op == "file.stat") {
            QFileInfo info(path);
            return {
                {"path", relative}, {"physicalPath", path}, {"size", info.size()}, {"exists", info.exists()}};
        }
        auto entries = QDir(path).entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden,
                                                QDir::Name | QDir::DirsFirst);
        int offset = qMax(0, request.value("offset").toInt());
        int limit = qBound(1, request.value("limit").toInt(128), 500);
        QJsonArray result;
        for (int i = offset; i < qMin(offset + limit, int(entries.size())); ++i) {
            rejectReparse(entries[i].absoluteFilePath());
            result.append(
                QJsonObject{{"name", entries[i].fileName()},
                            {"directory", entries[i].isDir()},
                            {"size", entries[i].size()},
                            {"path", QDir(dataPath).relativeFilePath(entries[i].absoluteFilePath())}});
        }
        return {{"entries", result},
                {"total", entries.size()},
                {"hasMore", offset + limit < entries.size()},
                {"nextOffset", offset + limit},
                {"source", relative},
                {"scope", "runtime"},
                {"physicalPath", path},
                {"live", active(sandbox)},
                {"coverage", "private directory only"}};
    }
    fail("unsupported_operation", "Operation is unavailable in the current driverless implementation: " + op);
}
QJsonObject Store::execute(const QJsonObject &request) noexcept {
    try {
        auto response = dispatch(request);
        response["ok"] = true;
        return response;
    } catch (const Error &error) {
        return {{"ok", false}, {"code", error.code}, {"error", QString::fromUtf8(error.what())}};
    } catch (const std::exception &error) {
        return {{"ok", false}, {"code", "internal"}, {"error", QString::fromUtf8(error.what())}};
    }
}
}

#include "driverless/snapshot.h"

namespace nb {
QJsonArray copyPrivateTree(const QString &source, const QString &destination, qint64 maximumBytes) {
    rejectReparse(source);
    rejectReparse(destination);
    if (!QFileInfo(source).isDir() || QFileInfo::exists(destination))
        fail("copy", "Source must exist and destination must be new");
    if (!QDir().mkpath(destination))
        fail("copy", "Cannot create copy destination");
    QJsonArray manifest;
    qint64 bytes = 0;
    QDirIterator iterator(source, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
                          QDirIterator::Subdirectories);
    while (iterator.hasNext()) {
        auto path = iterator.next();
        rejectReparse(path);
        auto relative = QDir(source).relativeFilePath(path);
        auto target = inside(destination, relative);
        if (iterator.fileInfo().isDir()) {
            if (!QDir().mkpath(target))
                fail("copy", "Cannot create copied directory");
            manifest.append(QJsonObject{{"path", relative}, {"directory", true}});
        } else {
            auto size = iterator.fileInfo().size();
            if (size < 0 || size > maximumBytes - bytes)
                fail("quota", "Copy exceeds the declared private-storage observation budget");
            auto before = digest(path);
            if (!QDir().mkpath(QFileInfo(target).absolutePath()) || !QFile::copy(path, target))
                fail("copy", "Cannot copy private file");
            if (digest(target) != before || digest(path) != before || QFileInfo(target).size() != size)
                fail("copy_changed", "Source changed while copying");
            bytes += size;
            manifest.append(
                QJsonObject{{"path", relative}, {"directory", false}, {"size", size}, {"sha256", before}});
        }
        if (manifest.size() > 5000)
            fail("manifest", "Snapshot file count exceeds the supported bound");
    }
    return manifest;
}
QJsonObject verifyPrivateSnapshot(const QString &snapshot) {
    rejectReparse(snapshot);
    auto manifest = parseObject(readFile(inside(snapshot, "manifest.json")));
    if (manifest.value("schema").toInt() != 2 || !manifest.value("entries").isArray())
        fail("snapshot_manifest", "Unsupported snapshot manifest");
    auto data = inside(snapshot, "data");
    QSet<QString> expected;
    for (const auto &value : manifest.value("entries").toArray()) {
        auto entry = value.toObject();
        auto relative = entry.value("path").toString();
        auto path = inside(data, relative);
        if (expected.contains(relative.toCaseFolded()))
            fail("snapshot_manifest", "Duplicate snapshot path");
        expected.insert(relative.toCaseFolded());
        QFileInfo info(path);
        if (!info.exists() || info.isDir() != entry.value("directory").toBool())
            fail("snapshot_corrupt", "Snapshot entry is missing or has the wrong type");
        if (info.isFile() && (info.size() != entry.value("size").toInteger(-1) ||
                              digest(path) != entry.value("sha256").toString()))
            fail("snapshot_corrupt", "Snapshot content hash differs");
    }
    QSet<QString> actual;
    QDirIterator iterator(data, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
                          QDirIterator::Subdirectories);
    while (iterator.hasNext()) {
        auto path = iterator.next();
        rejectReparse(path);
        actual.insert(QDir(data).relativeFilePath(path).toCaseFolded());
    }
    if (!QFileInfo(data).isDir() || actual != expected)
        fail("snapshot_corrupt", "Snapshot inventory differs from the manifest");
    return manifest;
}
void recoverPrivateRestore(const QString &base) {
    auto markerPath = inside(base, "restore.json");
    if (!QFileInfo::exists(markerPath))
        return;
    auto marker = parseObject(readFile(markerPath));
    auto transaction = validateId(marker.value("transaction").toString());
    auto data = inside(base, "data");
    auto retired = inside(base, "retained-" + transaction);
    auto staged = inside(base, "restore-" + transaction);
    if (!QFileInfo::exists(data)) {
        if (!QFileInfo(retired).isDir() || !QDir().rename(retired, data))
            fail("restore_recovery", "Cannot recover retained original data; all bytes are preserved");
    } else if (!QFileInfo(data).isDir())
        fail("restore_recovery", "Current private data is not a directory");
    if (QFileInfo::exists(staged)) {
        auto preserved = inside(base, "interrupted-" + transaction);
        if (!QDir().rename(staged, preserved))
            fail("restore_recovery", "Cannot preserve interrupted staging data");
    }
    if (!QFile::remove(markerPath))
        fail("restore_recovery", "Cannot commit recovery metadata");
}
QJsonObject createPrivateSnapshot(const QString &base, qint64 maximumBytes) {
    auto snapshotId = id();
    auto parent = inside(base, "snapshots");
    if (!QDir().mkpath(parent))
        fail("snapshot", "Cannot create snapshot parent");
    auto pending = inside(parent, snapshotId + ".pending");
    if (!QDir().mkpath(pending))
        fail("snapshot", "Cannot create pending snapshot");
    auto entries = copyPrivateTree(inside(base, "data"), inside(pending, "data"), maximumBytes);
    QJsonObject manifest{{"schema", 2},
                         {"id", snapshotId},
                         {"created", now()},
                         {"scope", "driverless private data only"},
                         {"entries", entries}};
    auto bytes = QJsonDocument(manifest).toJson(QJsonDocument::Compact);
    if (bytes.size() > 1024 * 1024)
        fail("manifest", "Snapshot manifest exceeds the supported bound");
    atomicWrite(inside(pending, "manifest.json"), bytes);
    verifyPrivateSnapshot(pending);
    if (!QDir().rename(pending, inside(parent, snapshotId)))
        fail("snapshot", "Cannot commit completed snapshot");
    return manifest;
}
void restorePrivateSnapshot(const QString &base, const QString &snapshotId, qint64 maximumBytes) {
    recoverPrivateRestore(base);
    auto snapshot = inside(base, "snapshots/" + validateId(snapshotId));
    verifyPrivateSnapshot(snapshot);
    auto transaction = id();
    auto staged = inside(base, "restore-" + transaction);
    auto copied = copyPrivateTree(inside(snapshot, "data"), staged, maximumBytes);
    Q_UNUSED(copied)
    verifyPrivateSnapshot(snapshot);
    auto marker = inside(base, "restore.json");
    atomicWrite(marker, QJsonDocument(QJsonObject{{"transaction", transaction}, {"snapshot", snapshotId}})
                            .toJson(QJsonDocument::Compact));
    auto data = inside(base, "data");
    auto retained = inside(base, "retained-" + transaction);
    if (!QDir().rename(data, retained))
        fail("restore", "Cannot retain current data; restore journal is preserved");
    if (!QDir().rename(staged, data)) {
        recoverPrivateRestore(base);
        fail("restore", "Restore could not commit; original data was recovered");
    }
    if (!QFile::remove(marker))
        fail("restore", "New data is installed but the recovery journal could not be cleared");
}
}

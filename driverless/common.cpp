#include "driverless/common.h"
#include <sddl.h>

namespace nb {
QString ownerSession(HANDLE process) {
    HANDLE value = nullptr;
    wincheck(OpenProcessToken(process, TOKEN_QUERY, &value), "Open process logon identity");
    Handle token(value);
    TOKEN_STATISTICS statistics{};
    DWORD bytes = 0, session = 0;
    wincheck(GetTokenInformation(token.get(), TokenStatistics, &statistics, sizeof(statistics), &bytes),
             "Read process logon identity");
    wincheck(ProcessIdToSessionId(GetProcessId(process), &session), "Read process Windows session");
    return QString::number(session) + ':' + QString::number(quint32(statistics.AuthenticationId.HighPart)) +
           ':' + QString::number(statistics.AuthenticationId.LowPart);
}
void fail(const QString &code, const QString &message) {
    throw Error(code, message);
}
void wincheck(bool success, const QString &operation) {
    if (!success)
        fail("win32", operation + " (" + QString::number(GetLastError()) + ')');
}
QString now() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}
QString id() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}
QString validateId(const QString &value) {
    static const QRegularExpression pattern("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$");
    if (!pattern.match(value).hasMatch())
        fail("id", "Invalid profile or snapshot ID");
    return value;
}
QString privatePath(const QString &path) {
    if (path.isEmpty() || path.contains(QChar(0)))
        fail("path", "Empty path or NUL in path");
    auto native = QDir::fromNativeSeparators(path);
    if (!QDir::isAbsolutePath(native) || native.startsWith("//") || native.size() < 3 || native[1] != ':' ||
        native.mid(2).contains(':'))
        fail("path", "Private storage requires an absolute local drive path without streams");
    return QDir::cleanPath(native);
}
void rejectReparse(const QString &path) {
    auto absolute = privatePath(path);
    auto parts = absolute.mid(3).split('/', Qt::SkipEmptyParts);
    QString current = absolute.left(3);
    for (const auto &part : parts) {
        current = QDir(current).filePath(part);
        auto native = QDir::toNativeSeparators(current).toStdWString();
        DWORD attributes = GetFileAttributesW(native.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                continue;
            fail("path_access", "Cannot inspect private storage path");
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
            fail("reparse", "Private storage cannot traverse a reparse point");
    }
}
QString inside(const QString &root, const QString &relative) {
    auto base = privatePath(root);
    if (relative.contains(QChar(0)) || relative.contains(':') || relative.contains('\\') ||
        relative.startsWith('/') || relative.split('/').contains(".."))
        fail("path", "Unsafe private relative path");
    auto path = QDir::cleanPath(base + '/' + relative);
    if (!path.startsWith(base + '/', Qt::CaseInsensitive))
        fail("path", "Path escapes private storage");
    rejectReparse(path);
    return path;
}
QByteArray readFile(const QString &path, qint64 limit) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        fail("read", file.errorString());
    if (file.size() > limit)
        fail("size", "File exceeds the input limit");
    auto bytes = file.read(limit + 1);
    if (bytes.size() > limit || file.error() != QFile::NoError)
        fail("read", "Incomplete or oversized input");
    return bytes;
}
void atomicWrite(const QString &path, const QByteArray &bytes) {
    rejectReparse(path);
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
        fail("write", file.errorString());
}
QJsonObject parseObject(const QByteArray &bytes) {
    if (bytes.size() > 1024 * 1024)
        fail("frame", "JSON exceeds one MiB");
    QJsonParseError error;
    auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        fail("json", "Expected a valid JSON object");
    return document.object();
}
QString digest(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        fail("hash", "Cannot read file to compute SHA-256");
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file))
        fail("hash", "SHA-256 read failed");
    return QString::fromLatin1(hash.result().toHex());
}
QString ownerSid(HANDLE process) {
    HANDLE value = nullptr;
    wincheck(OpenProcessToken(process, TOKEN_QUERY, &value), "Open process identity");
    Handle token(value);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (!size || size > 65536)
        fail("identity", "Invalid process identity size");
    QByteArray buffer(size, Qt::Uninitialized);
    wincheck(GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size),
             "Read process identity");
    LPWSTR text = nullptr;
    wincheck(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &text),
             "Format process identity");
    auto release = qScopeGuard([&] { LocalFree(text); });
    return QString::fromWCharArray(text);
}
QString defaultRoot() {
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/Storage";
}
Database::Database(const QString &path, bool readOnly) : connection_(id()) {
    rejectReparse(path);
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(path);
    db_.setConnectOptions(readOnly ? "QSQLITE_OPEN_READONLY;QSQLITE_BUSY_TIMEOUT=5000"
                                   : "QSQLITE_BUSY_TIMEOUT=5000");
    if (!db_.open())
        fail("database", db_.lastError().text());
    for (auto statement : {"PRAGMA trusted_schema=OFF", "PRAGMA foreign_keys=ON"}) {
        QSqlQuery query(db_);
        if (!query.exec(statement))
            fail("database", query.lastError().text());
    }
}
Database::~Database() {
    db_.close();
    db_ = {};
    QSqlDatabase::removeDatabase(connection_);
}
void sql(QSqlQuery &query) {
    if (!query.exec())
        fail("database", query.lastError().text());
}
}

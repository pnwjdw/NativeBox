#pragma once
#include <QtCore>
#include <QtSql>
#include <windows.h>
#include <memory>
#include <stdexcept>
#include <utility>

namespace nb {
class Error : public std::runtime_error {
  public:
    QString code;
    Error(QString value, const QString &message)
        : std::runtime_error(message.toStdString()), code(std::move(value)) {}
};
[[noreturn]] void fail(const QString &code, const QString &message);
void wincheck(bool success, const QString &operation);
QString now();
QString id();
QString validateId(const QString &value);
QString privatePath(const QString &path);
QString inside(const QString &root, const QString &relative);
void rejectReparse(const QString &path);
QByteArray readFile(const QString &path, qint64 limit = 1024 * 1024);
void atomicWrite(const QString &path, const QByteArray &bytes);
QJsonObject parseObject(const QByteArray &bytes);
QString digest(const QString &path);
QString ownerSid(HANDLE process = GetCurrentProcess());
QString ownerSession(HANDLE process = GetCurrentProcess());
QString defaultRoot();
class Handle {
    HANDLE value_ = nullptr;

  public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() {
        if (*this)
            CloseHandle(value_);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle &operator=(Handle &&other) noexcept {
        if (this != &other) {
            if (*this)
                CloseHandle(value_);
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
};
class Database {
    QString connection_;
    QSqlDatabase db_;

  public:
    explicit Database(const QString &path, bool readOnly = false);
    ~Database();
    QSqlDatabase &get() { return db_; }
};
void sql(QSqlQuery &query);
}

#pragma once
#include "driverless/common.h"
#include "driverless/runtime/protocol.h"
#include <functional>

namespace nb {
QString quoteArgument(const QString &argument);
QStringList parseArguments(const QString &arguments);
class RuntimeSession {
    Handle job_, process_;
    DWORD pid_ = 0;
    FILETIME creation_{};
    bool runtimeAttached_ = false;
    QString runId_;

  public:
    RuntimeSession(const QString &executable, const QStringList &arguments, const QString &directory,
                   const runtime::Configuration *configuration = nullptr, const QString &runtimeLibrary = {},
                   const QString &runtimeSha256 = {},
                   std::function<void(HANDLE, HANDLE)> beforeResume = {});
    QJsonObject status() const;
    bool active() const;
    DWORD activeCount() const;
    void stop();
};
}

#pragma once
#include "driverless/common.h"
#include "driverless/runtime/protocol.h"

namespace nb {
struct RuntimeBundle {
    QString library64, library32, offlineRegistry;
    QString sha64, sha32;
    QString reason;
    bool available() const { return reason.isEmpty(); }
};
RuntimeBundle inspectRuntimeBundle();
std::unique_ptr<runtime::Configuration> prepareRedirected(const QJsonObject &profile, const QString &sandbox,
                                                          const QString &dataPath,
                                                          const RuntimeBundle &bundle);
}

#pragma once
#include "driverless/common.h"
#include "driverless/runtime/network.h"

namespace nb {
bool hasProxyCredential(const QString &sandbox);
void saveProxyCredential(const QString &sandbox, QString username, QString password);
void clearProxyCredential(const QString &sandbox);
runtime::Proxy proxyConfiguration(const QJsonObject &network, const QString &sandbox);
}

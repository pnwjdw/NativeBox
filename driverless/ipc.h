#pragma once
#include "driverless/common.h"

namespace nb {
QString brokerName(const QString &root);
QJsonObject driverlessRequest(const QString &root, const QJsonObject &request);
}

#pragma once
#include "driverless/common.h"

namespace nb {
QJsonObject probeProxy(const QJsonObject &profile, const QString &sandbox, const QJsonObject &request);
}

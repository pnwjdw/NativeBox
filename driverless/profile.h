#pragma once
#include "driverless/common.h"

namespace nb {
QJsonObject validateDriverlessProfile(QJsonObject profile);
QJsonObject runtimeReadiness(const QJsonObject &profile, const QString &dataPath,
                             const QString &sandbox = {});
}

#pragma once
#include "driverless/common.h"

namespace nb {
QJsonArray copyPrivateTree(const QString &source, const QString &destination, qint64 maximumBytes);
QJsonObject verifyPrivateSnapshot(const QString &snapshot);
void recoverPrivateRestore(const QString &base);
QJsonObject createPrivateSnapshot(const QString &base, qint64 maximumBytes);
void restorePrivateSnapshot(const QString &base, const QString &snapshotId, qint64 maximumBytes);
}

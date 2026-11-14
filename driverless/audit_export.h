#pragma once
#include <QJsonObject>
#include <QString>

namespace nb {
// Export the complete raw newline-delimited journal, rather than the bounded UI cache.
// Sources are pinned and sized before copying; an unfinished final row is reported and omitted.
// Malformed complete rows are preserved byte for byte, because this is an evidence archive.
QJsonObject exportJournal(QString storageRoot, QString sandbox, QString destination);
}

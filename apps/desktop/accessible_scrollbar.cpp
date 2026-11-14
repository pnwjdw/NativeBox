#include "apps/desktop/accessible_scrollbar.h"
#include <qqml.h>

namespace nb {
AccessibleScrollBar::AccessibleScrollBar(QQuickItem *parent) : QQuickScrollBar(parent) {}
void AccessibleScrollBar::accessibilityActiveChanged(bool active) {
    if (active)
        QQuickScrollBar::accessibilityActiveChanged(false);
    QQuickScrollBar::accessibilityActiveChanged(active);
}
void registerDesktopControls() {
    static const int typeId = [] {
        qmlRegisterAnonymousTypesAndRevisions<QQuickControl>("NativeBox.Controls", 2);
        qmlRegisterAnonymousTypesAndRevisions<QQuickScrollBar>("NativeBox.Controls", 2);
        return qmlRegisterType<AccessibleScrollBar>("NativeBox.Controls", 2, 15, "NativeScrollBar");
    }();
    Q_UNUSED(typeId)
}
}

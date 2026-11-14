#pragma once
#include <QtQuickTemplates2/private/qquickscrollbar_p.h>

namespace nb {
class AccessibleScrollBar : public QQuickScrollBar {
    Q_OBJECT
  protected:
    void accessibilityActiveChanged(bool active) override;

  public:
    explicit AccessibleScrollBar(QQuickItem *parent = nullptr);
};
void registerDesktopControls();
}

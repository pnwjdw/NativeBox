#include "driverless/common.h"
#include "driverless/ipc.h"
#include "apps/desktop/controller.h"
#include "apps/desktop/accessible_scrollbar.h"
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>

int main(int argc, char **argv) {
    QGuiApplication app(argc, argv);
    QCoreApplication::setApplicationVersion(NB_PRODUCT_VERSION);
    QCoreApplication::setOrganizationName("NativeBox");
    QCoreApplication::setApplicationName("NativeBox");
    QQuickStyle::setStyle("Basic");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({"root", "Private data root", "path", nb::defaultRoot()});
    parser.addOption({"validate-ui", "Instantiate an invisible QML tree and exit"});
    parser.addOption({"diagnose-ui", "Record internal Qt window state after a visible startup, then exit"});
    parser.process(app);
    try {
        auto root = parser.value("root");
        nb::rejectReparse(QFileInfo(root).absoluteFilePath());
        if (!QDir().mkpath(root))
            nb::fail("storage", "Cannot prepare desktop settings");
        Controller controller(root);
        nb::registerDesktopControls();
        QQmlApplicationEngine engine;
        engine.rootContext()->setContextProperty("backend", &controller);
        engine.rootContext()->setContextProperty("validationMode", parser.isSet("validate-ui"));
        bool warnings = false;
        QObject::connect(&engine, &QQmlEngine::warnings, &app, [&](const QList<QQmlError> &errors) {
            warnings = true;
            for (const auto &error : errors)
                qWarning().noquote() << error.toString();
        });
        engine.loadFromModule("NativeBox", "Main");
        if (engine.rootObjects().isEmpty())
            return 2;
        if (parser.isSet("diagnose-ui"))
            QTimer::singleShot(3000, &app, [&] {
                auto window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
                QJsonObject result{{"scope", "internal Qt state only; not visible GUI acceptance"},
                                   {"qmlWarnings", warnings},
                                   {"timeUtc", nb::now()}};
                if (window) {
                    result["visible"] = window->isVisible();
                    result["exposed"] = window->isExposed();
                    result["width"] = window->width();
                    result["height"] = window->height();
                }
                try {
                    nb::atomicWrite(root + "/ui-diagnostics.json", QJsonDocument(result).toJson());
                } catch (...) {
                    app.exit(4);
                    return;
                }
                app.exit(warnings ? 3 : 0);
            });
        if (parser.isSet("validate-ui"))
            QTimer::singleShot(2000, &app, [&] { app.exit(warnings ? 3 : 0); });
        return app.exec();
    } catch (const std::exception &error) {
        qCritical() << error.what();
        return 1;
    }
}

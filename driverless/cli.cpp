#include "driverless/ipc.h"

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationVersion(NB_PRODUCT_VERSION);
    QCoreApplication::setOrganizationName("NativeBox");
    QCoreApplication::setApplicationName("NativeBox");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({"root", "Private data root", "path", nb::defaultRoot()});
    parser.addOption(
        {"request", "JSON request, @path, or - for standard input", "json", "{\"op\":\"status\"}"});
    parser.process(app);
    try {
        auto bytes = parser.value("request").toUtf8();
        if (bytes == "-") {
            QFile input;
            if (!input.open(stdin, QIODevice::ReadOnly))
                nb::fail("input", "Cannot read standard input");
            bytes = input.read(1024 * 1024 + 1);
            if (bytes.size() > 1024 * 1024)
                nb::fail("frame", "Request exceeds the IPC limit");
        }
        if (bytes.startsWith('@'))
            bytes = nb::readFile(QString::fromUtf8(bytes.mid(1)));
        auto response = nb::driverlessRequest(parser.value("root"), nb::parseObject(bytes));
        QTextStream(stdout) << QJsonDocument(response).toJson(QJsonDocument::Compact) << Qt::endl;
        return response.value("ok").toBool() ? 0 : 2;
    } catch (const nb::Error &error) {
        QTextStream(stdout) << QJsonDocument(QJsonObject{{"ok", false},
                                                         {"code", error.code},
                                                         {"error", QString::fromUtf8(error.what())}})
                                   .toJson(QJsonDocument::Compact)
                            << Qt::endl;
        return 1;
    }
}

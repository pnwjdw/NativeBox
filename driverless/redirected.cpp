#include "driverless/redirected.h"
#include "driverless/runtime/files.h"
#include "driverless/runtime/registry.h"
#include <QHostAddress>

namespace nb {
RuntimeBundle inspectRuntimeBundle() {
    RuntimeBundle result;
    auto directory = QCoreApplication::applicationDirPath();
    auto manifest = directory + "/runtime-artifacts.json";
    result.reason = "runtime_unavailable";
    if (!QFileInfo::exists(manifest))
        return result;
    try {
        rejectReparse(manifest);
        auto record = parseObject(readFile(manifest));
        if (record.value("contract").toString() != "nativebox.runtime/1" ||
            record.value("productVersion").toString() != NB_PRODUCT_VERSION ||
            record.value("provenance").toObject().value("detoursVersion").toString() != "4.0.1" ||
            !QRegularExpression("^[a-f0-9]{64}$").match(record.value("sourceDigest").toString()).hasMatch())
            fail("runtime_manifest", "Runtime build provenance or protocol does not match");
        auto files = record.value("artifacts").toObject();
        for (const auto &name : {QStringLiteral("nativebox_runtime64.dll"),
                                 QStringLiteral("nativebox_runtime32.dll"), QStringLiteral("offreg.dll")}) {
            auto file = directory + '/' + name;
            auto expected = files.value(name).toString();
            rejectReparse(file);
            if (!QRegularExpression("^[a-f0-9]{64}$").match(expected).hasMatch() || digest(file) != expected)
                fail("runtime_integrity", "Runtime artifact differs from the compiled build manifest");
            if (name == "offreg.dll" &&
                expected != "453c52750a193fb250209b9928b04a70398a8de94c967df72e8bb03af47c1956")
                fail("runtime_integrity", "Offline Registry redistributable differs from its Microsoft pin");
        }
        result.library64 = directory + "/nativebox_runtime64.dll";
        result.library32 = directory + "/nativebox_runtime32.dll";
        result.offlineRegistry = directory + "/offreg.dll";
        result.sha64 = files.value("nativebox_runtime64.dll").toString();
        result.sha32 = files.value("nativebox_runtime32.dll").toString();
        result.reason.clear();
    } catch (const Error &error) {
        result.reason = error.code;
    }
    return result;
}
namespace {
template <size_t Size> void text(wchar_t (&target)[Size], const QString &value) {
    if (value.contains(QChar(0)) || value.size() >= qsizetype(Size))
        fail("runtime_config", "Runtime text exceeds its bounded field");
    auto native = value.toStdWString();
    std::copy(native.begin(), native.end(), target);
    target[native.size()] = 0;
}
}
std::unique_ptr<runtime::Configuration> prepareRedirected(const QJsonObject &profile, const QString &sandbox,
                                                          const QString &dataPath,
                                                          const RuntimeBundle &bundle) {
    if (!bundle.available())
        fail(bundle.reason, "Required runtime artifacts are unavailable");
    auto ownedConfiguration = std::make_unique<runtime::Configuration>();
    auto &configuration = *ownedConfiguration;
    text(configuration.dataRoot, QDir::toNativeSeparators(dataPath));
    text(configuration.runtimeDll, QDir::toNativeSeparators(bundle.library64));
    text(configuration.profileId, validateId(sandbox));
    text(configuration.runId, id());
    auto sha64 = bundle.sha64.toLatin1(), sha32 = bundle.sha32.toLatin1();
    std::copy(sha64.begin(), sha64.end(), configuration.sha64);
    std::copy(sha32.begin(), sha32.end(), configuration.sha32);
    const auto redirect = profile.value("redirect").toObject();
    const bool everything = redirect.value("scope").toString(redirect.value("fileRoots").toArray().isEmpty() && redirect.value("registryRoots").toArray().isEmpty() ? "all" : "selected") == "all";
    auto files = redirect.value("fileRoots").toArray();
    const auto registry = everything ? QJsonArray() : redirect.value("registryRoots").toArray();
    auto storageRoot = QDir(dataPath);
    storageRoot.cdUp();
    storageRoot.cdUp();
    storageRoot.cdUp();
    text(configuration.excludeRoot, QDir::toNativeSeparators(storageRoot.absolutePath()));
    if (everything) {
        // Every local drive is a copy-on-write scope; the manager's own storage stays outside.
        files = {};
        DWORD drives = GetLogicalDrives();
        for (int letter = 0; letter < 26; ++letter) {
            if (!(drives & (1u << letter)))
                continue;
            QString drive = QString(QChar('A' + letter)) + ":\\";
            auto type = GetDriveTypeW(reinterpret_cast<LPCWSTR>(drive.utf16()));
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_RAMDISK)
                files.append(drive);
        }
        configuration.redirectAll = 1;
    }
    configuration.fileRootCount = uint32_t(files.size());
    configuration.registryRootCount = uint32_t(registry.size());
    if (files.size() > 26 || registry.size() > 8 || (!everything && files.isEmpty() && registry.isEmpty()))
        fail("redirect_scope", "Choose file or registry scopes");
    try {
        for (qsizetype index = 0; index < files.size(); ++index) {
            auto root = everything ? files[index].toString() : privatePath(files[index].toString());
            auto native = QDir::toNativeSeparators(root).toStdWString();
            auto storage = QDir::toNativeSeparators(dataPath).toStdWString();
            if (!everything && (runtime::beneath(storage, native) || runtime::beneath(native, storage)))
                fail("redirect_scope", "Logical file scope and private storage must not overlap");
            text(configuration.fileRoots[index], QDir::toNativeSeparators(root));
            runtime::FileStore prepare(native, storage + L"\\overlay\\" + std::to_wstring(index),
                                       configuration.excludeRoot);
        }
        bool roots = false;
        for (qsizetype index = 0; index < registry.size(); ++index) {
            auto root = registry[index].toString();
            bool user = root.startsWith("HKCU\\", Qt::CaseInsensitive);
            configuration.registryRoots[index].root = user ? 1u : 2u;
            text(configuration.registryRoots[index].prefix, root.mid(5));
            roots = true;
        }
        if (roots || everything) {
            auto root = QDir::toNativeSeparators(dataPath + "/registry").toStdWString();
            runtime::directories(root);
            runtime::createPrivateHive(root + L"\\private.hive",
                                       QDir::toNativeSeparators(bundle.offlineRegistry).toStdWString());
            runtime::RegistryStore prepare(root);
            prepare.flush();
        }
    } catch (const runtime::Error &error) {
        fail("runtime_storage", QString::fromUtf8(error.what()) + " (" + QString::number(error.code) + ')');
    }
    auto network = profile.value("network").toObject();
    if (network.value("mode").toString() == "managed_proxy") {
        auto protocol = network.value("protocol").toString();
        auto address = network.value("host").toString();
        QHostAddress parsed(address);
        int port = network.value("port").toInt();
        if ((protocol != "http" && protocol != "socks5") ||
            parsed.protocol() != QAbstractSocket::IPv4Protocol || port < 1 || port > 65535 ||
            network.value("dns").toString("local") != "local")
            fail("proxy_config", "Managed route requires a numeric IPv4 proxy and explicit local DNS");
        auto protocolBytes = protocol.toLatin1(), addressBytes = address.toLatin1();
        std::copy(protocolBytes.begin(), protocolBytes.end(), configuration.proxyProtocol);
        std::copy(addressBytes.begin(), addressBytes.end(), configuration.proxyAddress);
        configuration.proxyPort = uint32_t(port);
        int timeout = network.value("timeoutMs").toInt(5000);
        if (timeout < 100 || timeout > 30000)
            fail("proxy_config", "Proxy timeout must be between 100 and 30000 milliseconds");
        configuration.proxyTimeoutMs = uint32_t(timeout);
        configuration.managedProxy = 1;
        configuration.proxyAuthenticated = network.value("authenticated").toBool() ? 1u : 0u;
    }
    return ownedConfiguration;
}
}

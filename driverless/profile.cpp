#include "driverless/profile.h"
#include "driverless/redirected.h"
#include "driverless/credentials.h"
#include <QHostAddress>

namespace nb {
static void rejectSecrets(const QJsonValue &value) {
    if (value.isArray()) {
        for (const auto &child : value.toArray())
            rejectSecrets(child);
    }
    if (!value.isObject())
        return;
    const auto object = value.toObject();
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (QStringList{"password", "secret", "apikey", "accesstoken", "privatekey"}.contains(
                it.key().toLower()))
            fail("secret", "Profile contains a secret field; use a dedicated credential store");
        rejectSecrets(it.value());
    }
}
QJsonObject validateDriverlessProfile(QJsonObject profile) {
    rejectSecrets(profile);
    for (const auto &field : {"id", "readiness", "running", "canRestart"})
        profile.remove(field);
    if (profile.contains("network") && !profile.value("network").isObject())
        fail("network_mode", "Network configuration must be an object");
    if (profile.contains("applications") && !profile.value("applications").isArray())
        fail("profile", "Applications must be an array");
    if (profile.contains("audit") && !profile.value("audit").isObject())
        fail("profile", "Audit configuration must be an object");
    if (profile.value("audit").toObject().contains("required") &&
        !profile.value("audit").toObject().value("required").isBool())
        fail("profile", "Audit required must be a boolean");
    int quota = profile.value("quotaMiB").toInt(1024);
    if (quota < 1 || quota > 1048576)
        fail("quota", "Invalid observed private-storage budget");
    profile["quotaMiB"] = quota;
    if (profile.contains("schema") && profile.value("schema").toInt() != 2)
        fail("schema", "Driverless profile schema must be 2");
    auto name = profile.value("name").toString().trimmed();
    if (name.isEmpty() || name.size() > 100 || name.contains(QChar(0)))
        fail("profile", "Profile name requires 1 to 100 characters");
    auto mode = profile.value("executionMode").toString("usermode_redirected");
    if (mode != "usermode_redirected" && mode != "app_profile")
        fail("execution_mode", "Choose usermode_redirected or explicit app_profile");
    if (profile.contains("backend") && profile.value("backend").toString() != "driverless")
        fail("backend", "Cannot import a kernel profile as driverless");
    auto network = profile.value("network").toObject();
    auto networkMode = network.value("mode").toString("direct");
    if (!QStringList{"direct", "managed_proxy", "offline", "os_restricted_proxy"}.contains(networkMode))
        fail("network_mode", "Unknown driverless network mode; legacy strict mode must be reviewed");
    if (network.contains("password") || network.contains("username") || profile.contains("password"))
        fail("secret", "Credentials cannot be stored in profiles");
    network["mode"] = networkMode;
    if (networkMode == "managed_proxy") {
        int port = network.value("port").toInt();
        int timeout = network.value("timeoutMs").toInt(5000);
        QHostAddress address(network.value("host").toString());
        if (address.protocol() != QAbstractSocket::IPv4Protocol || port < 1 || port > 65535 ||
            !QStringList{"http", "socks5"}.contains(network.value("protocol").toString()) ||
            network.value("dns").toString("local") != "local" || timeout < 100 || timeout > 30000)
            fail("proxy_config",
                 "ManagedProxy requires HTTP/SOCKS5, numeric IPv4, local DNS and a bounded timeout");
        network["dns"] = "local";
        network["timeoutMs"] = timeout;
    }
    auto applications = profile.value("applications").toArray();
    if (applications.size() > 128)
        fail("profile", "Too many applications");
    for (const auto &entry : applications) {
        if (!entry.isObject() || entry.toObject().value("path").toString().contains(QChar(0)))
            fail("profile", "Invalid application entry");
    }
    auto adapter = profile.value("adapter").toObject();
    if (profile.contains("redirect") && !profile.value("redirect").isObject())
        fail("redirect_scope", "Redirection configuration must be an object");
    auto redirect = profile.value("redirect").toObject();
    for (const auto &field : {"fileRoots", "registryRoots"}) {
        if (redirect.contains(field) && !redirect.value(field).isArray())
            fail("redirect_scope", "Redirection roots must be arrays");
        if (redirect.value(field).toArray().size() > 8)
            fail("redirect_scope", "At most eight explicit roots are supported");
    }
    QJsonArray fileRoots;
    QStringList existing;
    for (const auto &entry : redirect.value("fileRoots").toArray()) {
        if (!entry.isString() || entry.toString().size() >= 1024)
            fail("redirect_scope", "Invalid bounded logical file root");
        auto root = privatePath(entry.toString());
        if (root.size() <= 3)
            fail("redirect_scope", "Whole-drive redirection is unsupported");
        rejectReparse(root);
        for (const auto &other : existing)
            if (root.compare(other, Qt::CaseInsensitive) == 0 ||
                root.startsWith(other + '/', Qt::CaseInsensitive) ||
                other.startsWith(root + '/', Qt::CaseInsensitive))
                fail("redirect_scope", "Logical file scopes must not overlap");
        existing.append(root);
        fileRoots.append(root);
    }
    QJsonArray registryRoots;
    existing.clear();
    for (const auto &entry : redirect.value("registryRoots").toArray()) {
        auto root = entry.toString();
        if (!entry.isString() || root.size() >= 512 || root.contains(QChar(0)) ||
            !QRegularExpression("^(HKCU|HKLM)\\\\Software\\\\.+", QRegularExpression::CaseInsensitiveOption)
                 .match(root)
                 .hasMatch())
            fail("redirect_scope", "Registry roots require a selected HKCU/HKLM Software subtree");
        for (const auto &part : root.split('\\'))
            if (part.isEmpty() || part == "." || part == ".." || part.size() > 255 || part.contains('/'))
                fail("redirect_scope", "Invalid registry scope component");
        for (const auto &other : existing)
            if (root.compare(other, Qt::CaseInsensitive) == 0 ||
                root.startsWith(other + '\\', Qt::CaseInsensitive) ||
                other.startsWith(root + '\\', Qt::CaseInsensitive))
                fail("redirect_scope", "Registry scopes must not overlap");
        existing.append(root);
        registryRoots.append(root);
    }
    redirect["fileRoots"] = fileRoots;
    redirect["registryRoots"] = registryRoots;
    // Default: redirect every write (all local drives and the whole registry). Explicit roots keep the older,
    // narrower behaviour for profiles that ask for it.
    auto scope = redirect.value("scope").toString(fileRoots.isEmpty() && registryRoots.isEmpty() ? "all" : "selected");
    if (scope != "all" && scope != "selected")
        fail("redirect_scope", "Redirection scope must be all or selected");
    redirect["scope"] = scope;
    if (mode == "app_profile") {
        if (adapter.value("type").toString() != "data_directory")
            fail("adapter", "APP_PROFILE requires an explicit data_directory adapter");
        auto executable = privatePath(adapter.value("executable").toString());
        auto sha = adapter.value("sha256").toString();
        if (!QRegularExpression("^[a-f0-9]{64}$").match(sha).hasMatch())
            fail("adapter", "Adapter requires the exact executable SHA-256");
        int dataArguments = 0;
        if (!adapter.value("arguments").isArray())
            fail("adapter", "Adapter arguments must be an array");
        for (const auto &value : adapter.value("arguments").toArray()) {
            if (!value.isString() || value.toString().contains(QChar(0)))
                fail("adapter", "Invalid adapter argument");
            dataArguments += value.toString().contains("{dataDir}");
        }
        if (dataArguments != 1)
            fail("adapter", "Adapter requires exactly one dataDir argument");
        adapter["executable"] = executable;
    }
    profile["schema"] = 2;
    profile["storageVersion"] = 2;
    profile["backend"] = "driverless";
    profile["name"] = name;
    profile["executionMode"] = mode;
    profile["network"] = network;
    profile["adapter"] = adapter;
    profile["redirect"] = redirect;
    profile["applications"] = applications;
    for (const auto &field :
         {"id", "running", "driverConnected", "kernelValidation", "RuntimeIsolationVerified", "readiness",
          "capabilities", "readOnly", "legacySource"})
        profile.remove(field);
    return profile;
}
QJsonObject runtimeReadiness(const QJsonObject &profile, const QString &dataPath, const QString &sandbox) {
    bool legacy = profile.value("backend").toString() != "driverless";
    bool adapter = profile.value("executionMode").toString() == "app_profile" && !legacy;
    auto network = profile.value("network").toObject().value("mode").toString("direct");
    bool storage = QFileInfo(dataPath).isDir() && !legacy;
    auto bundle = inspectRuntimeBundle();
    bool runtime = bundle.available();
    auto redirect = profile.value("redirect").toObject();
    bool everything = redirect.value("scope").toString(redirect.value("fileRoots").toArray().isEmpty() && redirect.value("registryRoots").toArray().isEmpty() ? "all" : "selected") == "all";
    bool scopes = everything || !redirect.value("fileRoots").toArray().isEmpty() ||
                  !redirect.value("registryRoots").toArray().isEmpty();
    bool routing = network == "direct" || (!adapter && runtime && network == "managed_proxy");
    bool credentials = network != "managed_proxy" ||
                       !profile.value("network").toObject().value("authenticated").toBool() ||
                       (!sandbox.isEmpty() && hasProxyCredential(sandbox));
    QJsonArray limitations{"Not a security boundary against malicious code",
                           "Shared Windows account, kernel and desktop", "EXCLUDED_IPV6_BY_OWNER"};
    if (adapter)
        limitations.append(
            "Only application-supported data-directory behavior; no file or registry interception");
    else if (!runtime)
        limitations.append("Instrumentation runtime is not available; redirected execution is refused");
    else {
        limitations.append(everything
                               ? "All local drives and HKCU/HKLM/HKCR are copy-on-write redirected through Win32 "
                                 "APIs; direct NT system calls, drivers and network shares are outside coverage"
                               : "Selected Win32 path APIs and selected registry subtrees only; direct "
                                 "syscalls and foreign handles are outside coverage");
        limitations.append(
            "Children created through covered CreateProcessW/A calls are instrumented; service, COM and "
            "other external process launch mechanisms are outside coverage");
        limitations.append("Managed route covers blocking TCP/IPv4 Winsock; DNS is local; nonblocking, "
                           "ConnectEx and UDP are unsupported");
    }
    if (!routing)
        limitations.append("Requested network routing/confinement is not implemented; execution is refused");
    return {{"backend", legacy ? "legacy_kernel" : "driverless"},
            {"executionMode", profile.value("executionMode")},
            {"contract", "nativebox.driverless/2"},
            {"runtimeVersion", runtime && !adapter ? QJsonValue("nativebox.runtime/1") : QJsonValue::Null},
            {"runtimeAttached", false},
            {"storageReady", storage},
            {"processTrackingReady", true},
            {"proxyRequested", network != "direct"},
            {"proxyRouted", false},
            {"fileRedirectCoverage", adapter   ? "application_data_directory_only"
                                     : runtime ? (everything ? "all_local_drives_win32" : "selected_win32_roots_unqualified")
                                               : "unavailable"},
            {"registryRedirectCoverage",
             !adapter && runtime ? (everything ? "all_registry_copy_on_write" : "selected_copy_on_write") : "none"},
            {"childCoverage", adapter   ? "application_controlled"
                              : runtime ? "CreateProcessW_A_unqualified"
                                        : "unavailable"},
            {"networkRoutingReady", routing},
            {"credentialsReady", credentials},
            {"networkConfinementLevel", "NOT_SUPPORTED"},
            {"kernelRequirements", "RETIRED_REQUIREMENT"},
            {"compatibilityValidated", false},
            {"launchReady", storage && routing && credentials && (adapter || (runtime && scopes))},
            {"reason", legacy         ? "legacy_read_only"
                       : adapter      ? network == "direct" ? "adapter_contract_only" : "network_unsupported"
                       : !runtime     ? bundle.reason
                       : !scopes      ? "redirect_scope_required"
                       : !routing     ? "network_unsupported"
                       : !credentials ? "credential_required"
                                      : "runtime_contract_unqualified"},
            {"limitations", limitations}};
}
}

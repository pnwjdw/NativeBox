#include "driverless/credentials.h"
#include <wincred.h>

namespace nb {
namespace {
std::wstring targetName(const QString &sandbox) {
    return (QStringLiteral("NativeBox.Driverless.Proxy.") + validateId(sandbox)).toStdWString();
}
bool validSecret(const QString &value) {
    return !value.contains(QChar(0)) && !value.contains('\r') && !value.contains('\n') &&
           value.toUtf8().size() <= 255;
}
}
bool hasProxyCredential(const QString &sandbox) {
    auto target = targetName(sandbox);
    PCREDENTIALW value = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &value)) {
        if (GetLastError() == ERROR_NOT_FOUND)
            return false;
        fail("credential_store", "Windows Credential Manager is unavailable for this user");
    }
    bool valid = value->UserName && *value->UserName && value->CredentialBlobSize <= 8192 &&
                 value->CredentialBlobSize % sizeof(wchar_t) == 0;
    SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
    CredFree(value);
    return valid;
}
void saveProxyCredential(const QString &sandbox, QString username, QString password) {
    username.detach();
    password.detach();
    auto wipe = qScopeGuard([&] {
        SecureZeroMemory(username.data(), SIZE_T(username.size()) * sizeof(QChar));
        SecureZeroMemory(password.data(), SIZE_T(password.size()) * sizeof(QChar));
    });
    if (username.isEmpty() || username.contains(':') || !validSecret(username) || !validSecret(password))
        fail("credential_format",
             "Credentials require a username without colon and bounded text without line breaks");
    auto target = targetName(sandbox);
    CREDENTIALW value{};
    value.Type = CRED_TYPE_GENERIC;
    value.TargetName = target.data();
    value.UserName = reinterpret_cast<LPWSTR>(username.data());
    value.CredentialBlob = reinterpret_cast<LPBYTE>(password.data());
    value.CredentialBlobSize = DWORD(password.size() * sizeof(QChar));
    value.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if (!CredWriteW(&value, 0))
        fail("credential_store", "Windows Credential Manager refused to save credentials (Windows error " +
                                     QString::number(GetLastError()) + ')');
}
void clearProxyCredential(const QString &sandbox) {
    auto target = targetName(sandbox);
    if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND)
        fail("credential_store", "Windows Credential Manager refused to remove credentials");
}
runtime::Proxy proxyConfiguration(const QJsonObject &network, const QString &sandbox) {
    runtime::Proxy result{network.value("host").toString().toStdString(),
                          static_cast<unsigned short>(network.value("port").toInt()),
                          network.value("protocol").toString().toStdString(),
                          {},
                          {},
                          DWORD(network.value("timeoutMs").toInt(5000))};
    if (!network.value("authenticated").toBool())
        return result;
    auto target = targetName(sandbox);
    PCREDENTIALW value = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &value))
        fail("credential_store", "Windows Credential Manager cannot provide route credentials");
    auto release = qScopeGuard([&] {
        SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
        CredFree(value);
    });
    if (!value->UserName || value->CredentialBlobSize > 8192 || value->CredentialBlobSize % sizeof(wchar_t))
        fail("credential_format", "Credential store record has an unsupported shape");
    auto username = QString::fromWCharArray(value->UserName);
    auto password = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(value->CredentialBlob),
                                            int(value->CredentialBlobSize / sizeof(wchar_t)));
    auto wipe = qScopeGuard([&] {
        SecureZeroMemory(username.data(), SIZE_T(username.size()) * sizeof(QChar));
        SecureZeroMemory(password.data(), SIZE_T(password.size()) * sizeof(QChar));
    });
    if (username.isEmpty() || !validSecret(username) || !validSecret(password))
        fail("credential_format", "Credential store record is outside the supported text bounds");
    result.username = username.toUtf8().toStdString();
    result.password = password.toUtf8().toStdString();
    return result;
}
}

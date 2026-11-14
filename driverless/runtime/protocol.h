#pragma once
#include "driverless/runtime/base.h"
#include <type_traits>

namespace nb::runtime {
inline constexpr uint32_t ProtocolMagic = 0x3158424e;
inline constexpr uint32_t ProtocolVersion = 4;
struct RegistryRoot {
    uint32_t root = 1;
    wchar_t prefix[512]{};
};
struct Configuration {
    uint32_t magic = ProtocolMagic;
    uint32_t version = ProtocolVersion;
    uint32_t bytes = sizeof(Configuration);
    uint32_t architecture = 64;
    uint64_t readyEvent = 0;
    uint32_t fileRootCount = 0;
    uint32_t registryRootCount = 0;
    uint32_t managedProxy = 0;
    uint32_t proxyPort = 0;
    uint32_t proxyTimeoutMs = 5000;
    uint32_t proxyAuthenticated = 0;
    // 1: every local drive and the whole HKCU/HKLM/HKCR registry are copy-on-write redirected.
    uint32_t redirectAll = 0;
    wchar_t dataRoot[2048]{};
    wchar_t runtimeDll[2048]{};
    wchar_t runId[64]{};
    wchar_t profileId[64]{};
    wchar_t fileRoots[26][1024]{};
    wchar_t excludeRoot[2048]{};
    RegistryRoot registryRoots[8]{};
    char proxyAddress[16]{};
    char proxyProtocol[8]{};
    char sha64[65]{};
    char sha32[65]{};
};
static_assert(std::is_trivially_copyable_v<Configuration>);
using CreateProcessRoutine = BOOL(WINAPI *)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                            BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                            LPPROCESS_INFORMATION);
struct Launch {
    const Configuration *configuration = nullptr;
    LPCWSTR application = nullptr;
    LPWSTR commandLine = nullptr;
    LPCWSTR directory = nullptr;
    LPCWSTR environment = nullptr;
    DWORD flags = 0;
    HANDLE job = nullptr;
    BOOL inherit = FALSE;
    LPSECURITY_ATTRIBUTES processSecurity = nullptr;
    LPSECURITY_ATTRIBUTES threadSecurity = nullptr;
    LPSTARTUPINFOW startup = nullptr;
    LPPROCESS_INFORMATION process = nullptr;
    CreateProcessRoutine actual = nullptr;
    void *observerContext = nullptr;
    BOOL(WINAPI *beforeResume)(void *, const PROCESS_INFORMATION *) = nullptr;
};
BOOL WINAPI launch(const Launch *request);
std::wstring sessionMappingName(const std::wstring &nonce);
std::wstring sessionReadyName(const std::wstring &nonce);
}

#include "driverless/runtime/instrumentation.h"
#include <bcrypt.h>
#include <cwchar>

namespace nb::runtime {
namespace {
std::vector<wchar_t> environment(const wchar_t *provided, const std::wstring &nonce) {
    wchar_t *owned = provided ? nullptr : GetEnvironmentStringsW();
    auto block = provided ? provided : owned;
    if (!block)
        throw Error(GetLastError(), "Read launch environment");
    std::vector<wchar_t> result;
    try {
        for (auto cursor = block; *cursor;) {
            size_t size = wcsnlen(cursor, 32768);
            if (size >= 32768 || result.size() + size > 65000)
                throw Error(ERROR_ENVVAR_NOT_FOUND, "Launch environment exceeds the supported size");
            std::wstring entry(cursor, size);
            auto separator = entry.find(L'=', 1);
            if (!same(entry.substr(0, separator), L"NATIVEBOX_SESSION_MAP")) {
                result.insert(result.end(), entry.begin(), entry.end());
                result.push_back(0);
            }
            cursor += size + 1;
        }
        auto setting = L"NATIVEBOX_SESSION_MAP=" + nonce;
        result.insert(result.end(), setting.begin(), setting.end());
        result.push_back(0);
        result.push_back(0);
    } catch (...) {
        if (owned)
            FreeEnvironmentStringsW(owned);
        throw;
    }
    if (owned)
        FreeEnvironmentStringsW(owned);
    return result;
}
std::wstring randomNonce() {
    unsigned char bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw Error(ERROR_INTERNAL_ERROR, "Generate session nonce");
    static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring result;
    for (auto value : bytes) {
        result += hex[value >> 4];
        result += hex[value & 15];
    }
    return result;
}
void keepAlive(HANDLE target, HANDLE object) {
    HANDLE duplicate = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), object, target, &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS),
            "Keep session objects alive for the target");
}
}
std::wstring sessionMappingName(const std::wstring &nonce) {
    return L"Local\\NativeBox.Session." + nonce;
}
std::wstring sessionReadyName(const std::wstring &nonce) {
    return L"Local\\NativeBox.Ready." + nonce;
}
BOOL WINAPI launch(const Launch *request) {
    try {
        if (!request || !request->configuration || !request->application || !request->process ||
            !request->startup || request->configuration->magic != ProtocolMagic ||
            request->configuration->version != ProtocolVersion ||
            request->configuration->bytes != sizeof(Configuration))
            throw Error(ERROR_INVALID_PARAMETER, "Invalid runtime launch contract");
        const bool root = request->job != nullptr;
        if (root && ((request->flags &
                      (CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)) ||
                     request->startup->cb != sizeof(STARTUPINFOW) ||
                     (request->startup->dwFlags & STARTF_USESTDHANDLES)))
            throw Error(ERROR_NOT_SUPPORTED, "Unsupported root launch attributes");
        if (!root && request->startup->cb < sizeof(STARTUPINFOW))
            throw Error(ERROR_INVALID_PARAMETER, "Invalid child startup information");
        if (!root && (request->flags & EXTENDED_STARTUPINFO_PRESENT) &&
            request->startup->cb < sizeof(STARTUPINFOEXW))
            throw Error(ERROR_INVALID_PARAMETER, "Invalid extended child startup information");
        *request->process = {};
        struct PendingProcess {
            PROCESS_INFORMATION *value;
            bool committed = false;
            ~PendingProcess() {
                if (committed)
                    return;
                if (value->hProcess) {
                    TerminateProcess(value->hProcess, ERROR_DLL_INIT_FAILED);
                    WaitForSingleObject(value->hProcess, 5000);
                    CloseHandle(value->hProcess);
                }
                if (value->hThread)
                    CloseHandle(value->hThread);
                *value = {};
            }
        } pending{request->process};
        auto ownedConfiguration = std::make_unique<Configuration>(*request->configuration);
        auto &configuration = *ownedConfiguration;
        DWORD binary = 0;
        require(GetBinaryTypeW(request->application, &binary), "Inspect target architecture");
        if (binary != SCS_32BIT_BINARY && binary != SCS_64BIT_BINARY)
            throw Error(ERROR_NOT_SUPPORTED, "Unsupported executable architecture");
        configuration.architecture = binary == SCS_64BIT_BINARY ? 64 : 32;
        std::wstring selectedLibrary(configuration.runtimeDll);
        if (!selectedLibrary.ends_with(L"64.dll"))
            throw Error(ERROR_INVALID_PARAMETER,
                        "Runtime module naming does not permit architecture selection");
        if (configuration.architecture == 32)
            selectedLibrary.replace(selectedLibrary.size() - 6, 6, L"32.dll");
        auto expected = configuration.architecture == 32 ? configuration.sha32 : configuration.sha64;
        if (!memchr(expected, 0, 65) || strlen(expected) != 64 || sha256(selectedLibrary) != expected)
            throw Error(ERROR_INVALID_DATA, "Selected runtime bytes differ from the approved build");
        auto nonce = randomNonce();
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, sessionReadyName(nonce).c_str()));
        require(ready.get() != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
                "Create runtime startup event");
        configuration.readyEvent = 0;
        Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                          sizeof(Configuration), sessionMappingName(nonce).c_str()));
        require(mapping.get() != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
                "Create session configuration");
        auto memory = MapViewOfFile(mapping.get(), FILE_MAP_WRITE, 0, 0, sizeof(Configuration));
        if (!memory)
            throw Error(GetLastError(), "Map session configuration");
        memcpy(memory, &configuration, sizeof(configuration));
        UnmapViewOfFile(memory);
        auto block = environment(request->environment, nonce);
        std::vector<char> library(8192);
        BOOL substituted = FALSE;
        auto characters = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, selectedLibrary.c_str(), -1,
                                              library.data(), int(library.size()), nullptr, &substituted);
        if (!characters || substituted)
            throw Error(ERROR_NO_UNICODE_TRANSLATION,
                        "Detours DLL path cannot be represented in the active code page");
        auto actual = request->actual ? request->actual : ::CreateProcessW;
        const bool callerSuspended = !root && (request->flags & CREATE_SUSPENDED);
        BOOL created = FALSE;
        if (root) {
            SIZE_T size = 0;
            InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
            if (!size || size > 65536)
                throw Error(ERROR_INVALID_DATA, "Invalid startup attribute allocation size");
            std::vector<BYTE> bytes(size);
            auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());
            require(InitializeProcThreadAttributeList(attributes, 1, 0, &size),
                    "Prepare controlled launch attributes");
            struct Attributes {
                LPPROC_THREAD_ATTRIBUTE_LIST value;
                ~Attributes() { DeleteProcThreadAttributeList(value); }
            } release{attributes};
            HANDLE job = request->job;
            require(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job,
                                              sizeof(job), nullptr, nullptr),
                    "Assign job before target execution");
            STARTUPINFOEXW startup{};
            startup.StartupInfo = *request->startup;
            startup.StartupInfo.cb = sizeof(startup);
            startup.lpAttributeList = attributes;
            created = DetourCreateProcessWithDllExW(
                request->application, request->commandLine, nullptr, nullptr, FALSE,
                request->flags | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                block.data(), request->directory, &startup.StartupInfo, request->process, library.data(),
                actual);
        } else {
            created = DetourCreateProcessWithDllExW(
                request->application, request->commandLine, request->processSecurity, request->threadSecurity,
                request->inherit, request->flags | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                block.data(), request->directory, request->startup, request->process, library.data(), actual);
        }
        auto code = GetLastError();
        if (created) {
            keepAlive(request->process->hProcess, mapping.get());
            keepAlive(request->process->hProcess, ready.get());
            if (root && request->beforeResume && !request->beforeResume(request->observerContext, request->process))
                throw Error(GetLastError(), "Register system observer before target execution");
            if (callerSuspended) {
                pending.committed = true;
                return TRUE;
            }
            if (ResumeThread(request->process->hThread) != DWORD(-1)) {
                HANDLE waits[]{ready.get(), request->process->hProcess};
                auto wait = WaitForMultipleObjects(2, waits, FALSE, 15000);
                if (wait == WAIT_OBJECT_0) {
                    pending.committed = true;
                    return TRUE;
                }
                code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_DLL_INIT_FAILED;
            } else
                code = GetLastError();
        }
        throw Error(code, "Instrumented startup failed without fallback");
    } catch (const Error &error) {
        SetLastError(error.code);
        return FALSE;
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}
}
extern "C" BOOL WINAPI NativeBoxLaunchW(const nb::runtime::Launch *request) {
    return nb::runtime::launch(request);
}

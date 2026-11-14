#include "driverless/runtime/telemetry.h"

namespace nb::runtime {
namespace {
std::string quoted(const std::wstring &value) {
    auto length = int(std::min<size_t>(value.size(), 32760));
    int count = WideCharToMultiByte(CP_UTF8, 0, value.data(), length, nullptr, 0, nullptr, nullptr);
    if (!count && length)
        throw Error(ERROR_NO_UNICODE_TRANSLATION, "Encode runtime event");
    std::string bytes(size_t(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), length, bytes.data(), count, nullptr, nullptr);
    std::string result = "\"";
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char byte : bytes) {
        if (byte == '"' || byte == '\\') {
            result += '\\';
            result += char(byte);
        } else if (byte < 32) {
            result += "\\u00";
            result += digits[byte >> 4];
            result += digits[byte & 15];
        } else
            result += char(byte);
    }
    return result + '"';
}
struct TraceState {
    CRITICAL_SECTION lock{};
    std::unique_ptr<Handle> file;
    std::wstring root, basename;
    uint64_t creation = 0;
    uint64_t count = 0, bytes = 0, segment = 0;
    bool failed = false;
    explicit TraceState(const Configuration &configuration) {
        require(InitializeCriticalSectionEx(&lock, 4000, CRITICAL_SECTION_NO_DEBUG_INFO),
                "Initialize runtime trace lock");
        FILETIME start{}, exit{}, kernel{}, user{};
        require(GetProcessTimes(GetCurrentProcess(), &start, &exit, &kernel, &user),
                "Read trace process identity");
        creation = (uint64_t(start.dwHighDateTime) << 32) | start.dwLowDateTime;
        root =
            std::filesystem::path(canonical(configuration.dataRoot)).parent_path().wstring() + L"\\telemetry";
        directories(root);
        noReparse(root);
        basename = std::wstring(configuration.runId) + L"_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                   std::to_wstring(creation);
        open();
    }
    void open() {
        auto suffix = segment ? L"_" + std::to_wstring(segment) : L"";
        auto next = std::make_unique<Handle>(
            CreateFileW(extendedPath(root + L"\\" + basename + suffix + L".jsonl").c_str(), FILE_APPEND_DATA,
                        FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        require(next->get() != INVALID_HANDLE_VALUE, "Create runtime trace segment");
        file = std::move(next);
        bytes = 0;
    }
};
struct TraceLock {
    CRITICAL_SECTION &value;
    explicit TraceLock(CRITICAL_SECTION &lock) noexcept : value(lock) { EnterCriticalSection(&value); }
    ~TraceLock() { LeaveCriticalSection(&value); }
};
struct PreserveErrors {
    DWORD error = GetLastError();
    int socketError = WSAGetLastError();
    ~PreserveErrors() {
        WSASetLastError(socketError);
        SetLastError(error);
    }
};
}
void trace(const Configuration &configuration, const char *category, const char *operation,
           const std::wstring &path, DWORD result) noexcept {
    PreserveErrors errors;
    // Logging must never instrument its own I/O, including callers that do not already hold the hook guard.
    static thread_local bool tracing = false;
    if (tracing)
        return;
    tracing = true;
    struct Reset {
        bool &flag;
        ~Reset() { flag = false; }
    } reset{tracing};
    try {
        // Host threads may still enter hooks while the CRT runs DLL_PROCESS_DETACH. Keep the lock and
        // handle alive until the OS tears down the process, just like the runtime handle tables.
        static TraceState *statePointer = [&]() noexcept -> TraceState * {
            try {
                return new TraceState(configuration);
            } catch (...) {
                return nullptr;
            }
        }();
        if (!statePointer)
            return;
        auto &state = *statePointer;
        TraceLock lock(state.lock);
        if (state.failed)
            return;
        // Retain all raw segments. The broker can import them incrementally without blocking the
        // application on a single enormous file or silently dropping events after a call count.
        if (state.bytes >= 8 * 1024 * 1024) {
            ++state.segment;
            try {
                state.open();
            } catch (...) {
                state.failed = true;
                throw;
            }
        }
        FILETIME time{};
        GetSystemTimeAsFileTime(&time);
        auto timestamp = (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
        std::string row =
            "{\"schema\":1,\"source\":\"runtime_win32_hooks\",\"sandbox\":" +
            quoted(configuration.profileId) + ",\"runId\":" + quoted(configuration.runId) +
            ",\"pid\":" + std::to_string(GetCurrentProcessId()) +
            ",\"threadId\":" + std::to_string(GetCurrentThreadId()) + ",\"creationTime\":\"" +
            std::to_string(state.creation) + "\",\"fileTime\":\"" + std::to_string(timestamp) +
            "\",\"category\":\"" + category + "\",\"operation\":\"" + operation + "\",\"path\":" + quoted(path) +
            ",\"result\":" + std::to_string(result) + ",\"sequence\":" + std::to_string(state.count++) +
            ",\"segment\":" + std::to_string(state.segment) +
            ",\"pathTruncated\":" + (path.size() > 32760 ? "true" : "false") + "}\n";
        DWORD written = 0;
        if (row.size() > 256 * 1024 ||
            !WriteFile(state.file->get(), row.data(), DWORD(row.size()), &written, nullptr) ||
            written != row.size())
            state.failed = true;
        else
            state.bytes += written;
    } catch (...) {
    }
}
}

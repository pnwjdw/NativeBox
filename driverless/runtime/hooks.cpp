#include "driverless/runtime/instrumentation.h"
#include "driverless/runtime/files.h"
#include "driverless/runtime/registry.h"
#include "driverless/runtime/network.h"
#include "driverless/runtime/telemetry.h"
#include <wincred.h>
#include <mswsock.h>
#include <unordered_map>
#include <optional>
#include <cstddef>
#include <cwchar>

namespace nb::runtime {
namespace {
Configuration configuration;
thread_local unsigned recursion = 0;
struct Guard {
    Guard() { ++recursion; }
    ~Guard() { --recursion; }
};
auto realCreateFileW = &CreateFileW;
auto realCreateFileA = &CreateFileA;
auto realDeleteFileW = &DeleteFileW;
auto realCreateDirectoryW = &CreateDirectoryW;
auto realRemoveDirectoryW = &RemoveDirectoryW;
auto realMoveFileExW = &MoveFileExW;
auto realCopyFileW = &CopyFileW;
auto realGetFileAttributesW = &GetFileAttributesW;
auto realGetFileAttributesExW = &GetFileAttributesExW;
auto realSetFileAttributesW = &SetFileAttributesW;
auto realReplaceFileW = &ReplaceFileW;
auto realFindFirstFileW = &FindFirstFileW;
auto realMoveFileW = &MoveFileW;
auto realFindFirstFileExW = &FindFirstFileExW;
auto realFindNextFileW = &FindNextFileW;
auto realFindClose = &FindClose;
auto realCloseHandle = &CloseHandle;
auto realSetFileInformationByHandle = &SetFileInformationByHandle;
auto realReadFile = &ReadFile;
auto realWriteFile = &WriteFile;
auto realFlushFileBuffers = &FlushFileBuffers;
auto realRegOpenKeyExW = &RegOpenKeyExW;
auto realRegCreateKeyExW = &RegCreateKeyExW;
auto realRegDeleteKeyExW = &RegDeleteKeyExW;
auto realRegDeleteKeyW = &RegDeleteKeyW;
auto realRegDeleteTreeW = &RegDeleteTreeW;
auto realRegCloseKey = &RegCloseKey;
auto realRegSetValueExW = &RegSetValueExW;
auto realRegQueryValueExW = &RegQueryValueExW;
auto realRegDeleteValueW = &RegDeleteValueW;
auto realRegEnumKeyExW = &RegEnumKeyExW;
auto realRegEnumKeyW = &RegEnumKeyW;
auto realRegQueryInfoKeyW = &RegQueryInfoKeyW;
auto realRegOpenCurrentUser = &RegOpenCurrentUser;
auto realRegGetValueW = &RegGetValueW;
auto realRegSetKeyValueW = &RegSetKeyValueW;
auto realRegDeleteKeyValueW = &RegDeleteKeyValueW;
auto realRegOpenKeyExA = &RegOpenKeyExA;
auto realRegCreateKeyExA = &RegCreateKeyExA;
auto realRegDeleteKeyExA = &RegDeleteKeyExA;
auto realRegDeleteKeyA = &RegDeleteKeyA;
auto realRegDeleteTreeA = &RegDeleteTreeA;
auto realRegSetValueExA = &RegSetValueExA;
auto realRegQueryValueExA = &RegQueryValueExA;
auto realRegDeleteValueA = &RegDeleteValueA;
auto realRegEnumKeyExA = &RegEnumKeyExA;
auto realRegQueryInfoKeyA = &RegQueryInfoKeyA;
auto realRegGetValueA = &RegGetValueA;
auto realRegConnectRegistryW = &RegConnectRegistryW;
auto realRegConnectRegistryA = &RegConnectRegistryA;
auto realCreateProcessW = &CreateProcessW;
auto realCreateProcessA = &CreateProcessA;
auto realSocket = &socket;
auto realWSASocketW = &WSASocketW;
using SocketARoutine = SOCKET(WSAAPI *)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
SocketARoutine realWSASocketA = nullptr;
auto realConnect = &connect;
auto realWSAConnect = &WSAConnect;
auto realIoctlSocket = &ioctlsocket;
auto realWSAIoctl = &WSAIoctl;
auto realSendTo = &sendto;
auto realWSASendTo = &WSASendTo;
auto realWSAEventSelect = &WSAEventSelect;
using AsyncSelectRoutine = int(WSAAPI *)(SOCKET, HWND, unsigned, long);
AsyncSelectRoutine realWSAAsyncSelect = nullptr;
struct KeyLocation {
    wchar_t root = 0; // U, M, C or 0 for untracked handles
    std::wstring path;
    unsigned view = sizeof(void *) == 8 ? 64u : 32u;
    bool isPrivate = false;
    bool predefined = false;
    bool namesReady = false;
    std::vector<std::wstring> names;
};
struct Search {
    std::vector<WIN32_FIND_DATAW> entries;
    size_t index = 0;
};
// Handle tables live for the whole process lifetime and are never destroyed: host threads may still close
// handles while the loader runs DLL_PROCESS_DETACH. The critical section is re-entrant and never throws, so a
// hook can never escalate into std::terminate inside the host process.
struct Tracked {
    std::wstring path;
    FileStore *store = nullptr;
    bool mutation = false;
};
struct HandleTables {
    CRITICAL_SECTION lock;
    std::unordered_map<HANDLE, Tracked> fileHandles;
    std::unordered_map<HKEY, KeyLocation> keyHandles;
    std::unordered_map<HANDLE, Search> searches;
    HandleTables() { InitializeCriticalSectionEx(&lock, 4000, CRITICAL_SECTION_NO_DEBUG_INFO); }
};
HandleTables &tables = *new HandleTables;
auto &fileHandles = tables.fileHandles;
auto &keyHandles = tables.keyHandles;
auto &searches = tables.searches;
class HandlesLock {
    bool held = true;

  public:
    HandlesLock() noexcept { EnterCriticalSection(&tables.lock); }
    HandlesLock(const HandlesLock &) = delete;
    HandlesLock &operator=(const HandlesLock &) = delete;
    void unlock() noexcept {
        if (held) {
            held = false;
            LeaveCriticalSection(&tables.lock);
        }
    }
    ~HandlesLock() { unlock(); }
};
struct Engine {
    std::vector<std::unique_ptr<FileStore>> files;
    std::unique_ptr<RegistryStore> registry;
    Engine() {
        auto root = canonical(configuration.dataRoot);
        noReparse(root);
        for (uint32_t index = 0; index < configuration.fileRootCount; ++index)
            files.push_back(std::make_unique<FileStore>(configuration.fileRoots[index],
                                                        root + L"\\overlay\\" + std::to_wstring(index),
                                                        configuration.excludeRoot));
        if (configuration.registryRootCount || configuration.redirectAll)
            registry = std::make_unique<RegistryStore>(root + L"\\registry");
    }
};
Engine &engine() {
    static std::once_flag once;
    static Engine *value = nullptr;
    std::call_once(once, [] { value = new Engine; });
    return *value;
}
bool mayBeCovered(const std::wstring &input) {
    auto value = input;
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.starts_with(L"\\\\?\\") || value.starts_with(L"\\??\\")) {
        if (value.size() < 7 || !iswalpha(value[4]) || value[5] != L':' || value[6] != L'\\')
            return false;
        value.erase(0, 4);
    }
    DWORD size = GetFullPathNameW(value.c_str(), 0, nullptr, nullptr);
    if (!size || size > 32760)
        return true;
    std::vector<wchar_t> storage(size + 1);
    auto count = GetFullPathNameW(value.c_str(), DWORD(storage.size()), storage.data(), nullptr);
    if (!count || count >= storage.size())
        return true;
    std::wstring full(storage.data(), count);
    if (full.size() < 3 || full[1] != L':' || full[2] != L'\\')
        return false;
    auto stream = full.find(L':', 2);
    if (stream != std::wstring::npos)
        full.resize(stream);
    while (full.size() > 3 && (full.back() == L'\\' || full.back() == L'.' || full.back() == L' '))
        full.pop_back();
    if (full.find(L'~') != std::wstring::npos)
        full = longForm(full);
    for (const auto &store : engine().files)
        if (beneath(full, store->logicalRoot()))
            return true;
    return false;
}
bool dosDevice(const std::wstring &path) {
    // Extended drive paths can address literal files named NUL, so only the ordinary
    // DOS namespace gets this exception. Device I/O must retain the host's semantics.
    if (path.starts_with(L"\\\\?\\") || path.starts_with(L"\\??\\"))
        return false;
    auto name = std::filesystem::path(path).filename().wstring();
    auto stem = name.substr(0, name.find_first_of(L".:"));
    return same(stem, L"CON") || same(stem, L"PRN") || same(stem, L"AUX") || same(stem, L"NUL") ||
           same(name, L"CONIN$") || same(name, L"CONOUT$") ||
           (stem.size() == 4 && (same(stem.substr(0, 3), L"COM") || same(stem.substr(0, 3), L"LPT")) &&
            ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == 0xB9 || stem[3] == 0xB2 || stem[3] == 0xB3));
}
FileStore *fileStore(LPCWSTR path) {
    if (!path)
        throw Error(ERROR_INVALID_PARAMETER, "Null file path");
    std::wstring value(path);
    if (dosDevice(value))
        return nullptr;
    if (value.starts_with(L"\\\\") && !value.starts_with(L"\\\\?\\"))
        return nullptr;
    if (value.starts_with(L"\\\\?\\") || value.starts_with(L"\\??\\")) {
        // pipes, UNC shares, GLOBALROOT and volume GUID paths are not redirected drive paths
        if (value.size() < 7 || !iswalpha(value[4]) || value[5] != L':' || value[6] != L'\\')
            return nullptr;
    }
    std::wstring normalized;
    try {
        normalized = canonical(value);
    } catch (const Error &error) {
        // Names Windows itself rejects (wildcards, quotes, control characters) cannot create anything:
        // let the original API report its usual error.
        auto invalid = value.find_first_of(L"*?\"<>|") != std::wstring::npos ||
                       std::any_of(value.begin(), value.end(), [](wchar_t c) { return c < 32; });
        if (invalid || !mayBeCovered(value))
            return nullptr;
        trace(configuration, "file", "unsupported_path", value, error.code);
        throw;
    }
    if (configuration.excludeRoot[0]) {
        // The backing store is excluded to prevent recursive overlays, not to expose
        // the manager database or the physical files belonging to other sandboxes.
        static const auto &excluded = *new std::wstring(canonical(configuration.excludeRoot));
        static const auto &owned = *new std::wstring(
            std::filesystem::path(canonical(configuration.dataRoot)).parent_path().wstring());
        if (beneath(normalized, excluded) && !beneath(normalized, owned)) {
            trace(configuration, "file", "foreign_sandbox_storage_denied", normalized, ERROR_ACCESS_DENIED);
            throw Error(ERROR_ACCESS_DENIED, "Other sandbox storage is unavailable");
        }
    }
    for (const auto &store : engine().files)
        if (store->covers(normalized))
            return store.get();
    return nullptr;
}
std::wstring wide(LPCSTR input) {
    if (!input)
        throw Error(ERROR_INVALID_PARAMETER, "Null ANSI argument");
    auto page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    int size = MultiByteToWideChar(page, 0, input, -1, nullptr, 0);
    if (!size || size > 32768)
        throw Error(ERROR_NO_UNICODE_TRANSLATION, "Invalid ANSI file path");
    std::wstring result(size_t(size), L'\0');
    require(MultiByteToWideChar(page, 0, input, -1, result.data(), size) == size, "Decode ANSI file path");
    result.pop_back();
    return result;
}
template <class Function, class Result> Result fileCall(Function &&call, Result failure) noexcept {
    Guard guard;
    try {
        return call();
    } catch (const Error &error) {
        SetLastError(error.code);
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    return failure;
}
HANDLE WINAPI createFileW(LPCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
                          DWORD disposition, DWORD flags, HANDLE templateFile) {
    if (recursion)
        return realCreateFileW(path, access, share, security, disposition, flags, templateFile);
    return fileCall(
        [&] {
            auto store = fileStore(path);
            HANDLE result =
                store ? store->open(path, access, share, security, disposition, flags, templateFile)
                      : realCreateFileW(path, access, share, security, disposition, flags, templateFile);
            if (store && result != INVALID_HANDLE_VALUE) {
                auto code = GetLastError();
                try {
                    Tracked entry{canonical(path), store, FileStore::mutates(access, disposition, flags)};
                    HandlesLock lock;
                    fileHandles[result] = std::move(entry);
                } catch (...) {
                    realCloseHandle(result);
                    throw;
                }
                SetLastError(code);
            }
            if (store)
                trace(configuration, "file", "CreateFileW", path,
                      result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS);
            return result;
        },
        INVALID_HANDLE_VALUE);
}
void traceHandle(HANDLE handle, const char *operation, DWORD code) noexcept {
    // Looking up/copying a tracked path may itself call Win32. Preserve the result of the
    // caller's I/O operation, especially ERROR_IO_PENDING for overlapped reads and writes.
    const DWORD error = GetLastError();
    try {
        std::wstring path;
        bool tracked = false;
        {
            HandlesLock lock;
            auto found = fileHandles.find(handle);
            if (found != fileHandles.end()) {
                path = found->second.path;
                tracked = true;
            }
        }
        if (tracked)
            trace(configuration, "file", operation, path, code);
    } catch (...) {
    }
    SetLastError(error);
}
BOOL WINAPI readFile(HANDLE handle, LPVOID data, DWORD bytes, LPDWORD count, LPOVERLAPPED overlapped) {
    if (recursion)
        return realReadFile(handle, data, bytes, count, overlapped);
    Guard guard;
    BOOL result = realReadFile(handle, data, bytes, count, overlapped);
    traceHandle(handle, "ReadFile", result ? ERROR_SUCCESS : GetLastError());
    return result;
}
BOOL WINAPI writeFile(HANDLE handle, LPCVOID data, DWORD bytes, LPDWORD count, LPOVERLAPPED overlapped) {
    if (recursion)
        return realWriteFile(handle, data, bytes, count, overlapped);
    Guard guard;
    BOOL result = realWriteFile(handle, data, bytes, count, overlapped);
    traceHandle(handle, "WriteFile", result ? ERROR_SUCCESS : GetLastError());
    return result;
}
BOOL WINAPI flushFileBuffers(HANDLE handle) {
    if (recursion)
        return realFlushFileBuffers(handle);
    Guard guard;
    BOOL result = realFlushFileBuffers(handle);
    traceHandle(handle, "FlushFileBuffers", result ? ERROR_SUCCESS : GetLastError());
    return result;
}
HANDLE WINAPI createFileA(LPCSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
                          DWORD disposition, DWORD flags, HANDLE templateFile) {
    if (recursion)
        return realCreateFileA(path, access, share, security, disposition, flags, templateFile);
    try {
        auto converted = wide(path);
        return createFileW(converted.c_str(), access, share, security, disposition, flags, templateFile);
    } catch (const Error &error) {
        SetLastError(error.code);
        return INVALID_HANDLE_VALUE;
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }
}
BOOL WINAPI deleteFileW(LPCWSTR path) {
    if (recursion)
        return realDeleteFileW(path);
    return fileCall(
        [&]() -> BOOL {
            auto store = fileStore(path);
            if (!store)
                return realDeleteFileW(path);
            store->remove(path, false);
            return TRUE;
        },
        FALSE);
}
BOOL WINAPI createDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES security) {
    if (recursion)
        return realCreateDirectoryW(path, security);
    return fileCall(
        [&]() -> BOOL {
            auto store = fileStore(path);
            if (!store)
                return realCreateDirectoryW(path, security);
            store->createDirectory(path, security);
            return TRUE;
        },
        FALSE);
}
BOOL WINAPI removeDirectoryW(LPCWSTR path) {
    if (recursion)
        return realRemoveDirectoryW(path);
    return fileCall(
        [&]() -> BOOL {
            auto store = fileStore(path);
            if (!store)
                return realRemoveDirectoryW(path);
            store->remove(path, true);
            return TRUE;
        },
        FALSE);
}
void crossMove(LPCWSTR source, FileStore *from, LPCWSTR destination, FileStore *to, bool failIfExists) {
    auto physical = from ? from->resolve(source) : std::wstring(source);
    auto attributes = realGetFileAttributesW(physical.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
        throw Error(GetLastError(), "Inspect move source");
    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
        throw Error(ERROR_NOT_SAME_DEVICE, "Directories cannot move across sandbox scopes");
    if (to)
        to->importFile(physical, destination, failIfExists);
    else
        require(realCopyFileW(physical.c_str(), destination, failIfExists), "Move sandbox file outward");
    if (from)
        from->remove(source, false);
    else
        require(realDeleteFileW(source), "Complete move into sandbox");
}
BOOL WINAPI moveFileExW(LPCWSTR source, LPCWSTR destination, DWORD flags) {
    if (recursion)
        return realMoveFileExW(source, destination, flags);
    return fileCall(
        [&]() -> BOOL {
            auto from = fileStore(source), to = destination ? fileStore(destination) : nullptr;
            if (!from && !to)
                return realMoveFileExW(source, destination, flags);
            if (!destination) {
                // MOVEFILE_DELAY_UNTIL_REBOOT deletion request for a covered path: delete inside the sandbox
                // now.
                from->remove(source, false);
                return TRUE;
            }
            if (from && from == to) {
                from->rename(source, destination, flags);
                return TRUE;
            }
            crossMove(source, from, destination, to, (flags & MOVEFILE_REPLACE_EXISTING) == 0);
            return TRUE;
        },
        FALSE);
}
BOOL WINAPI copyFileW(LPCWSTR source, LPCWSTR destination, BOOL failIfExists) {
    if (recursion)
        return realCopyFileW(source, destination, failIfExists);
    return fileCall(
        [&]() -> BOOL {
            auto from = fileStore(source), to = fileStore(destination);
            if (!from && !to)
                return realCopyFileW(source, destination, failIfExists);
            if (from && from == to) {
                from->copy(source, destination, failIfExists != FALSE);
                return TRUE;
            }
            auto physical = from ? from->resolve(source) : std::wstring(source);
            if (to)
                to->importFile(physical, destination, failIfExists != FALSE);
            else
                require(realCopyFileW(physical.c_str(), destination, failIfExists),
                        "Copy sandbox file outward");
            return TRUE;
        },
        FALSE);
}
DWORD WINAPI getFileAttributesW(LPCWSTR path) {
    if (recursion)
        return realGetFileAttributesW(path);
    return fileCall(
        [&] {
            auto store = fileStore(path);
            return store ? store->attributes(path) : realGetFileAttributesW(path);
        },
        DWORD(INVALID_FILE_ATTRIBUTES));
}
BOOL WINAPI getFileAttributesExW(LPCWSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID result) {
    if (recursion)
        return realGetFileAttributesExW(path, level, result);
    return fileCall(
        [&]() -> BOOL {
            auto store = fileStore(path);
            if (!store)
                return realGetFileAttributesExW(path, level, result);
            if (level != GetFileExInfoStandard || !result)
                throw Error(ERROR_NOT_SUPPORTED, "Unsupported file metadata query");
            store->information(path, *static_cast<WIN32_FILE_ATTRIBUTE_DATA *>(result));
            return TRUE;
        },
        FALSE);
}
BOOL WINAPI setFileAttributesW(LPCWSTR path, DWORD attributes) {
    if (recursion)
        return realSetFileAttributesW(path, attributes);
    return fileCall(
        [&]() -> BOOL {
            auto store = fileStore(path);
            if (!store)
                return realSetFileAttributesW(path, attributes);
            store->setAttributes(path, attributes);
            return TRUE;
        },
        FALSE);
}
BOOL WINAPI replaceFileW(LPCWSTR replaced, LPCWSTR replacement, LPCWSTR backup, DWORD flags, LPVOID exclude,
                         LPVOID reserved) {
    if (recursion)
        return realReplaceFileW(replaced, replacement, backup, flags, exclude, reserved);
    return fileCall(
        [&]() -> BOOL {
            auto target = fileStore(replaced), source = fileStore(replacement);
            auto saved = backup ? fileStore(backup) : nullptr;
            if (!target && !source && !saved)
                return realReplaceFileW(replaced, replacement, backup, flags, exclude, reserved);
            if (!target || target != source || (backup && saved != target))
                throw Error(ERROR_UNABLE_TO_MOVE_REPLACEMENT, "ReplaceFile across sandbox scopes");
            target->replace(replaced, replacement, backup ? std::wstring(backup) : std::wstring());
            return TRUE;
        },
        FALSE);
}
HANDLE WINAPI findFirstFileExW(LPCWSTR input, FINDEX_INFO_LEVELS level, LPVOID result,
                               FINDEX_SEARCH_OPS search, LPVOID filter, DWORD flags) {
    if (recursion)
        return realFindFirstFileExW(input, level, result, search, filter, flags);
    return fileCall(
        [&]() -> HANDLE {
            if (!input)
                throw Error(ERROR_INVALID_PARAMETER, "Null enumeration input");
            std::wstring path(input);
            auto separator = path.find_last_of(L"\\/");
            if (separator == std::wstring::npos)
                path = L".\\" + path;
            separator = path.find_last_of(L"\\/");
            auto directory = path.substr(0, separator), pattern = path.substr(separator + 1);
            auto store = fileStore(directory.c_str());
            if (!store)
                return realFindFirstFileExW(input, level, result, search, filter, flags);
            if ((level != FindExInfoStandard && level != FindExInfoBasic) ||
                (search != FindExSearchNameMatch && search != FindExSearchLimitToDirectories) || filter ||
                flags & ~(FIND_FIRST_EX_LARGE_FETCH | FIND_FIRST_EX_CASE_SENSITIVE |
                          FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY) ||
                !result)
                throw Error(ERROR_NOT_SUPPORTED, "Unsupported merged enumeration semantics");
            auto entries = store->enumerate(directory, pattern);
            if (entries.empty())
                throw Error(ERROR_FILE_NOT_FOUND, "No matching logical directory entries");
            Handle identity(CreateEventW(nullptr, FALSE, FALSE, nullptr));
            require(identity.get() != nullptr, "Create merged enumeration identity");
            *static_cast<WIN32_FIND_DATAW *>(result) = entries.front();
            HandlesLock lock;
            searches.emplace(identity.get(), Search{std::move(entries), 1});
            return identity.release();
        },
        INVALID_HANDLE_VALUE);
}
BOOL WINAPI findNextFileW(HANDLE handle, LPWIN32_FIND_DATAW result) {
    if (recursion)
        return realFindNextFileW(handle, result);
    return fileCall(
        [&]() -> BOOL {
            HandlesLock lock;
            auto found = searches.find(handle);
            if (found == searches.end()) {
                lock.unlock();
                return realFindNextFileW(handle, result);
            }
            if (!result)
                throw Error(ERROR_INVALID_PARAMETER, "Null enumeration result");
            if (found->second.index >= found->second.entries.size())
                throw Error(ERROR_NO_MORE_FILES, "End of merged enumeration");
            *result = found->second.entries[found->second.index++];
            return TRUE;
        },
        FALSE);
}
HANDLE WINAPI findFirstFileW(LPCWSTR path, LPWIN32_FIND_DATAW result) {
    return recursion ? realFindFirstFileW(path, result)
                     : findFirstFileExW(path, FindExInfoStandard, result, FindExSearchNameMatch, nullptr, 0);
}
BOOL WINAPI moveFileW(LPCWSTR source, LPCWSTR destination) {
    return recursion ? realMoveFileW(source, destination) : moveFileExW(source, destination, 0);
}
BOOL WINAPI findClose(HANDLE handle) {
    if (recursion)
        return realFindClose(handle);
    Guard guard;
    bool merged = false;
    try {
        HandlesLock lock;
        merged = searches.erase(handle) != 0;
    } catch (...) {
    }
    return merged ? realCloseHandle(handle) : realFindClose(handle);
}
std::optional<Tracked> trackedHandle(HANDLE handle, bool remove) noexcept {
    try {
        HandlesLock lock;
        auto found = fileHandles.find(handle);
        if (found == fileHandles.end())
            return std::nullopt;
        std::optional<Tracked> result(std::move(found->second));
        if (remove)
            fileHandles.erase(found);
        else
            found->second = *result;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}
BOOL WINAPI closeHandle(HANDLE handle) {
    if (recursion)
        return realCloseHandle(handle);
    Guard guard;
    auto entry = trackedHandle(handle, true);
    BOOL result = realCloseHandle(handle);
    if (entry && entry->mutation) {
        DWORD code = GetLastError();
        try {
            entry->store->reconcile(entry->path);
        } catch (...) {
        }
        SetLastError(code);
    }
    return result;
}
std::wstring renameTarget(const FILE_RENAME_INFO *rename, DWORD size, const std::wstring &current) {
    constexpr auto header = offsetof(FILE_RENAME_INFO, FileName);
    if (size < header || rename->FileNameLength % sizeof(wchar_t) || rename->FileNameLength > size - header)
        throw Error(ERROR_INVALID_PARAMETER, "Invalid rename information");
    std::wstring name(rename->FileName, rename->FileNameLength / sizeof(wchar_t));
    if (name.starts_with(L"\\??\\"))
        return name.substr(4);
    if (name.find(L'\\') == std::wstring::npos && !current.empty())
        return std::filesystem::path(current).parent_path().wstring() + L"\\" + name;
    return name;
}
BOOL WINAPI setFileInformation(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID info, DWORD size) {
    if (recursion || (kind != FileRenameInfo && kind != FileRenameInfoEx))
        return realSetFileInformationByHandle(handle, kind, info, size);
    return fileCall(
        [&]() -> BOOL {
            if (!info)
                throw Error(ERROR_INVALID_PARAMETER, "Null rename information");
            auto rename = static_cast<const FILE_RENAME_INFO *>(info);
            auto entry = trackedHandle(handle, false);
            auto target = renameTarget(rename, size, entry ? entry->path : std::wstring());
            auto destination = rename->RootDirectory ? nullptr : fileStore(target.c_str());
            if (!entry && !destination && !rename->RootDirectory)
                return realSetFileInformationByHandle(handle, kind, info, size);
            if (!entry) {
                if (rename->RootDirectory)
                    return realSetFileInformationByHandle(handle, kind, info, size);
                throw Error(ERROR_NOT_SAME_DEVICE, "Handle rename into a sandbox scope");
            }
            if (rename->RootDirectory || destination != entry->store)
                throw Error(ERROR_NOT_SAME_DEVICE, "Handle rename across sandbox scopes");
            bool replace = kind == FileRenameInfoEx
                               ? (rename->Flags & FILE_RENAME_FLAG_REPLACE_IF_EXISTS) != 0
                               : rename->ReplaceIfExists != FALSE;
            if (!replace && destination->attributes(target) != INVALID_FILE_ATTRIBUTES)
                throw Error(ERROR_ALREADY_EXISTS, "Logical rename destination exists");
            auto physical = L"\\??\\" + canonical(destination->prepareTarget(target));
            constexpr auto header = offsetof(FILE_RENAME_INFO, FileName);
            std::vector<BYTE> storage(header + (physical.size() + 1) * sizeof(wchar_t));
            auto rewritten = reinterpret_cast<FILE_RENAME_INFO *>(storage.data());
            memcpy(rewritten, rename, header);
            if (kind == FileRenameInfoEx)
                rewritten->Flags = rename->Flags | (replace ? FILE_RENAME_FLAG_REPLACE_IF_EXISTS : 0);
            else
                rewritten->ReplaceIfExists = TRUE;
            rewritten->RootDirectory = nullptr;
            rewritten->FileNameLength = DWORD(physical.size() * sizeof(wchar_t));
            memcpy(rewritten->FileName, physical.c_str(), (physical.size() + 1) * sizeof(wchar_t));
            if (!realSetFileInformationByHandle(handle, kind, rewritten, DWORD(storage.size())))
                throw Error(GetLastError(), "Rename private file by handle");
            destination->committed(entry->path, target);
            try {
                HandlesLock lock;
                auto found = fileHandles.find(handle);
                if (found != fileHandles.end()) {
                    found->second.path = canonical(target);
                    found->second.mutation = true;
                }
            } catch (...) {
            }
            trace(configuration, "file", "SetFileInformationByHandle", target, ERROR_SUCCESS);
            return TRUE;
        },
        FALSE);
}
bool windows64() {
    static const bool value = [] {
        if (sizeof(void *) == 8)
            return true;
        BOOL wow = FALSE;
        return IsWow64Process(GetCurrentProcess(), &wow) && wow;
    }();
    return value;
}
wchar_t predefinedRoot(HKEY key) {
    if (key == HKEY_CURRENT_USER)
        return L'U';
    if (key == HKEY_LOCAL_MACHINE)
        return L'M';
    if (key == HKEY_CLASSES_ROOT)
        return L'C';
    return 0;
}
// HKLM paths are stored by their physical 64-bit location so 32-bit and 64-bit processes share one view.
std::wstring machinePath(const std::wstring &path, unsigned view) {
    if (view != 32 || !windows64())
        return path;
    auto separator = path.find(L'\\');
    auto first = path.substr(0, separator);
    if (!same(first, L"Software"))
        return path;
    auto rest = separator == std::wstring::npos ? std::wstring() : path.substr(separator + 1);
    auto second = rest.substr(0, rest.find(L'\\'));
    if (same(second, L"WOW6432Node") || same(second, L"Classes"))
        return path;
    return first + L"\\WOW6432Node" + (rest.empty() ? L"" : L"\\" + rest);
}
KeyLocation location(HKEY key, LPCWSTR subkey, REGSAM access) {
    KeyLocation value;
    if (auto root = predefinedRoot(key)) {
        value.root = root;
        value.predefined = true;
    } else {
        HandlesLock lock;
        auto found = keyHandles.find(key);
        if (found == keyHandles.end())
            return {};
        value.root = found->second.root;
        value.path = found->second.path;
        value.view = found->second.view;
        value.isPrivate = found->second.isPrivate;
    }
    if (access & KEY_WOW64_32KEY)
        value.view = 32;
    else if (access & KEY_WOW64_64KEY)
        value.view = 64;
    std::wstring extra = subkey ? subkey : L"";
    while (!extra.empty() && extra.back() == L'\\')
        extra.pop_back();
    if (!extra.empty()) {
        bool fromRoot = value.predefined;
        value.path += (value.path.empty() ? L"" : L"\\") + extra;
        value.isPrivate = false;
        value.predefined = false;
        if (fromRoot && value.root == L'M')
            value.path = machinePath(value.path, value.view);
    }
    return value;
}
RegistryStore *registryStore() {
    return engine().registry.get();
}
bool covered(const KeyLocation &value) {
    if (!value.root || !registryStore())
        return false;
    if (configuration.redirectAll)
        return true;
    for (uint32_t index = 0; index < configuration.registryRootCount; ++index) {
        const auto &scope = configuration.registryRoots[index];
        if ((scope.root == 1 ? L'U' : L'M') == value.root && beneath(value.path, scope.prefix))
            return true;
    }
    return false;
}
RegistryPath registryPath(const KeyLocation &value) {
    return {value.root, value.path, REGSAM(value.view == 32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY)};
}
bool traceReads() {
    return !configuration.redirectAll;
}
template <class Call> LSTATUS registryCall(Call &&call) noexcept {
    Guard guard;
    try {
        return call();
    } catch (const Error &error) {
        return LSTATUS(error.code);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}
void trackKey(HKEY handle, KeyLocation value) {
    try {
        HandlesLock lock;
        keyHandles[handle] = std::move(value);
    } catch (...) {
        realRegCloseKey(handle);
        throw;
    }
}
LSTATUS openCovered(const KeyLocation &value, REGSAM access, bool create, DWORD *disposition, PHKEY result) {
    bool isPrivate = false;
    DWORD created = 0;
    try {
        *result = registryStore()->open(registryPath(value), access, create, &created, isPrivate);
    } catch (const Error &error) {
        if (error.code != ERROR_FILE_NOT_FOUND && error.code != ERROR_PATH_NOT_FOUND)
            trace(configuration, "registry", create ? "RegCreateKeyExW" : "RegOpenKeyExW",
                  std::wstring(1, value.root) + L":" + value.path, error.code);
        throw;
    }
    if (disposition)
        *disposition = created;
    auto tracked = value;
    tracked.isPrivate = isPrivate;
    tracked.predefined = false;
    trackKey(*result, std::move(tracked));
    if (create && created == REG_CREATED_NEW_KEY)
        trace(configuration, "registry", "RegCreateKeyExW", value.path, ERROR_SUCCESS);
    else if (traceReads())
        trace(configuration, "registry", create ? "RegCreateKeyExW" : "RegOpenKeyExW", value.path,
              ERROR_SUCCESS);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI regOpen(HKEY key, LPCWSTR path, DWORD options, REGSAM access, PHKEY result) {
    if (recursion)
        return realRegOpenKeyExW(key, path, options, access, result);
    return registryCall([&]() -> LSTATUS {
        if (!result)
            return ERROR_INVALID_PARAMETER;
        auto value = location(key, path, access);
        if (covered(value))
            return openCovered(value, access, false, nullptr, result);
        auto code = realRegOpenKeyExW(key, path, options, access, result);
        if (code == ERROR_SUCCESS && value.root) {
            value.isPrivate = false;
            value.predefined = false;
            trackKey(*result, std::move(value));
        }
        return code;
    });
}
LSTATUS WINAPI regCreate(HKEY key, LPCWSTR path, DWORD reserved, LPWSTR keyClass, DWORD options,
                         REGSAM access, const LPSECURITY_ATTRIBUTES security, PHKEY result,
                         LPDWORD disposition) {
    if (recursion)
        return realRegCreateKeyExW(key, path, reserved, keyClass, options, access, security, result,
                                   disposition);
    return registryCall([&]() -> LSTATUS {
        if (!result)
            return ERROR_INVALID_PARAMETER;
        auto value = location(key, path, access);
        if (covered(value)) {
            if (options & REG_OPTION_CREATE_LINK)
                return ERROR_ACCESS_DENIED;
            return openCovered(value, access, true, disposition, result);
        }
        auto code = realRegCreateKeyExW(key, path, reserved, keyClass, options, access, security, result,
                                        disposition);
        if (code == ERROR_SUCCESS && value.root) {
            value.isPrivate = false;
            value.predefined = false;
            trackKey(*result, std::move(value));
        }
        return code;
    });
}
LSTATUS regRemove(HKEY key, LPCWSTR path, REGSAM access, DWORD reserved, bool recursive) {
    return registryCall([&]() -> LSTATUS {
        auto value = location(key, path, access);
        if (!covered(value))
            return recursive ? realRegDeleteTreeW(key, path)
                             : realRegDeleteKeyExW(key, path, access, reserved);
        if (recursive && (!path || !*path))
            registryStore()->clearTree(registryPath(value));
        else if (recursive)
            registryStore()->removeTree(registryPath(value));
        else
            registryStore()->removeKey(registryPath(value));
        trace(configuration, "registry", recursive ? "RegDeleteTreeW" : "RegDeleteKeyW", value.path,
              ERROR_SUCCESS);
        return ERROR_SUCCESS;
    });
}
LSTATUS WINAPI regDeleteEx(HKEY key, LPCWSTR path, REGSAM access, DWORD reserved) {
    return recursion ? realRegDeleteKeyExW(key, path, access, reserved)
                     : regRemove(key, path, access, reserved, false);
}
LSTATUS WINAPI regDelete(HKEY key, LPCWSTR path) {
    return recursion ? realRegDeleteKeyW(key, path) : regRemove(key, path, 0, 0, false);
}
LSTATUS WINAPI regDeleteTree(HKEY key, LPCWSTR path) {
    return recursion ? realRegDeleteTreeW(key, path) : regRemove(key, path, 0, 0, true);
}
LSTATUS WINAPI regClose(HKEY key) {
    if (!recursion) {
        Guard guard;
        try {
            HandlesLock lock;
            keyHandles.erase(key);
        } catch (...) {
        }
    }
    return realRegCloseKey(key);
}
// Value operations on a predefined root (e.g. RegSetValueExW(HKEY_CURRENT_USER, ...)) use the private root.
HKEY valueKey(HKEY key, bool write, Key &owned) {
    auto root = predefinedRoot(key);
    if (!root)
        return key;
    auto value = location(key, nullptr, 0);
    if (!covered(value))
        return key;
    auto path = registryPath(value);
    if (!write && !registryStore()->hasPrivate(path))
        return key;
    bool isPrivate = false;
    owned = Key(registryStore()->open(path, write ? KEY_ALL_ACCESS : KEY_READ, write, nullptr, isPrivate));
    return owned.get();
}
void traceKey(HKEY key, LPCWSTR name, const char *operation, LSTATUS code, bool write) noexcept {
    try {
        if (!write && !traceReads())
            return;
        auto value = location(key, name, 0);
        if (covered(value))
            trace(configuration, "registry", operation, value.path, DWORD(code));
    } catch (...) {
    }
}
LSTATUS WINAPI regSetValue(HKEY key, LPCWSTR name, DWORD reserved, DWORD type, const BYTE *data, DWORD size) {
    if (recursion)
        return realRegSetValueExW(key, name, reserved, type, data, size);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        auto code = realRegSetValueExW(valueKey(key, true, owned), name, reserved, type, data, size);
        traceKey(key, name, "RegSetValueExW", code, true);
        return code;
    });
}
LSTATUS WINAPI regQueryValue(HKEY key, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data,
                             LPDWORD size) {
    if (recursion)
        return realRegQueryValueExW(key, name, reserved, type, data, size);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        auto code = realRegQueryValueExW(valueKey(key, false, owned), name, reserved, type, data, size);
        traceKey(key, name, "RegQueryValueExW", code, false);
        return code;
    });
}
LSTATUS WINAPI regDeleteValue(HKEY key, LPCWSTR name) {
    if (recursion)
        return realRegDeleteValueW(key, name);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        auto code = realRegDeleteValueW(valueKey(key, true, owned), name);
        traceKey(key, name, "RegDeleteValueW", code, true);
        return code;
    });
}
// Subkey enumeration of private keys merges private and original children.
bool mergedNames(HKEY key, DWORD index, std::vector<std::wstring> &names) {
    auto value = location(key, nullptr, 0);
    if (!covered(value))
        return false;
    if (value.predefined) {
        if (!registryStore()->hasPrivate(registryPath(value)))
            return false;
        names = registryStore()->subkeys(registryPath(value));
        return true;
    }
    if (!value.isPrivate)
        return false;
    HandlesLock lock;
    auto found = keyHandles.find(key);
    if (found == keyHandles.end())
        return false;
    if (index == 0 || !found->second.namesReady) {
        lock.unlock();
        auto fresh = registryStore()->subkeys(registryPath(value));
        HandlesLock relock;
        auto again = keyHandles.find(key);
        if (again != keyHandles.end()) {
            again->second.names = fresh;
            again->second.namesReady = true;
        }
        names = std::move(fresh);
        return true;
    }
    names = found->second.names;
    return true;
}
LSTATUS WINAPI regEnumKeyEx(HKEY key, DWORD index, LPWSTR name, LPDWORD count, LPDWORD reserved,
                            LPWSTR keyClass, LPDWORD classCount, PFILETIME written) {
    if (recursion)
        return realRegEnumKeyExW(key, index, name, count, reserved, keyClass, classCount, written);
    return registryCall([&]() -> LSTATUS {
        std::vector<std::wstring> names;
        if (!mergedNames(key, index, names))
            return realRegEnumKeyExW(key, index, name, count, reserved, keyClass, classCount, written);
        if (!name || !count)
            return ERROR_INVALID_PARAMETER;
        if (index >= names.size())
            return ERROR_NO_MORE_ITEMS;
        const auto &entry = names[index];
        if (*count <= entry.size())
            return ERROR_MORE_DATA;
        memcpy(name, entry.c_str(), (entry.size() + 1) * sizeof(wchar_t));
        *count = DWORD(entry.size());
        if (keyClass && classCount && *classCount)
            keyClass[0] = 0;
        if (classCount)
            *classCount = 0;
        if (written)
            GetSystemTimeAsFileTime(written);
        return ERROR_SUCCESS;
    });
}
LSTATUS WINAPI regEnumKey(HKEY key, DWORD index, LPWSTR name, DWORD count) {
    if (recursion)
        return realRegEnumKeyW(key, index, name, count);
    DWORD size = count;
    return regEnumKeyEx(key, index, name, &size, nullptr, nullptr, nullptr, nullptr);
}
LSTATUS WINAPI regQueryInfoKey(HKEY key, LPWSTR keyClass, LPDWORD classCount, LPDWORD reserved,
                               LPDWORD subkeys, LPDWORD maxSubkey, LPDWORD maxClass, LPDWORD values,
                               LPDWORD maxValueName, LPDWORD maxValue, LPDWORD security, PFILETIME written) {
    if (recursion)
        return realRegQueryInfoKeyW(key, keyClass, classCount, reserved, subkeys, maxSubkey, maxClass, values,
                                    maxValueName, maxValue, security, written);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        auto code =
            realRegQueryInfoKeyW(valueKey(key, false, owned), keyClass, classCount, reserved, subkeys,
                                 maxSubkey, maxClass, values, maxValueName, maxValue, security, written);
        std::vector<std::wstring> names;
        if (code == ERROR_SUCCESS && (subkeys || maxSubkey) && mergedNames(key, 0, names)) {
            if (subkeys)
                *subkeys = DWORD(names.size());
            if (maxSubkey) {
                size_t longest = 0;
                for (const auto &entry : names)
                    longest = std::max(longest, entry.size());
                *maxSubkey = DWORD(longest);
            }
        }
        return code;
    });
}
LSTATUS WINAPI regOpenCurrentUser(REGSAM access, PHKEY result) {
    auto code = realRegOpenCurrentUser(access, result);
    if (recursion || code != ERROR_SUCCESS || !result)
        return code;
    Guard guard;
    try {
        KeyLocation value;
        value.root = L'U';
        if (access & KEY_WOW64_32KEY)
            value.view = 32;
        trackKey(*result, std::move(value));
    } catch (...) {
        *result = nullptr;
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return code;
}
std::wstring ansiText(LPCSTR value);
bool localMachineName(const std::wstring &name) {
    if (name.empty())
        return true;
    auto value = name;
    while (!value.empty() && value.front() == L'\\')
        value.erase(0, 1);
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    return same(value, L".") || same(value, L"localhost") ||
           (GetComputerNameW(computer, &size) && same(value, std::wstring(computer, size)));
}
LSTATUS connected(HKEY key, bool local, LSTATUS code, PHKEY result) {
    if (recursion || code != ERROR_SUCCESS || !result || !local || !predefinedRoot(key))
        return code;
    Guard guard;
    try {
        KeyLocation value;
        value.root = predefinedRoot(key);
        trackKey(*result, std::move(value));
    } catch (...) {
        *result = nullptr;
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return code;
}
LSTATUS WINAPI regConnectW(LPCWSTR machine, HKEY key, PHKEY result) {
    auto code = realRegConnectRegistryW(machine, key, result);
    return connected(key, localMachineName(machine ? machine : L""), code, result);
}
LSTATUS WINAPI regConnectA(LPCSTR machine, HKEY key, PHKEY result) {
    auto code = realRegConnectRegistryA(machine, key, result);
    bool local = true;
    try {
        local = localMachineName(machine ? ansiText(machine) : std::wstring());
    } catch (...) {
        local = false;
    }
    return connected(key, local, code, result);
}
REGSAM viewFromFlags(DWORD flags) {
    if (flags & 0x00020000) // RRF_SUBKEY_WOW6432KEY
        return KEY_WOW64_32KEY;
    if (flags & 0x00010000) // RRF_SUBKEY_WOW6464KEY
        return KEY_WOW64_64KEY;
    return 0;
}
LSTATUS WINAPI regGetValue(HKEY key, LPCWSTR subkey, LPCWSTR name, DWORD flags, LPDWORD type, PVOID data,
                           LPDWORD size) {
    if (recursion)
        return realRegGetValueW(key, subkey, name, flags, type, data, size);
    HKEY opened = nullptr;
    if (subkey && *subkey) {
        auto code = regOpen(key, subkey, 0, KEY_QUERY_VALUE | viewFromFlags(flags), &opened);
        if (code != ERROR_SUCCESS)
            return code;
        code = regGetValue(opened, nullptr, name, flags & ~0x00030000u, type, data, size);
        regClose(opened);
        return code;
    }
    return registryCall([&]() -> LSTATUS {
        Key owned;
        return realRegGetValueW(valueKey(key, false, owned), nullptr, name, flags, type, data, size);
    });
}
LSTATUS WINAPI regSetKeyValue(HKEY key, LPCWSTR subkey, LPCWSTR name, DWORD type, LPCVOID data, DWORD size) {
    if (recursion)
        return realRegSetKeyValueW(key, subkey, name, type, data, size);
    if (subkey && *subkey) {
        HKEY opened = nullptr;
        auto code = regCreate(key, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &opened, nullptr);
        if (code != ERROR_SUCCESS)
            return code;
        code = regSetValue(opened, name, 0, type, static_cast<const BYTE *>(data), size);
        regClose(opened);
        return code;
    }
    return regSetValue(key, name, 0, type, static_cast<const BYTE *>(data), size);
}
LSTATUS WINAPI regDeleteKeyValue(HKEY key, LPCWSTR subkey, LPCWSTR name) {
    if (recursion)
        return realRegDeleteKeyValueW(key, subkey, name);
    if (subkey && *subkey) {
        HKEY opened = nullptr;
        auto code = regOpen(key, subkey, 0, KEY_SET_VALUE, &opened);
        if (code != ERROR_SUCCESS)
            return code;
        code = regDeleteValue(opened, name);
        regClose(opened);
        return code;
    }
    return regDeleteValue(key, name);
}
// ---- ANSI registry entry points: converted and routed through the Unicode hooks ----
std::wstring ansiText(LPCSTR value) {
    if (!value)
        return {};
    int size = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (size <= 0 || size > 32768)
        throw Error(ERROR_INVALID_PARAMETER, "Invalid ANSI registry text");
    std::wstring result(size_t(size), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, result.data(), size);
    result.pop_back();
    return result;
}
template <class Call> LSTATUS ansiCall(Call &&call) noexcept {
    try {
        return call();
    } catch (const Error &error) {
        return LSTATUS(error.code);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}
LPCWSTR optional(LPCSTR source, const std::wstring &converted) {
    return source ? converted.c_str() : nullptr;
}
LSTATUS WINAPI regOpenA(HKEY key, LPCSTR path, DWORD options, REGSAM access, PHKEY result) {
    if (recursion)
        return realRegOpenKeyExA(key, path, options, access, result);
    return ansiCall([&] {
        auto text = ansiText(path);
        return regOpen(key, optional(path, text), options, access, result);
    });
}
LSTATUS WINAPI regCreateA(HKEY key, LPCSTR path, DWORD reserved, LPSTR keyClass, DWORD options, REGSAM access,
                          const LPSECURITY_ATTRIBUTES security, PHKEY result, LPDWORD disposition) {
    if (recursion)
        return realRegCreateKeyExA(key, path, reserved, keyClass, options, access, security, result,
                                   disposition);
    return ansiCall([&] {
        auto text = ansiText(path);
        auto value = location(key, optional(path, text), access);
        if (!covered(value))
            return realRegCreateKeyExA(key, path, reserved, keyClass, options, access, security, result,
                                       disposition);
        return regCreate(key, optional(path, text), reserved, nullptr, options, access, security, result,
                         disposition);
    });
}
LSTATUS WINAPI regDeleteExA(HKEY key, LPCSTR path, REGSAM access, DWORD reserved) {
    if (recursion)
        return realRegDeleteKeyExA(key, path, access, reserved);
    return ansiCall([&] {
        auto text = ansiText(path);
        return regRemove(key, optional(path, text), access, reserved, false);
    });
}
LSTATUS WINAPI regDeleteA(HKEY key, LPCSTR path) {
    if (recursion)
        return realRegDeleteKeyA(key, path);
    return ansiCall([&] {
        auto text = ansiText(path);
        return regRemove(key, optional(path, text), 0, 0, false);
    });
}
LSTATUS WINAPI regDeleteTreeA(HKEY key, LPCSTR path) {
    if (recursion)
        return realRegDeleteTreeA(key, path);
    return ansiCall([&] {
        auto text = ansiText(path);
        return regRemove(key, optional(path, text), 0, 0, true);
    });
}
LSTATUS WINAPI regSetValueA(HKEY key, LPCSTR name, DWORD reserved, DWORD type, const BYTE *data, DWORD size) {
    if (recursion || !predefinedRoot(key))
        return realRegSetValueExA(key, name, reserved, type, data, size);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        return realRegSetValueExA(valueKey(key, true, owned), name, reserved, type, data, size);
    });
}
LSTATUS WINAPI regQueryValueA(HKEY key, LPCSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data,
                              LPDWORD size) {
    if (recursion || !predefinedRoot(key))
        return realRegQueryValueExA(key, name, reserved, type, data, size);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        return realRegQueryValueExA(valueKey(key, false, owned), name, reserved, type, data, size);
    });
}
LSTATUS WINAPI regDeleteValueA(HKEY key, LPCSTR name) {
    if (recursion || !predefinedRoot(key))
        return realRegDeleteValueA(key, name);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        return realRegDeleteValueA(valueKey(key, true, owned), name);
    });
}
LSTATUS WINAPI regEnumKeyExA(HKEY key, DWORD index, LPSTR name, LPDWORD count, LPDWORD reserved,
                             LPSTR keyClass, LPDWORD classCount, PFILETIME written) {
    if (recursion)
        return realRegEnumKeyExA(key, index, name, count, reserved, keyClass, classCount, written);
    return registryCall([&]() -> LSTATUS {
        std::vector<std::wstring> names;
        if (!mergedNames(key, index, names))
            return realRegEnumKeyExA(key, index, name, count, reserved, keyClass, classCount, written);
        if (!name || !count)
            return ERROR_INVALID_PARAMETER;
        if (index >= names.size())
            return ERROR_NO_MORE_ITEMS;
        int bytes = WideCharToMultiByte(CP_ACP, 0, names[index].c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (bytes <= 0 || DWORD(bytes) > *count)
            return ERROR_MORE_DATA;
        WideCharToMultiByte(CP_ACP, 0, names[index].c_str(), -1, name, int(*count), nullptr, nullptr);
        *count = DWORD(bytes - 1);
        if (keyClass && classCount && *classCount)
            keyClass[0] = 0;
        if (classCount)
            *classCount = 0;
        if (written)
            GetSystemTimeAsFileTime(written);
        return ERROR_SUCCESS;
    });
}
LSTATUS WINAPI regQueryInfoKeyA(HKEY key, LPSTR keyClass, LPDWORD classCount, LPDWORD reserved,
                                LPDWORD subkeys, LPDWORD maxSubkey, LPDWORD maxClass, LPDWORD values,
                                LPDWORD maxValueName, LPDWORD maxValue, LPDWORD security, PFILETIME written) {
    if (recursion)
        return realRegQueryInfoKeyA(key, keyClass, classCount, reserved, subkeys, maxSubkey, maxClass, values,
                                    maxValueName, maxValue, security, written);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        auto code =
            realRegQueryInfoKeyA(valueKey(key, false, owned), keyClass, classCount, reserved, subkeys,
                                 maxSubkey, maxClass, values, maxValueName, maxValue, security, written);
        std::vector<std::wstring> names;
        if (code == ERROR_SUCCESS && (subkeys || maxSubkey) && mergedNames(key, 0, names)) {
            if (subkeys)
                *subkeys = DWORD(names.size());
            if (maxSubkey) {
                size_t longest = 0;
                for (const auto &entry : names)
                    longest = std::max(longest, entry.size() * 2);
                *maxSubkey = DWORD(longest);
            }
        }
        return code;
    });
}
LSTATUS WINAPI regGetValueA(HKEY key, LPCSTR subkey, LPCSTR name, DWORD flags, LPDWORD type, PVOID data,
                            LPDWORD size) {
    if (recursion)
        return realRegGetValueA(key, subkey, name, flags, type, data, size);
    if (subkey && *subkey) {
        HKEY opened = nullptr;
        auto code = regOpenA(key, subkey, 0, KEY_QUERY_VALUE | viewFromFlags(flags), &opened);
        if (code != ERROR_SUCCESS)
            return code;
        code = regGetValueA(opened, nullptr, name, flags & ~0x00030000u, type, data, size);
        regClose(opened);
        return code;
    }
    if (!predefinedRoot(key))
        return realRegGetValueA(key, nullptr, name, flags, type, data, size);
    return registryCall([&]() -> LSTATUS {
        Key owned;
        return realRegGetValueA(valueKey(key, false, owned), nullptr, name, flags, type, data, size);
    });
}
std::wstring systemLocation(UINT(WINAPI *query)(LPWSTR, UINT)) {
    std::wstring value(32768, L'\0');
    auto size = query(value.data(), UINT(value.size()));
    if (!size || size >= value.size())
        return {};
    value.resize(size);
    return value;
}
bool regularFile(const std::wstring &path) {
    auto attributes = realGetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
std::wstring fullPath(const std::wstring &path) {
    std::wstring value(32768, L'\0');
    auto size = GetFullPathNameW(path.c_str(), DWORD(value.size()), value.data(), nullptr);
    if (!size || size >= value.size())
        throw Error(ERROR_FILENAME_EXCED_RANGE, "Child executable path cannot be normalized");
    value.resize(size);
    return value;
}
std::vector<std::wstring> searchDirectories() {
    std::vector<std::wstring> result;
    std::wstring module(32768, L'\0');
    auto size = GetModuleFileNameW(nullptr, module.data(), DWORD(module.size()));
    if (size && size < module.size()) {
        module.resize(size);
        result.push_back(module.substr(0, module.find_last_of(L'\\')));
    }
    std::wstring current(32768, L'\0');
    size = GetCurrentDirectoryW(DWORD(current.size()), current.data());
    if (size && size < current.size()) {
        current.resize(size);
        result.push_back(current);
    }
    auto system = systemLocation(GetSystemDirectoryW), windows = systemLocation(GetWindowsDirectoryW);
    if (!system.empty())
        result.push_back(system);
    if (!windows.empty()) {
        result.push_back(windows + L"\\System");
        result.push_back(windows);
    }
    std::wstring path(32767, L'\0');
    size = GetEnvironmentVariableW(L"PATH", path.data(), DWORD(path.size()));
    if (size && size < path.size()) {
        path.resize(size);
        for (size_t start = 0; start <= path.size();) {
            auto end = path.find(L';', start);
            auto entry = path.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
            if (!entry.empty())
                result.push_back(entry);
            if (end == std::wstring::npos)
                break;
            start = end + 1;
        }
    }
    return result;
}
std::wstring resolveApplication(LPCWSTR command) {
    if (!command || !*command)
        throw Error(ERROR_INVALID_PARAMETER, "Child launch requires an executable or a command line");
    std::wstring line(command, wcsnlen(command, 32767));
    std::vector<std::wstring> candidates;
    if (line.front() == L'"') {
        auto end = line.find(L'"', 1);
        if (end == std::wstring::npos || end == 1)
            throw Error(ERROR_INVALID_PARAMETER, "Unterminated quoted child executable");
        candidates.push_back(line.substr(1, end - 1));
    } else {
        for (size_t start = 0;;) {
            auto space = line.find_first_of(L" \t", start);
            candidates.push_back(line.substr(0, space));
            if (space == std::wstring::npos)
                break;
            start = space + 1;
        }
    }
    for (auto name : candidates) {
        if (name.empty())
            continue;
        auto slash = name.find_last_of(L"\\/"), dot = name.find_last_of(L'.');
        if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
            name += L".exe";
        if (name.find_first_of(L"\\/:") != std::wstring::npos) {
            auto path = fullPath(name);
            if (regularFile(path))
                return path;
            continue;
        }
        for (const auto &directory : searchDirectories()) {
            auto path = fullPath(directory + L"\\" + name);
            if (regularFile(path))
                return path;
        }
    }
    throw Error(ERROR_FILE_NOT_FOUND, "Child executable cannot be resolved from the command line");
}
BOOL WINAPI createProcessW(LPCWSTR application, LPWSTR command, LPSECURITY_ATTRIBUTES processSecurity,
                           LPSECURITY_ATTRIBUTES threadSecurity, BOOL inherit, DWORD flags,
                           LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
                           LPPROCESS_INFORMATION process) {
    if (recursion)
        return realCreateProcessW(application, command, processSecurity, threadSecurity, inherit, flags,
                                  environment, directory, startup, process);
    Guard guard;
    try {
        std::vector<wchar_t> converted;
        if (environment && !(flags & CREATE_UNICODE_ENVIRONMENT)) {
            auto ansi = static_cast<const char *>(environment);
            size_t length = 0;
            while (length < 1048576 && (ansi[length] || ansi[length + 1]))
                ++length;
            if (length >= 1048576) {
                SetLastError(ERROR_ENVVAR_NOT_FOUND);
                return FALSE;
            }
            int size = MultiByteToWideChar(CP_ACP, 0, ansi, int(length + 2), nullptr, 0);
            if (size <= 0) {
                SetLastError(ERROR_NO_UNICODE_TRANSLATION);
                return FALSE;
            }
            converted.resize(size_t(size));
            MultiByteToWideChar(CP_ACP, 0, ansi, int(length + 2), converted.data(), size);
            environment = converted.data();
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        std::wstring resolved;
        if (!application) {
            try {
                resolved = resolveApplication(command);
            } catch (const Error &error) {
                trace(configuration, "process", "CreateProcessW", command ? command : L"", error.code);
                SetLastError(error.code);
                return FALSE;
            }
            application = resolved.c_str();
        }
        Launch request{.configuration = &configuration,
                       .application = application,
                       .commandLine = command,
                       .directory = directory,
                       .environment = static_cast<LPCWSTR>(environment),
                       .flags = flags,
                       .inherit = inherit,
                       .processSecurity = processSecurity,
                       .threadSecurity = threadSecurity,
                       .startup = startup,
                       .process = process,
                       .actual = realCreateProcessW};
        BOOL result = launch(&request);
        const DWORD error = GetLastError();
        // Diagnostics must never turn a successful creation into a reported failure with an
        // unowned child left running, even if allocating the event path fails.
        try {
            trace(configuration, "process", "CreateProcessW", application ? application : L"",
                  result ? ERROR_SUCCESS : error);
        } catch (...) {
        }
        SetLastError(error);
        return result;
    } catch (const Error &error) {
        SetLastError(error.code);
        return FALSE;
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}
std::wstring launchText(LPCSTR value) {
    if (!value)
        return {};
    int size = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (size <= 0)
        throw Error(ERROR_NO_UNICODE_TRANSLATION, "Convert ANSI launch text");
    std::wstring result(size_t(size), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, result.data(), size);
    result.resize(size_t(size - 1));
    return result;
}
BOOL WINAPI createProcessA(LPCSTR application, LPSTR command, LPSECURITY_ATTRIBUTES processSecurity,
                           LPSECURITY_ATTRIBUTES threadSecurity, BOOL inherit, DWORD flags,
                           LPVOID environment, LPCSTR directory, LPSTARTUPINFOA startup,
                           LPPROCESS_INFORMATION process) {
    if (recursion)
        return realCreateProcessA(application, command, processSecurity, threadSecurity, inherit, flags,
                                  environment, directory, startup, process);
    try {
        if (!startup || startup->cb < sizeof(STARTUPINFOA) ||
            ((flags & EXTENDED_STARTUPINFO_PRESENT) && startup->cb < sizeof(STARTUPINFOEXA))) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        auto app = launchText(application), line = launchText(command), folder = launchText(directory);
        auto desktop = launchText(startup->lpDesktop), title = launchText(startup->lpTitle);
        STARTUPINFOEXW converted{};
        memcpy(&converted.StartupInfo, startup, sizeof(STARTUPINFOA));
        converted.StartupInfo.cb =
            (flags & EXTENDED_STARTUPINFO_PRESENT) ? sizeof(STARTUPINFOEXW) : sizeof(STARTUPINFOW);
        converted.StartupInfo.lpReserved = nullptr;
        converted.StartupInfo.lpDesktop = startup->lpDesktop ? desktop.data() : nullptr;
        converted.StartupInfo.lpTitle = startup->lpTitle ? title.data() : nullptr;
        if (flags & EXTENDED_STARTUPINFO_PRESENT)
            converted.lpAttributeList = reinterpret_cast<LPSTARTUPINFOEXA>(startup)->lpAttributeList;
        std::vector<wchar_t> mutableLine(line.begin(), line.end());
        mutableLine.push_back(0);
        return createProcessW(application ? app.c_str() : nullptr, command ? mutableLine.data() : nullptr,
                              processSecurity, threadSecurity, inherit, flags, environment,
                              directory ? folder.c_str() : nullptr, &converted.StartupInfo, process);
    } catch (const Error &error) {
        SetLastError(error.code);
        return FALSE;
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}
SOCKET WSAAPI socketHook(int family, int type, int protocol) {
    if (!recursion && configuration.managedProxy &&
        (family != AF_INET || type != SOCK_STREAM || (protocol != IPPROTO_TCP && protocol != 0))) {
        WSASetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    return realSocket(family, type, protocol);
}
SOCKET WSAAPI wsaSocketHook(int family, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP group,
                            DWORD flags) {
    if (!recursion && configuration.managedProxy &&
        (family != AF_INET || type != SOCK_STREAM || info || group ||
         (protocol != IPPROTO_TCP && protocol != 0))) {
        WSASetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    return realWSASocketW(family, type, protocol, info, group, flags);
}
SOCKET WSAAPI wsaSocketAHook(int family, int type, int protocol, LPWSAPROTOCOL_INFOA info, GROUP group,
                             DWORD flags) {
    if (!recursion && configuration.managedProxy &&
        (family != AF_INET || type != SOCK_STREAM || info || group ||
         (protocol != IPPROTO_TCP && protocol != 0))) {
        WSASetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    return realWSASocketA(family, type, protocol, info, group, flags);
}
std::string utf8(const wchar_t *value, int count) {
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, count, nullptr, 0, nullptr, nullptr);
    if (size < 0 || size > 4096 || (!size && count))
        throw Error(ERROR_INVALID_DATA, "Invalid credential encoding");
    std::string result(size_t(size), '\0');
    if (size)
        require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, count, result.data(), size, nullptr,
                                    nullptr) == size,
                "Encode route credentials");
    return result;
}
int WSAAPI connectHook(SOCKET socket, const sockaddr *address, int size) {
    if (recursion || !configuration.managedProxy)
        return realConnect(socket, address, size);
    Guard guard;
    if (!address || size != sizeof(sockaddr_in) || address->sa_family != AF_INET) {
        WSASetLastError(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }
    try {
        Proxy proxy{configuration.proxyAddress,
                    static_cast<unsigned short>(configuration.proxyPort),
                    configuration.proxyProtocol,
                    {},
                    {},
                    configuration.proxyTimeoutMs};
        struct Secrets {
            Proxy &proxy;
            ~Secrets() {
                SecureZeroMemory(proxy.username.data(), proxy.username.size());
                SecureZeroMemory(proxy.password.data(), proxy.password.size());
            }
        } wipe{proxy};
        if (configuration.proxyAuthenticated) {
            PCREDENTIALW credential = nullptr;
            auto target = std::wstring(L"NativeBox.Driverless.Proxy.") + configuration.profileId;
            require(CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential),
                    "Read owner route credentials");
            struct Credential {
                PCREDENTIALW value;
                ~Credential() {
                    SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
                    CredFree(value);
                }
            } release{credential};
            if (!credential->UserName || credential->CredentialBlobSize % sizeof(wchar_t) ||
                credential->CredentialBlobSize > 8192)
                throw Error(ERROR_INVALID_DATA, "Invalid route credential record");
            proxy.username = utf8(credential->UserName, int(wcslen(credential->UserName)));
            auto password = reinterpret_cast<const wchar_t *>(credential->CredentialBlob);
            int count = int(credential->CredentialBlobSize / sizeof(wchar_t));
            if (count && password[count - 1] == 0)
                --count;
            proxy.password = utf8(password, count);
            if (proxy.username.empty())
                throw Error(ERROR_INVALID_DATA, "Authenticated route requires a username");
        }
        auto &destination = *reinterpret_cast<const sockaddr_in *>(address);
        int result = routeBlockingIpv4(socket, destination, proxy);
        int code = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        wchar_t target[INET_ADDRSTRLEN]{};
        InetNtopW(AF_INET, &destination.sin_addr, target, DWORD(std::size(target)));
        trace(configuration, "network", "connect_managed_ipv4",
              std::wstring(target) + L":" + std::to_wstring(ntohs(destination.sin_port)), DWORD(code));
        WSASetLastError(code);
        return result;
    } catch (const Error &) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    } catch (...) {
        WSASetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
}
int WSAAPI wsaConnectHook(SOCKET socket, const sockaddr *address, int size, LPWSABUF caller, LPWSABUF callee,
                          LPQOS sending, LPQOS receiving) {
    if (recursion || !configuration.managedProxy)
        return realWSAConnect(socket, address, size, caller, callee, sending, receiving);
    if (caller || callee || sending || receiving) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return connectHook(socket, address, size);
}
int WSAAPI ioctlSocketHook(SOCKET socket, long command, u_long *value) {
    if (!recursion && configuration.managedProxy && command == FIONBIO && value && *value) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realIoctlSocket(socket, command, value);
}
int WSAAPI wsaIoctlHook(SOCKET socket, DWORD code, LPVOID input, DWORD inputSize, LPVOID output,
                        DWORD outputSize, LPDWORD bytes, LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!recursion && configuration.managedProxy &&
        (code == SIO_GET_EXTENSION_FUNCTION_POINTER || code == SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER ||
         (code == FIONBIO && input && inputSize >= sizeof(u_long) && *static_cast<u_long *>(input)))) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realWSAIoctl(socket, code, input, inputSize, output, outputSize, bytes, overlapped, completion);
}
int WSAAPI sendToHook(SOCKET socket, const char *buffer, int size, int flags, const sockaddr *destination,
                      int destinationSize) {
    if (!recursion && configuration.managedProxy) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realSendTo(socket, buffer, size, flags, destination, destinationSize);
}
int WSAAPI wsaSendToHook(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                         const sockaddr *destination, int destinationSize, LPWSAOVERLAPPED overlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!recursion && configuration.managedProxy) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realWSASendTo(socket, buffers, count, sent, flags, destination, destinationSize, overlapped,
                         completion);
}
int WSAAPI eventSelectHook(SOCKET socket, WSAEVENT event, long events) {
    if (!recursion && configuration.managedProxy && events) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realWSAEventSelect(socket, event, events);
}
int WSAAPI asyncSelectHook(SOCKET socket, HWND window, unsigned message, long events) {
    if (!recursion && configuration.managedProxy && events) {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    return realWSAAsyncSelect(socket, window, message, events);
}
// ---- Per-sandbox isolation of named kernel objects and of other instances' windows ----
auto realCreateMutexW = &CreateMutexW;
auto realCreateMutexExW = &CreateMutexExW;
auto realOpenMutexW = &OpenMutexW;
auto realCreateEventW = &CreateEventW;
auto realCreateEventExW = &CreateEventExW;
auto realOpenEventW = &OpenEventW;
auto realCreateSemaphoreW = &CreateSemaphoreW;
auto realCreateSemaphoreExW = &CreateSemaphoreExW;
auto realOpenSemaphoreW = &OpenSemaphoreW;
auto realCreateFileMappingW = &CreateFileMappingW;
auto realOpenFileMappingW = &OpenFileMappingW;
auto realCreateMutexA = &CreateMutexA;
auto realOpenMutexA = &OpenMutexA;
auto realCreateEventA = &CreateEventA;
auto realOpenEventA = &OpenEventA;
auto realCreateFileMappingA = &CreateFileMappingA;
auto realOpenFileMappingA = &OpenFileMappingA;
using FindWindowExWRoutine = HWND(WINAPI *)(HWND, HWND, LPCWSTR, LPCWSTR);
using FindWindowExARoutine = HWND(WINAPI *)(HWND, HWND, LPCSTR, LPCSTR);
using FindWindowWRoutine = HWND(WINAPI *)(LPCWSTR, LPCWSTR);
using FindWindowARoutine = HWND(WINAPI *)(LPCSTR, LPCSTR);
using WindowProcessRoutine = DWORD(WINAPI *)(HWND, LPDWORD);
FindWindowExWRoutine realFindWindowExW = nullptr;
FindWindowExARoutine realFindWindowExA = nullptr;
FindWindowWRoutine realFindWindowW = nullptr;
FindWindowARoutine realFindWindowA = nullptr;
WindowProcessRoutine windowProcess = nullptr;

// Returns an empty string when the name must stay untouched.
std::wstring isolatedName(LPCWSTR name) {
    if (!name || !*name || !configuration.profileId[0])
        return {};
    std::wstring value(name), prefix;
    for (const wchar_t *scope : {L"Global\\", L"Local\\"}) {
        auto length = wcslen(scope);
        if (value.size() > length && _wcsnicmp(value.c_str(), scope, length) == 0) {
            prefix.assign(value, 0, length);
            value.erase(0, length);
            break;
        }
    }
    // Session\N\..., private namespaces and our own session objects are left alone.
    if (value.find(L'\\') != std::wstring::npos || value.starts_with(L"NativeBox."))
        return {};
    return prefix + L"NativeBox." + configuration.profileId + L"." + value;
}
std::wstring wideName(LPCSTR name) {
    if (!name)
        return {};
    int size = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
    if (size <= 0 || size > 32768)
        throw Error(ERROR_INVALID_PARAMETER, "Invalid object name");
    std::wstring result(size_t(size), L'\0');
    MultiByteToWideChar(CP_ACP, 0, name, -1, result.data(), size);
    result.pop_back();
    return result;
}
template <class Create> HANDLE createNamed(LPCWSTR name, Create &&create) {
    if (recursion)
        return create(name);
    Guard guard;
    std::wstring isolated;
    try {
        isolated = isolatedName(name);
    } catch (...) {
    }
    return create(isolated.empty() ? name : isolated.c_str());
}
template <class Open> HANDLE openNamed(LPCWSTR name, Open &&open) {
    if (recursion)
        return open(name);
    Guard guard;
    std::wstring isolated;
    try {
        isolated = isolatedName(name);
    } catch (...) {
    }
    if (isolated.empty())
        return open(name);
    HANDLE result = open(isolated.c_str());
    if (result || GetLastError() != ERROR_FILE_NOT_FOUND)
        return result;
    // Objects created outside any sandbox (host services, drivers) stay reachable read-through.
    return open(name);
}
HANDLE WINAPI createMutexW(LPSECURITY_ATTRIBUTES security, BOOL owner, LPCWSTR name) {
    return createNamed(name, [&](LPCWSTR value) { return realCreateMutexW(security, owner, value); });
}
HANDLE WINAPI createMutexExW(LPSECURITY_ATTRIBUTES security, LPCWSTR name, DWORD flags, DWORD access) {
    return createNamed(name,
                       [&](LPCWSTR value) { return realCreateMutexExW(security, value, flags, access); });
}
HANDLE WINAPI openMutexW(DWORD access, BOOL inherit, LPCWSTR name) {
    return openNamed(name, [&](LPCWSTR value) { return realOpenMutexW(access, inherit, value); });
}
HANDLE WINAPI createEventW(LPSECURITY_ATTRIBUTES security, BOOL manual, BOOL initial, LPCWSTR name) {
    return createNamed(name,
                       [&](LPCWSTR value) { return realCreateEventW(security, manual, initial, value); });
}
HANDLE WINAPI createEventExW(LPSECURITY_ATTRIBUTES security, LPCWSTR name, DWORD flags, DWORD access) {
    return createNamed(name,
                       [&](LPCWSTR value) { return realCreateEventExW(security, value, flags, access); });
}
HANDLE WINAPI openEventW(DWORD access, BOOL inherit, LPCWSTR name) {
    return openNamed(name, [&](LPCWSTR value) { return realOpenEventW(access, inherit, value); });
}
HANDLE WINAPI createSemaphoreW(LPSECURITY_ATTRIBUTES security, LONG initial, LONG maximum, LPCWSTR name) {
    return createNamed(
        name, [&](LPCWSTR value) { return realCreateSemaphoreW(security, initial, maximum, value); });
}
HANDLE WINAPI createSemaphoreExW(LPSECURITY_ATTRIBUTES security, LONG initial, LONG maximum, LPCWSTR name,
                                 DWORD flags, DWORD access) {
    return createNamed(name, [&](LPCWSTR value) {
        return realCreateSemaphoreExW(security, initial, maximum, value, flags, access);
    });
}
HANDLE WINAPI openSemaphoreW(DWORD access, BOOL inherit, LPCWSTR name) {
    return openNamed(name, [&](LPCWSTR value) { return realOpenSemaphoreW(access, inherit, value); });
}
HANDLE WINAPI createFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES security, DWORD protect, DWORD high,
                                 DWORD low, LPCWSTR name) {
    return createNamed(name, [&](LPCWSTR value) {
        return realCreateFileMappingW(file, security, protect, high, low, value);
    });
}
HANDLE WINAPI openFileMappingW(DWORD access, BOOL inherit, LPCWSTR name) {
    return openNamed(name, [&](LPCWSTR value) { return realOpenFileMappingW(access, inherit, value); });
}
template <class Call> HANDLE ansiNamed(LPCSTR name, Call &&call) {
    if (!name)
        return call(nullptr);
    try {
        auto value = wideName(name);
        return call(value.c_str());
    } catch (const Error &error) {
        SetLastError(error.code);
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    return nullptr;
}
HANDLE WINAPI createMutexA(LPSECURITY_ATTRIBUTES security, BOOL owner, LPCSTR name) {
    if (recursion)
        return realCreateMutexA(security, owner, name);
    return ansiNamed(name, [&](LPCWSTR value) { return createMutexW(security, owner, value); });
}
HANDLE WINAPI openMutexA(DWORD access, BOOL inherit, LPCSTR name) {
    if (recursion)
        return realOpenMutexA(access, inherit, name);
    return ansiNamed(name, [&](LPCWSTR value) { return openMutexW(access, inherit, value); });
}
HANDLE WINAPI createEventA(LPSECURITY_ATTRIBUTES security, BOOL manual, BOOL initial, LPCSTR name) {
    if (recursion)
        return realCreateEventA(security, manual, initial, name);
    return ansiNamed(name, [&](LPCWSTR value) { return createEventW(security, manual, initial, value); });
}
HANDLE WINAPI openEventA(DWORD access, BOOL inherit, LPCSTR name) {
    if (recursion)
        return realOpenEventA(access, inherit, name);
    return ansiNamed(name, [&](LPCWSTR value) { return openEventW(access, inherit, value); });
}
HANDLE WINAPI createFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES security, DWORD protect, DWORD high,
                                 DWORD low, LPCSTR name) {
    if (recursion)
        return realCreateFileMappingA(file, security, protect, high, low, name);
    return ansiNamed(
        name, [&](LPCWSTR value) { return createFileMappingW(file, security, protect, high, low, value); });
}
HANDLE WINAPI openFileMappingA(DWORD access, BOOL inherit, LPCSTR name) {
    if (recursion)
        return realOpenFileMappingA(access, inherit, name);
    return ansiNamed(name, [&](LPCWSTR value) { return openFileMappingW(access, inherit, value); });
}
std::wstring processImage(HANDLE process) {
    std::vector<wchar_t> buffer(32768);
    DWORD size = DWORD(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
        return {};
    return std::wstring(buffer.data(), size);
}
bool sharesJob(DWORD pid) {
    std::vector<BYTE> storage(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 8192 * sizeof(ULONG_PTR));
    auto list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST *>(storage.data());
    if (!QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, list, DWORD(storage.size()),
                                   nullptr))
        return true; // not in a job or unknown: do not hide anything
    for (DWORD index = 0; index < list->NumberOfProcessIdsInList; ++index)
        if (list->ProcessIdList[index] == pid)
            return true;
    return false;
}
// Another instance of the same program that lives outside this sandbox (host or another sandbox).
bool foreignInstance(HWND window) {
    if (!windowProcess)
        return false;
    DWORD pid = 0;
    windowProcess(window, &pid);
    if (!pid || pid == GetCurrentProcessId() || sharesJob(pid))
        return false;
    Handle other(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!other.get())
        return false;
    static const std::wstring own = processImage(GetCurrentProcess());
    auto image = processImage(other.get());
    return !own.empty() && !image.empty() &&
           CompareStringOrdinal(own.c_str(), -1, image.c_str(), -1, TRUE) == CSTR_EQUAL;
}
HWND WINAPI findWindowExW(HWND parent, HWND after, LPCWSTR className, LPCWSTR title) {
    if (recursion)
        return realFindWindowExW(parent, after, className, title);
    Guard guard;
    HWND current = after;
    for (unsigned attempt = 0; attempt < 4096; ++attempt) {
        current = realFindWindowExW(parent, current, className, title);
        bool hidden = false;
        try {
            hidden = current && foreignInstance(current);
        } catch (...) {
        }
        if (!hidden)
            return current;
    }
    SetLastError(ERROR_SUCCESS);
    return nullptr;
}
HWND WINAPI findWindowW(LPCWSTR className, LPCWSTR title) {
    if (recursion)
        return realFindWindowW(className, title);
    return findWindowExW(nullptr, nullptr, className, title);
}
LPCWSTR atomOrText(LPCSTR value, std::wstring &storage) {
    if (!value)
        return nullptr;
    if (IS_INTRESOURCE(value))
        return reinterpret_cast<LPCWSTR>(value);
    storage = wideName(value);
    return storage.c_str();
}
HWND WINAPI findWindowExA(HWND parent, HWND after, LPCSTR className, LPCSTR title) {
    if (recursion)
        return realFindWindowExA(parent, after, className, title);
    try {
        std::wstring classText, titleText;
        auto wideClass = atomOrText(className, classText);
        auto wideTitle = title ? (titleText = wideName(title)).c_str() : nullptr;
        return findWindowExW(parent, after, wideClass, wideTitle);
    } catch (...) {
        return realFindWindowExA(parent, after, className, title);
    }
}
HWND WINAPI findWindowA(LPCSTR className, LPCSTR title) {
    if (recursion)
        return realFindWindowA(className, title);
    return findWindowExA(nullptr, nullptr, className, title);
}
template <class Actual, class Replacement> void attach(Actual &actual, Replacement replacement) {
    auto code = DetourAttach(reinterpret_cast<PVOID *>(&actual), reinterpret_cast<PVOID>(replacement));
    if (code != ERROR_SUCCESS)
        throw Error(DWORD(code), "Attach covered Win32 API");
}
// Some APIs exist twice: a kernel32/advapi32 implementation and the kernelbase one that api-set importers
// (e.g. reg.exe, modern system tools) call directly. Both entries are detoured to the same replacement and
// the kernelbase original becomes the "real" routine, so no path bypasses the runtime and no hook re-enters
// itself through the other copy.
template <class Actual, class Replacement>
void attachAll(Actual &actual, Replacement replacement, const char *name) {
    static HMODULE base = GetModuleHandleW(L"kernelbase.dll");
    auto other = base ? reinterpret_cast<Actual>(GetProcAddress(base, name)) : nullptr;
    if (!other || DetourCodeFromPointer(reinterpret_cast<PVOID>(other), nullptr) ==
                      DetourCodeFromPointer(reinterpret_cast<PVOID>(actual), nullptr)) {
        attach(actual, replacement);
        return;
    }
    auto *secondary = new Actual(actual);
    actual = other;
    attach(actual, replacement);
    attach(*secondary, replacement);
}
bool install() {
    if (DetourTransactionBegin() != NO_ERROR)
        return false;
    try {
        auto winsock = GetModuleHandleW(L"ws2_32.dll");
        if (!winsock)
            throw Error(ERROR_MOD_NOT_FOUND, "Imported system Winsock module is unavailable");
        realWSASocketA = reinterpret_cast<SocketARoutine>(GetProcAddress(winsock, "WSASocketA"));
        realWSAAsyncSelect = reinterpret_cast<AsyncSelectRoutine>(GetProcAddress(winsock, "WSAAsyncSelect"));
        if (!realWSASocketA || !realWSAAsyncSelect)
            throw Error(ERROR_PROC_NOT_FOUND, "Covered legacy Winsock entry points are unavailable");
        registryCheck(DetourUpdateThread(GetCurrentThread()), "Enroll runtime startup thread");
        attachAll(realCreateFileW, createFileW, "CreateFileW");
        attachAll(realCreateFileA, createFileA, "CreateFileA");
        attachAll(realDeleteFileW, deleteFileW, "DeleteFileW");
        attachAll(realCreateDirectoryW, createDirectoryW, "CreateDirectoryW");
        attachAll(realRemoveDirectoryW, removeDirectoryW, "RemoveDirectoryW");
        attachAll(realMoveFileExW, moveFileExW, "MoveFileExW");
        attachAll(realCopyFileW, copyFileW, "CopyFileW");
        attachAll(realGetFileAttributesW, getFileAttributesW, "GetFileAttributesW");
        attachAll(realGetFileAttributesExW, getFileAttributesExW, "GetFileAttributesExW");
        attachAll(realSetFileAttributesW, setFileAttributesW, "SetFileAttributesW");
        attachAll(realReplaceFileW, replaceFileW, "ReplaceFileW");
        attachAll(realFindFirstFileW, findFirstFileW, "FindFirstFileW");
        attachAll(realMoveFileW, moveFileW, "MoveFileW");
        attachAll(realFindFirstFileExW, findFirstFileExW, "FindFirstFileExW");
        attachAll(realFindNextFileW, findNextFileW, "FindNextFileW");
        attachAll(realFindClose, findClose, "FindClose");
        attachAll(realCloseHandle, closeHandle, "CloseHandle");
        attachAll(realSetFileInformationByHandle, setFileInformation, "SetFileInformationByHandle");
        attachAll(realReadFile, readFile, "ReadFile");
        attachAll(realWriteFile, writeFile, "WriteFile");
        attachAll(realFlushFileBuffers, flushFileBuffers, "FlushFileBuffers");
        attachAll(realRegOpenKeyExW, regOpen, "RegOpenKeyExW");
        attachAll(realRegCreateKeyExW, regCreate, "RegCreateKeyExW");
        attachAll(realRegDeleteKeyExW, regDeleteEx, "RegDeleteKeyExW");
        attachAll(realRegDeleteKeyW, regDelete, "RegDeleteKeyW");
        attachAll(realRegDeleteTreeW, regDeleteTree, "RegDeleteTreeW");
        attachAll(realRegCloseKey, regClose, "RegCloseKey");
        attachAll(realRegSetValueExW, regSetValue, "RegSetValueExW");
        attachAll(realRegQueryValueExW, regQueryValue, "RegQueryValueExW");
        attachAll(realRegDeleteValueW, regDeleteValue, "RegDeleteValueW");
        attachAll(realRegEnumKeyExW, regEnumKeyEx, "RegEnumKeyExW");
        attachAll(realRegEnumKeyW, regEnumKey, "RegEnumKeyW");
        attachAll(realRegQueryInfoKeyW, regQueryInfoKey, "RegQueryInfoKeyW");
        attachAll(realRegOpenCurrentUser, regOpenCurrentUser, "RegOpenCurrentUser");
        attachAll(realRegGetValueW, regGetValue, "RegGetValueW");
        attachAll(realRegSetKeyValueW, regSetKeyValue, "RegSetKeyValueW");
        attachAll(realRegDeleteKeyValueW, regDeleteKeyValue, "RegDeleteKeyValueW");
        attachAll(realRegOpenKeyExA, regOpenA, "RegOpenKeyExA");
        attachAll(realRegCreateKeyExA, regCreateA, "RegCreateKeyExA");
        attachAll(realRegDeleteKeyExA, regDeleteExA, "RegDeleteKeyExA");
        attachAll(realRegDeleteKeyA, regDeleteA, "RegDeleteKeyA");
        attachAll(realRegDeleteTreeA, regDeleteTreeA, "RegDeleteTreeA");
        attachAll(realRegSetValueExA, regSetValueA, "RegSetValueExA");
        attachAll(realRegQueryValueExA, regQueryValueA, "RegQueryValueExA");
        attachAll(realRegDeleteValueA, regDeleteValueA, "RegDeleteValueA");
        attachAll(realRegEnumKeyExA, regEnumKeyExA, "RegEnumKeyExA");
        attachAll(realRegQueryInfoKeyA, regQueryInfoKeyA, "RegQueryInfoKeyA");
        attachAll(realRegGetValueA, regGetValueA, "RegGetValueA");
        attachAll(realRegConnectRegistryW, regConnectW, "RegConnectRegistryW");
        attachAll(realRegConnectRegistryA, regConnectA, "RegConnectRegistryA");
        attachAll(realCreateProcessW, createProcessW, "CreateProcessW");
        attachAll(realCreateMutexW, createMutexW, "CreateMutexW");
        attachAll(realCreateMutexExW, createMutexExW, "CreateMutexExW");
        attachAll(realOpenMutexW, openMutexW, "OpenMutexW");
        attachAll(realCreateEventW, createEventW, "CreateEventW");
        attachAll(realCreateEventExW, createEventExW, "CreateEventExW");
        attachAll(realOpenEventW, openEventW, "OpenEventW");
        attachAll(realCreateSemaphoreW, createSemaphoreW, "CreateSemaphoreW");
        attachAll(realCreateSemaphoreExW, createSemaphoreExW, "CreateSemaphoreExW");
        attachAll(realOpenSemaphoreW, openSemaphoreW, "OpenSemaphoreW");
        attachAll(realCreateFileMappingW, createFileMappingW, "CreateFileMappingW");
        attachAll(realOpenFileMappingW, openFileMappingW, "OpenFileMappingW");
        attachAll(realCreateMutexA, createMutexA, "CreateMutexA");
        attachAll(realOpenMutexA, openMutexA, "OpenMutexA");
        attachAll(realCreateEventA, createEventA, "CreateEventA");
        attachAll(realOpenEventA, openEventA, "OpenEventA");
        attachAll(realCreateFileMappingA, createFileMappingA, "CreateFileMappingA");
        attachAll(realOpenFileMappingA, openFileMappingA, "OpenFileMappingA");
        if (auto user = GetModuleHandleW(L"user32.dll")) {
            windowProcess =
                reinterpret_cast<WindowProcessRoutine>(GetProcAddress(user, "GetWindowThreadProcessId"));
            realFindWindowExW = reinterpret_cast<FindWindowExWRoutine>(GetProcAddress(user, "FindWindowExW"));
            realFindWindowExA = reinterpret_cast<FindWindowExARoutine>(GetProcAddress(user, "FindWindowExA"));
            realFindWindowW = reinterpret_cast<FindWindowWRoutine>(GetProcAddress(user, "FindWindowW"));
            realFindWindowA = reinterpret_cast<FindWindowARoutine>(GetProcAddress(user, "FindWindowA"));
            if (windowProcess && realFindWindowExW && realFindWindowExA && realFindWindowW &&
                realFindWindowA) {
                attach(realFindWindowExW, findWindowExW);
                attach(realFindWindowExA, findWindowExA);
                attach(realFindWindowW, findWindowW);
                attach(realFindWindowA, findWindowA);
            }
        }
        attachAll(realCreateProcessA, createProcessA, "CreateProcessA");
        // These restrictions only implement the optional blocking IPv4 proxy. A direct
        // connection needs no Winsock patches at all (games also use UDP and async I/O).
        if (configuration.managedProxy) {
            attach(realSocket, socketHook);
            attach(realWSASocketW, wsaSocketHook);
            attach(realWSASocketA, wsaSocketAHook);
            attach(realConnect, connectHook);
            attach(realWSAConnect, wsaConnectHook);
            attach(realIoctlSocket, ioctlSocketHook);
            attach(realWSAIoctl, wsaIoctlHook);
            attach(realSendTo, sendToHook);
            attach(realWSASendTo, wsaSendToHook);
            attach(realWSAEventSelect, eventSelectHook);
            attach(realWSAAsyncSelect, asyncSelectHook);
        }
        return DetourTransactionCommit() == NO_ERROR;
    } catch (...) {
        DetourTransactionAbort();
        return false;
    }
}
}
}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    using namespace nb::runtime;
    if (reason != DLL_PROCESS_ATTACH || DetourIsHelperProcess())
        return TRUE;
    try {
        Guard guard;
        wchar_t value[64]{};
        auto length = GetEnvironmentVariableW(L"NATIVEBOX_SESSION_MAP", value, DWORD(std::size(value)));
        if (!length)
            return TRUE;
        if (length != 32 || !std::all_of(value, value + 32, [](wchar_t c) { return iswxdigit(c); }))
            return FALSE;
        const std::wstring nonce(value, 32);
        Handle mapping(OpenFileMappingW(FILE_MAP_READ, FALSE, sessionMappingName(nonce).c_str()));
        if (!mapping.get())
            return FALSE;
        auto memory = MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, sizeof(Configuration));
        if (!memory)
            return FALSE;
        memcpy(&configuration, memory, sizeof(Configuration));
        UnmapViewOfFile(memory);
        if (configuration.magic != ProtocolMagic || configuration.version != ProtocolVersion ||
            configuration.bytes != sizeof(Configuration) ||
            configuration.architecture != sizeof(void *) * 8 || configuration.fileRootCount > 26 ||
            configuration.registryRootCount > 8 ||
            !wmemchr(configuration.dataRoot, 0, std::size(configuration.dataRoot)) ||
            !wmemchr(configuration.runtimeDll, 0, std::size(configuration.runtimeDll)) ||
            !wmemchr(configuration.runId, 0, std::size(configuration.runId)) ||
            !wmemchr(configuration.excludeRoot, 0, std::size(configuration.excludeRoot)) ||
            configuration.proxyPort > 65535 ||
            !memchr(configuration.proxyAddress, 0, sizeof(configuration.proxyAddress)) ||
            !memchr(configuration.proxyProtocol, 0, sizeof(configuration.proxyProtocol)) ||
            !wmemchr(configuration.profileId, 0, std::size(configuration.profileId)) ||
            !memchr(configuration.sha64, 0, sizeof(configuration.sha64)) ||
            !memchr(configuration.sha32, 0, sizeof(configuration.sha32)))
            return FALSE;
        for (uint32_t index = 0; index < configuration.fileRootCount; ++index)
            if (!wmemchr(configuration.fileRoots[index], 0, std::size(configuration.fileRoots[index])))
                return FALSE;
        for (uint32_t index = 0; index < configuration.registryRootCount; ++index)
            if (!wmemchr(configuration.registryRoots[index].prefix, 0,
                         std::size(configuration.registryRoots[index].prefix)) ||
                (configuration.registryRoots[index].root != 1 &&
                 configuration.registryRoots[index].root != 2))
                return FALSE;
        if (!DetourRestoreAfterWith())
            return FALSE;
        HMODULE pinned = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(module), &pinned))
            return FALSE;
        if (!install())
            return FALSE;
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, sessionReadyName(nonce).c_str()));
        return ready.get() && SetEvent(ready.get());
    } catch (...) {
        // No C++ exception may unwind through the Windows loader into the host process.
        return FALSE;
    }
}

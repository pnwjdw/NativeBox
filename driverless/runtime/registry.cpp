#include "driverless/runtime/registry.h"
#include <sddl.h>

namespace nb::runtime {
void createPrivateHive(const std::wstring &input, const std::wstring &offlineLibrary) {
    auto path = canonical(input), libraryPath = canonical(offlineLibrary);
    noReparse(path);
    noReparse(libraryPath);
    if (GetFileAttributesW(extendedPath(path).c_str()) != INVALID_FILE_ATTRIBUTES)
        return;
    Handle pinned(CreateFileW(extendedPath(libraryPath).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr));
    require(pinned.get() != INVALID_HANDLE_VALUE, "Pin offline registry library");
    if (sha256(libraryPath) != "453c52750a193fb250209b9928b04a70398a8de94c967df72e8bb03af47c1956")
        throw Error(ERROR_INVALID_DATA, "Offline registry library differs from the recorded Microsoft pin");
    HMODULE library = LoadLibraryExW(extendedPath(libraryPath).c_str(), nullptr,
                                     LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library)
        throw Error(GetLastError(), "Load pinned offline registry library");
    struct Module {
        HMODULE value;
        ~Module() { FreeLibrary(value); }
    } release{library};
    using Create = DWORD(WINAPI *)(HANDLE *);
    using Save = DWORD(WINAPI *)(HANDLE, LPCWSTR, DWORD, DWORD);
    using Close = DWORD(WINAPI *)(HANDLE);
    using Security = DWORD(WINAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    auto create = reinterpret_cast<Create>(GetProcAddress(library, "ORCreateHive"));
    auto save = reinterpret_cast<Save>(GetProcAddress(library, "ORSaveHive"));
    auto close = reinterpret_cast<Close>(GetProcAddress(library, "ORCloseHive"));
    auto security = reinterpret_cast<Security>(GetProcAddress(library, "ORSetKeySecurity"));
    if (!create || !save || !close || !security)
        throw Error(ERROR_PROC_NOT_FOUND, "Required offline registry exports are absent");
    HANDLE hive = nullptr;
    registryCheck(create(&hive), "Create empty private hive");
    struct Hive {
        HANDLE value;
        Close close;
        ~Hive() { close(value); }
    } unload{hive, close};
    HANDLE tokenValue = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenValue), "Read private hive owner");
    Handle token(tokenValue);
    DWORD count = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &count);
    if (!count || count > 65536)
        throw Error(ERROR_INVALID_DATA, "Invalid owner token size");
    std::vector<BYTE> data(count);
    require(GetTokenInformation(token.get(), TokenUser, data.data(), count, &count), "Read owner SID");
    LPWSTR sid = nullptr;
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &sid),
            "Format owner SID");
    auto sddl = std::wstring(L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;") + sid + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor,
                                                                 nullptr),
            "Prepare private hive ACL");
    auto status = security(hive, DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    registryCheck(status, "Set private hive owner ACL");
    directories(std::filesystem::path(path).parent_path().wstring());
    registryCheck(save(hive, extendedPath(path).c_str(), 6, 1), "Save empty private hive");
}
namespace {
HKEY loadHive(const std::wstring &root) {
    auto path = canonical(root + L"\\private.hive");
    noReparse(path);
    HKEY hive = nullptr;
    registryCheck(RegLoadAppKeyW(extendedPath(path).c_str(), &hive, KEY_ALL_ACCESS, 0, 0),
                  "Load process-local private hive");
    return hive;
}
constexpr DWORD Deleted = 1, Opaque = 2;
std::vector<std::wstring> components(const std::wstring &path) {
    std::vector<std::wstring> result;
    for (size_t start = 0; start < path.size();) {
        auto end = path.find(L'\\', start);
        auto part = path.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
        if (part.empty() || part.size() > 255)
            throw Error(ERROR_INVALID_PARAMETER, "Invalid registry path component");
        result.push_back(part);
        if (end == std::wstring::npos)
            break;
        start = end + 1;
    }
    if (result.size() > 512)
        throw Error(ERROR_INVALID_PARAMETER, "Registry path is too deep");
    return result;
}
RegistryPath parentOf(const RegistryPath &key) {
    auto result = key;
    auto separator = key.path.find_last_of(L'\\');
    result.path = separator == std::wstring::npos ? std::wstring() : key.path.substr(0, separator);
    return result;
}
RegistryPath childOf(const RegistryPath &key, const std::wstring &name) {
    auto result = key;
    result.path = key.path.empty() ? name : key.path + L"\\" + name;
    return result;
}
void copyValues(HKEY source, HKEY destination) {
    std::vector<wchar_t> name(16384 + 2);
    std::vector<BYTE> data(65536);
    for (DWORD index = 0;; ++index) {
        DWORD characters = DWORD(name.size()), size = DWORD(data.size()), type = 0;
        auto status = RegEnumValueW(source, index, name.data(), &characters, nullptr, &type, data.data(), &size);
        if (status == ERROR_MORE_DATA) {
            if (size > 256u * 1024 * 1024)
                throw Error(ERROR_NOT_ENOUGH_MEMORY, "Registry value is too large to copy");
            data.resize(size_t(size) + 16);
            --index;
            continue;
        }
        if (status == ERROR_NO_MORE_ITEMS)
            break;
        registryCheck(status, "Read original registry value");
        registryCheck(RegSetValueExW(destination, name.data(), 0, type, data.data(), size),
                      "Write private registry value");
    }
}
std::vector<std::wstring> enumerateNames(HKEY key) {
    std::vector<std::wstring> result;
    for (DWORD index = 0;; ++index) {
        wchar_t name[256]{};
        DWORD count = 256;
        auto status = RegEnumKeyExW(key, index, name, &count, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS)
            break;
        registryCheck(status, "Enumerate registry subkeys");
        result.emplace_back(name, count);
    }
    return result;
}
}
RegistryStore::RegistryStore(const std::wstring &privateDirectory)
    : hive_(loadHive(privateDirectory)), lock_(privateDirectory) {}
bool RegistryStore::writes(REGSAM access) {
    return access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER |
                     GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED);
}
std::wstring RegistryStore::dataPath(const RegistryPath &key) const {
    return std::wstring(L"data\\") + key.root + (key.path.empty() ? L"" : L"\\" + key.path);
}
std::wstring RegistryStore::metaPath(const RegistryPath &key) const {
    return std::wstring(L"meta\\") + key.root + (key.path.empty() ? L"" : L"\\" + key.path);
}
bool RegistryStore::privateExists(const RegistryPath &key) const {
    HKEY raw = nullptr;
    if (RegOpenKeyExW(hive_.get(), dataPath(key).c_str(), 0, KEY_QUERY_VALUE, &raw) != ERROR_SUCCESS)
        return false;
    RegCloseKey(raw);
    return true;
}
DWORD RegistryStore::state(const RegistryPath &key) const {
    HKEY raw = nullptr;
    if (RegOpenKeyExW(hive_.get(), metaPath(key).c_str(), 0, KEY_QUERY_VALUE, &raw) != ERROR_SUCCESS)
        return 0;
    Key meta(raw);
    DWORD value = 0, type = 0, size = sizeof(value);
    if (RegQueryValueExW(meta.get(), L"State", nullptr, &type, reinterpret_cast<BYTE *>(&value), &size) !=
            ERROR_SUCCESS ||
        type != REG_DWORD)
        return 0;
    return value;
}
void RegistryStore::setState(const RegistryPath &key, DWORD value) {
    if (!value) {
        HKEY raw = nullptr;
        if (RegOpenKeyExW(hive_.get(), metaPath(key).c_str(), 0, KEY_SET_VALUE, &raw) == ERROR_SUCCESS) {
            RegDeleteValueW(raw, L"State");
            RegCloseKey(raw);
        }
        return;
    }
    HKEY raw = nullptr;
    registryCheck(RegCreateKeyExW(hive_.get(), metaPath(key).c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &raw,
                                  nullptr),
                  "Create private registry metadata");
    Key meta(raw);
    registryCheck(RegSetValueExW(meta.get(), L"State", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&value),
                                 sizeof(value)),
                  "Write private registry metadata");
}
bool RegistryStore::originalVisible(const RegistryPath &key) const {
    HKEY raw = nullptr;
    if (RegOpenKeyExW(hive_.get(), (std::wstring(L"meta\\") + key.root).c_str(), 0, KEY_READ, &raw) !=
        ERROR_SUCCESS)
        return true;
    Key current(raw);
    for (const auto &part : components(key.path)) {
        HKEY next = nullptr;
        if (RegOpenKeyExW(current.get(), part.c_str(), 0, KEY_READ, &next) != ERROR_SUCCESS)
            return true;
        Key child(next);
        DWORD value = 0, type = 0, size = sizeof(value);
        if (RegQueryValueExW(child.get(), L"State", nullptr, &type, reinterpret_cast<BYTE *>(&value), &size) ==
                ERROR_SUCCESS &&
            type == REG_DWORD && (value == Deleted || value == Opaque))
            return false;
        std::swap(current, child);
    }
    return true;
}
HKEY RegistryStore::openOriginal(const RegistryPath &key, REGSAM access, LSTATUS &status) const {
    HKEY root = key.root == L'M' ? HKEY_LOCAL_MACHINE : key.root == L'C' ? HKEY_CLASSES_ROOT : HKEY_CURRENT_USER;
    REGSAM view = key.root == L'M' ? KEY_WOW64_64KEY : key.view;
    HKEY result = nullptr;
    status = RegOpenKeyExW(root, key.path.empty() ? nullptr : key.path.c_str(), 0, access | view, &result);
    return status == ERROR_SUCCESS ? result : nullptr;
}
void RegistryStore::materialize(const RegistryPath &key) {
    auto parts = components(key.path);
    RegistryPath current{key.root, L"", key.view};
    for (size_t level = 0; level <= parts.size(); ++level) {
        if (level)
            current = childOf(current, parts[level - 1]);
        if (privateExists(current))
            continue;
        LSTATUS status = ERROR_FILE_NOT_FOUND;
        Key original(originalVisible(current) ? openOriginal(current, KEY_READ, status) : nullptr);
        HKEY raw = nullptr;
        registryCheck(RegCreateKeyExW(hive_.get(), dataPath(current).c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr,
                                      &raw, nullptr),
                      "Create private registry key");
        Key copy(raw);
        try {
            if (original.get())
                copyValues(original.get(), copy.get());
        } catch (...) {
            // A failed value copy must not turn a partly populated key into the persistent private
            // version. Readers hold the same storage lock, so no caller can observe this key yet.
            copy = Key();
            RegDeleteKeyW(hive_.get(), dataPath(current).c_str());
            throw;
        }
        if (state(current) == Deleted)
            setState(current, Opaque);
    }
}
HKEY RegistryStore::open(const RegistryPath &key, REGSAM access, bool create, DWORD *disposition, bool &isPrivate) {
    components(key.path);
    // Serialize the entire decision and copy with readers and writers in other target processes.
    // Locking only immediately before materialize exposed the newly created, still empty key.
    StorageLock::Guard guard(lock_);
    REGSAM clean = access & ~(KEY_WOW64_32KEY | KEY_WOW64_64KEY | ACCESS_SYSTEM_SECURITY);
    HKEY result = nullptr;
    if (privateExists(key)) {
        registryCheck(RegOpenKeyExW(hive_.get(), dataPath(key).c_str(), 0, clean, &result), "Open private registry key");
        isPrivate = true;
        if (disposition)
            *disposition = REG_OPENED_EXISTING_KEY;
        return result;
    }
    bool write = writes(access);
    LSTATUS status = ERROR_FILE_NOT_FOUND;
    HKEY original = originalVisible(key) ? openOriginal(key, write ? KEY_READ : clean, status) : nullptr;
    if (!original && status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND)
        throw Error(DWORD(status), "Open original registry key");
    bool exists = original != nullptr;
    if (!exists && !create)
        throw Error(ERROR_FILE_NOT_FOUND, "Registry key does not exist");
    if (exists && !write) {
        isPrivate = false;
        if (disposition)
            *disposition = REG_OPENED_EXISTING_KEY;
        return original;
    }
    if (original)
        RegCloseKey(original);
    bool already = privateExists(key);
    materialize(key);
    registryCheck(RegOpenKeyExW(hive_.get(), dataPath(key).c_str(), 0, clean, &result), "Open private registry key");
    isPrivate = true;
    if (disposition)
        *disposition = exists || already ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
    return result;
}
bool RegistryStore::exists(const RegistryPath &key) const {
    StorageLock::Guard guard(lock_);
    return existsUnlocked(key);
}
bool RegistryStore::hasPrivate(const RegistryPath &key) const {
    StorageLock::Guard guard(lock_);
    return privateExists(key);
}
bool RegistryStore::existsUnlocked(const RegistryPath &key) const {
    if (privateExists(key))
        return true;
    if (!originalVisible(key))
        return false;
    LSTATUS status = ERROR_FILE_NOT_FOUND;
    Key original(openOriginal(key, KEY_QUERY_VALUE, status));
    return original.get() || status == ERROR_ACCESS_DENIED;
}
std::vector<std::wstring> RegistryStore::subkeys(const RegistryPath &key) const {
    StorageLock::Guard guard(lock_);
    return subkeysUnlocked(key);
}
std::vector<std::wstring> RegistryStore::subkeysUnlocked(const RegistryPath &key) const {
    std::map<std::wstring, bool, OrdinalLess> merged;
    HKEY raw = nullptr;
    if (RegOpenKeyExW(hive_.get(), dataPath(key).c_str(), 0, KEY_READ, &raw) == ERROR_SUCCESS) {
        Key own(raw);
        for (auto &name : enumerateNames(own.get()))
            merged.emplace(std::move(name), true);
    }
    if (originalVisible(key)) {
        LSTATUS status = ERROR_FILE_NOT_FOUND;
        Key original(openOriginal(key, KEY_ENUMERATE_SUB_KEYS, status));
        if (original.get())
            for (auto &name : enumerateNames(original.get()))
                if (!merged.contains(name) && state(childOf(key, name)) != Deleted)
                    merged.emplace(std::move(name), false);
    }
    std::vector<std::wstring> result;
    for (auto &entry : merged)
        result.push_back(entry.first);
    return result;
}
void RegistryStore::deleteOne(const RegistryPath &key) {
    if (key.path.empty())
        throw Error(ERROR_ACCESS_DENIED, "Registry roots cannot be deleted");
    if (!existsUnlocked(key))
        throw Error(ERROR_FILE_NOT_FOUND, "Registry key does not exist");
    if (!subkeysUnlocked(key).empty())
        throw Error(ERROR_ACCESS_DENIED, "Registry key has subkeys");
    materialize(parentOf(key));
    if (privateExists(key))
        registryCheck(RegDeleteKeyW(hive_.get(), dataPath(key).c_str()), "Delete private registry key");
    LSTATUS status = ERROR_FILE_NOT_FOUND;
    Key original(openOriginal(key, KEY_QUERY_VALUE, status));
    setState(key, original.get() || status == ERROR_ACCESS_DENIED ? Deleted : 0);
}
void RegistryStore::deleteTreeUnlocked(const RegistryPath &key) {
    for (const auto &name : subkeysUnlocked(key))
        deleteTreeUnlocked(childOf(key, name));
    deleteOne(key);
}
void RegistryStore::removeKey(const RegistryPath &key) {
    StorageLock::Guard guard(lock_);
    deleteOne(key);
}
void RegistryStore::removeTree(const RegistryPath &key) {
    StorageLock::Guard guard(lock_);
    if (!existsUnlocked(key))
        throw Error(ERROR_FILE_NOT_FOUND, "Registry key does not exist");
    deleteTreeUnlocked(key);
}
void RegistryStore::clearTree(const RegistryPath &key) {
    StorageLock::Guard guard(lock_);
    if (!existsUnlocked(key))
        throw Error(ERROR_FILE_NOT_FOUND, "Registry key does not exist");
    for (const auto &name : subkeysUnlocked(key))
        deleteTreeUnlocked(childOf(key, name));
    materialize(key);
    HKEY raw = nullptr;
    registryCheck(RegOpenKeyExW(hive_.get(), dataPath(key).c_str(), 0, KEY_ALL_ACCESS, &raw),
                  "Open private registry key for clearing");
    Key own(raw);
    for (;;) {
        wchar_t name[16384]{};
        DWORD count = 16384;
        auto status = RegEnumValueW(own.get(), 0, name, &count, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS)
            break;
        registryCheck(status, "Enumerate private registry values");
        registryCheck(RegDeleteValueW(own.get(), name), "Delete private registry value");
    }
}
void RegistryStore::flush() {
    StorageLock::Guard guard(lock_);
    registryCheck(RegFlushKey(hive_.get()), "Flush private registry hive");
}
}

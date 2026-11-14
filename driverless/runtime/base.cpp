#include "driverless/runtime/base.h"
#include <bcrypt.h>
#include <array>

namespace nb::runtime {
bool same(const std::wstring &left, const std::wstring &right) {
    return CompareStringOrdinal(left.c_str(), int(left.size()), right.c_str(), int(right.size()), TRUE) ==
           CSTR_EQUAL;
}
bool beneath(const std::wstring &path, const std::wstring &root) {
    if (same(path, root))
        return true;
    if (!root.empty() && root.back() == L'\\')
        return path.size() > root.size() && same(path.substr(0, root.size()), root);
    return path.size() > root.size() && path[root.size()] == L'\\' && same(path.substr(0, root.size()), root);
}
std::wstring extendedPath(const std::wstring &path) {
    if (path.starts_with(L"\\\\?\\"))
        return path;
    if (path.starts_with(L"\\??\\"))
        return L"\\\\?\\" + path.substr(4);
    if (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\')
        return L"\\\\?\\" + path;
    return L"\\\\?\\" + canonical(path);
}
std::wstring longForm(const std::wstring &path, unsigned depth) {
    if (depth > 64 || path.size() <= 3)
        return path;
    DWORD size = GetLongPathNameW(extendedPath(path).c_str(), nullptr, 0);
    if (size && size < 32760) {
        std::vector<wchar_t> storage(size + 1);
        auto count = GetLongPathNameW(extendedPath(path).c_str(), storage.data(), DWORD(storage.size()));
        if (count && count < storage.size()) {
            std::wstring result(storage.data(), count);
            return result.starts_with(L"\\\\?\\") ? result.substr(4) : result;
        }
    }
    auto separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos || separator < 2)
        return path;
    return longForm(path.substr(0, separator), depth + 1) + path.substr(separator);
}
std::wstring canonical(const std::wstring &input) {
    auto value = input;
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.starts_with(L"\\\\?\\") || value.starts_with(L"\\??\\")) {
        // Only \\?\X:\ is a file system path; \\?\pipe\, \\?\UNC\, \\?\GLOBALROOT\ ... are other namespaces.
        if (value.size() < 7 || !iswalpha(value[4]) || value[5] != L':' || value[6] != L'\\')
            throw Error(ERROR_NOT_SUPPORTED, "Non-drive Win32 namespace");
        value.erase(0, 4);
    }
    if (value.starts_with(L"\\\\") || value.empty() ||
        value.find_first_of(L"*?\"<>|") != std::wstring::npos ||
        std::any_of(value.begin(), value.end(), [](wchar_t c) { return c < 32; }))
        throw Error(ERROR_NOT_SUPPORTED, "Unsupported path namespace or characters");
    for (const auto &part : std::filesystem::path(value).relative_path()) {
        auto component = part.wstring();
        // GetFullPathName may discard a final dot/space. Reject ambiguous file components before
        // normalization so the host and overlay cannot interpret the same spelling differently.
        if (component != L"." && component != L".." && !component.empty() &&
            (component.back() == L'.' || component.back() == L' '))
            throw Error(ERROR_NOT_SUPPORTED, "Ambiguous trailing path character");
        auto stem = component.substr(0, component.find(L'.'));
        if (same(stem, L"CON") || same(stem, L"PRN") || same(stem, L"AUX") || same(stem, L"NUL") ||
            (stem.size() == 4 && (same(stem.substr(0, 3), L"COM") || same(stem.substr(0, 3), L"LPT")) &&
             ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == 0xB9 || stem[3] == 0xB2 || stem[3] == 0xB3)))
            throw Error(ERROR_NOT_SUPPORTED, "DOS device aliases are outside file coverage");
    }
    DWORD size = GetFullPathNameW(value.c_str(), 0, nullptr, nullptr);
    if (!size || size > 32760)
        throw Error(ERROR_FILENAME_EXCED_RANGE, "Invalid absolute path length");
    std::vector<wchar_t> storage(size + 1);
    auto count = GetFullPathNameW(value.c_str(), DWORD(storage.size()), storage.data(), nullptr);
    require(count > 0 && count < storage.size(), "Canonicalize DOS path");
    value.assign(storage.data(), count);
    if (value.size() < 3 || value[1] != L':' || value[2] != L'\\' ||
        value.find(L':', 2) != std::wstring::npos)
        throw Error(ERROR_NOT_SUPPORTED, "Only local DOS paths without alternate streams are supported");
    while (value.size() > 3 && value.back() == L'\\')
        value.pop_back();
    if (value.find(L'~') != std::wstring::npos)
        value = longForm(value, 0);
    for (const auto &part : std::filesystem::path(value).relative_path()) {
        auto component = part.wstring();
        if (!component.empty() && (component.back() == L'.' || component.back() == L' '))
            throw Error(ERROR_NOT_SUPPORTED, "Ambiguous trailing path character");
    }
    return value;
}
std::wstring resolveLinks(const std::wstring &input) {
    auto value = canonical(input);
    for (unsigned hop = 0; hop < 32; ++hop) {
        bool changed = false;
        for (size_t index = 4; index <= value.size(); ++index) {
            if (index != value.size() && value[index] != L'\\')
                continue;
            auto prefix = value.substr(0, index);
            auto physical = extendedPath(prefix);
            auto attributes = GetFileAttributesW(physical.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                auto error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                    return value;
                if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION)
                    continue;
                throw Error(error, "Inspect path component");
            }
            if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                continue;
            WIN32_FIND_DATAW data{};
            HANDLE search =
                FindFirstFileExW(physical.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
            if (search == INVALID_HANDLE_VALUE)
                continue;
            FindClose(search);
            // Cloud placeholders, deduplicated files and similar tags behave like ordinary entries.
            if (!IsReparseTagNameSurrogate(data.dwReserved0))
                continue;
            Handle target(CreateFileW(physical.c_str(), FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (target.get() == INVALID_HANDLE_VALUE)
                throw Error(GetLastError(), "Resolve link target");
            std::vector<wchar_t> storage(32768);
            auto count = GetFinalPathNameByHandleW(target.get(), storage.data(), DWORD(storage.size()),
                                                   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (!count || count >= storage.size())
                throw Error(GetLastError(), "Read link target");
            std::wstring resolved(storage.data(), count);
            if (resolved.starts_with(L"\\\\?\\UNC\\"))
                throw Error(ERROR_NOT_SUPPORTED, "Links to network locations are outside file coverage");
            if (resolved.starts_with(L"\\\\?\\"))
                resolved.erase(0, 4);
            value = canonical(resolved + value.substr(index));
            changed = true;
            break;
        }
        if (!changed)
            return value;
    }
    throw Error(ERROR_CANT_RESOLVE_FILENAME, "Too many nested links");
}
void noReparse(const std::wstring &path) {
    auto value = canonical(path);
    for (size_t index = 3; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != L'\\')
            continue;
        auto prefix = value.substr(0, index);
        auto attributes = GetFileAttributesW(extendedPath(prefix).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                continue;
            throw Error(error, "Inspect path component");
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
            throw Error(ERROR_NOT_SUPPORTED, "Reparse points are outside runtime coverage");
    }
}
void directories(const std::wstring &path) {
    noReparse(path);
    std::error_code error;
    std::filesystem::create_directories(extendedPath(canonical(path)), error);
    if (error)
        throw Error(DWORD(error.value()), "Create private storage directories");
    noReparse(path);
}
void registryCheck(LSTATUS code, const char *operation) {
    if (code != ERROR_SUCCESS)
        throw Error(DWORD(code), operation);
}
std::string sha256(const std::wstring &path) {
    Handle file(CreateFileW(extendedPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    require(file.get() != INVALID_HANDLE_VALUE, "Pin hash input");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw Error(ERROR_INVALID_FUNCTION, "Open SHA-256 provider");
    struct Algorithm {
        BCRYPT_ALG_HANDLE value;
        ~Algorithm() { BCryptCloseAlgorithmProvider(value, 0); }
    } release{algorithm};
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0)
        throw Error(ERROR_INVALID_FUNCTION, "Create SHA-256 state");
    struct Hash {
        BCRYPT_HASH_HANDLE value;
        ~Hash() { BCryptDestroyHash(value); }
    } finish{hash};
    std::vector<BYTE> bytes(65536);
    DWORD count = 0;
    for (;;) {
        require(ReadFile(file.get(), bytes.data(), DWORD(bytes.size()), &count, nullptr), "Read hash input");
        if (!count)
            break;
        if (BCryptHashData(hash, bytes.data(), count, 0) < 0)
            throw Error(ERROR_INVALID_FUNCTION, "Update SHA-256 state");
    }
    std::array<BYTE, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), DWORD(digest.size()), 0) < 0)
        throw Error(ERROR_INVALID_FUNCTION, "Finish SHA-256 state");
    std::string result;
    constexpr char alphabet[] = "0123456789abcdef";
    for (auto value : digest) {
        result += alphabet[value >> 4];
        result += alphabet[value & 15];
    }
    return result;
}
StorageLock::StorageLock(const std::wstring &root)
    : file_(CreateFileW((extendedPath(root) + L"\\state.lock").c_str(), GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                        nullptr)) {
    require(file_.get() != INVALID_HANDLE_VALUE, "Open private mutation lock");
}
StorageLock::Guard::Guard(const StorageLock &lock) : file_(lock.file_.get()) {
    auto deadline = GetTickCount64() + 5000;
    while (!LockFileEx(file_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset_)) {
        auto error = GetLastError();
        if (error != ERROR_LOCK_VIOLATION)
            throw Error(error, "Acquire private mutation lock");
        if (GetTickCount64() >= deadline)
            throw Error(ERROR_TIMEOUT, "Private mutation lock timed out");
        Sleep(2);
    }
}
StorageLock::Guard::~Guard() {
    auto code = GetLastError();
    UnlockFileEx(file_, 0, 1, 0, &offset_);
    SetLastError(code);
}
}

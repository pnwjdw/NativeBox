#include "driverless/runtime/files.h"

namespace nb::runtime {
namespace {
bool exists(const std::wstring &path) {
    auto attributes = GetFileAttributesW(extendedPath(path).c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
        return true;
    auto code = GetLastError();
    if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND)
        throw Error(code, "Inspect overlay entry");
    return false;
}
std::wstring parentPath(const std::wstring &path) {
    return std::filesystem::path(path).parent_path().wstring();
}
}
FileStore::FileStore(std::wstring logicalRoot, std::wstring privateRoot, std::wstring excludedRoot)
    : logical_(canonical(logicalRoot)), private_(canonical(privateRoot)), files_(private_ + L"\\files"),
      deleted_(private_ + L"\\deleted"),
      excluded_(excludedRoot.empty() ? std::wstring() : canonical(excludedRoot)) {
    // Private storage may live inside the logical scope (whole-drive redirection); it is then excluded.
    if (beneath(logical_, private_))
        throw Error(ERROR_INVALID_PARAMETER, "Logical scope must not live inside private storage");
    if (beneath(private_, logical_) && (excluded_.empty() || !beneath(private_, excluded_)))
        throw Error(ERROR_INVALID_PARAMETER, "Private storage inside the scope must be excluded");
    files_ = extendedPath(files_);
    deleted_ = extendedPath(deleted_);
    noReparse(logical_);
    directories(files_);
    directories(deleted_);
    lock_ = std::make_unique<StorageLock>(private_);
    StorageLock::Guard guard(*lock_);
    recover();
}
void FileStore::recover() {
    auto journal = extendedPath(private_) + L"\\rename.pending";
    if (!exists(journal))
        return;
    std::wstring record;
    {
        Handle file(CreateFileW(journal.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr));
        require(file.get() != INVALID_HANDLE_VALUE, "Read private rename journal");
        LARGE_INTEGER size{};
        require(GetFileSizeEx(file.get(), &size), "Inspect private journal size");
        if (size.QuadPart < 6 || size.QuadPart > 131040 || size.QuadPart % sizeof(wchar_t))
            throw Error(ERROR_INVALID_DATA, "Corrupt private rename journal");
        record.resize(size_t(size.QuadPart) / sizeof(wchar_t));
        DWORD bytes = 0;
        require(ReadFile(file.get(), record.data(), DWORD(size.QuadPart), &bytes, nullptr) &&
                    bytes == DWORD(size.QuadPart),
                "Read complete private rename journal");
    }
    auto separator = record.find(L'\n');
    if (separator == std::wstring::npos || record.find(L'\n', separator + 1) != std::wstring::npos)
        throw Error(ERROR_INVALID_DATA, "Invalid private rename journal fields");
    auto source = record.substr(0, separator), target = record.substr(separator + 1);
    auto from = backing(source), to = backing(target);
    if (!exists(from)) {
        if (!exists(to))
            throw Error(ERROR_INVALID_DATA, "Private rename journal has no recoverable data");
        mark(source, true);
        mark(target, false);
    }
    require(DeleteFileW(journal.c_str()), "Recover private rename metadata");
}
bool FileStore::covers(const std::wstring &path) const {
    auto value = resolveLinks(path);
    return beneath(value, logical_) && !beneath(value, private_) &&
           (excluded_.empty() || !beneath(value, excluded_));
}
std::wstring FileStore::relative(const std::wstring &path) const {
    auto value = resolveLinks(path);
    if (!beneath(value, logical_))
        throw Error(ERROR_INVALID_PARAMETER, "Path is outside configured file scope");
    if (value.size() == logical_.size())
        return L"";
    return value.substr(logical_.size() + (logical_.back() == L'\\' ? 0 : 1));
}
std::wstring FileStore::backing(const std::wstring &path) const {
    auto suffix = relative(path);
    auto result = files_ + (suffix.empty() ? L"" : L"\\" + suffix);
    noReparse(result);
    return result;
}
std::wstring FileStore::marker(const std::wstring &path) const {
    auto suffix = relative(path);
    auto result = deleted_ + (suffix.empty() ? L"\\root" : L"\\entries\\" + suffix + L"\\tombstone");
    noReparse(result);
    return result;
}
bool FileStore::erased(const std::wstring &path) const {
    auto current = canonical(path);
    while (beneath(current, logical_)) {
        if (exists(marker(current)))
            return true;
        if (same(current, logical_))
            break;
        current = parentPath(current);
    }
    return false;
}
void FileStore::mark(const std::wstring &path, bool deleted) {
    auto value = marker(path);
    if (!deleted) {
        if (!DeleteFileW(value.c_str())) {
            auto code = GetLastError();
            if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND)
                throw Error(code, "Clear private tombstone");
        }
        return;
    }
    directories(parentPath(value));
    Handle file(CreateFileW(value.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    require(file.get() != INVALID_HANDLE_VALUE && FlushFileBuffers(file.get()), "Persist private tombstone");
}
DWORD FileStore::attributesUnlocked(const std::wstring &path) const {
    if (erased(path)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    auto physical = backing(path);
    if (exists(physical))
        return GetFileAttributesW(physical.c_str());
    return GetFileAttributesW(extendedPath(canonical(path)).c_str());
}
void FileStore::parent(const std::wstring &path) {
    auto logicalParent = parentPath(canonical(path));
    auto attributes = attributesUnlocked(logicalParent);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw Error(ERROR_PATH_NOT_FOUND, "Logical parent directory is unavailable");
    directories(parentPath(backing(path)));
}
std::wstring FileStore::readPath(const std::wstring &path) const {
    if (erased(path))
        throw Error(ERROR_FILE_NOT_FOUND, "Logical path is deleted");
    auto result = backing(path);
    return exists(result) ? result : extendedPath(canonical(path));
}
std::wstring FileStore::materialize(const std::wstring &path, bool preserve) {
    auto result = backing(path);
    parent(path);
    if (!exists(result) && !erased(path) && preserve && exists(canonical(path))) {
        auto attributes = GetFileAttributesW(extendedPath(canonical(path)).c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            directories(result);
            return result;
        }
        directories(extendedPath(private_) + L"\\staging");
        auto staging = extendedPath(private_) + L"\\staging\\copy-" + std::to_wstring(GetCurrentProcessId()) +
                       L"-" + std::to_wstring(GetTickCount64());
        require(CopyFileW(extendedPath(canonical(path)).c_str(), staging.c_str(), TRUE),
                "Copy original into private staging");
        if (!MoveFileExW(staging.c_str(), result.c_str(), MOVEFILE_WRITE_THROUGH)) {
            auto error = GetLastError();
            DeleteFileW(staging.c_str());
            throw Error(error, "Commit private copy");
        }
    }
    return result;
}
HANDLE FileStore::open(const std::wstring &path, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES security,
                       DWORD disposition, DWORD flags, HANDLE templateFile) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (disposition < CREATE_NEW || disposition > TRUNCATE_EXISTING)
        throw Error(ERROR_INVALID_PARAMETER, "Invalid file disposition");
    bool write = mutates(access, OPEN_EXISTING, flags);
    bool creates = disposition == CREATE_NEW || disposition == CREATE_ALWAYS || disposition == OPEN_ALWAYS;
    auto attributes = attributesUnlocked(path);
    bool originalExists = attributes != INVALID_FILE_ATTRIBUTES;
    if (disposition == CREATE_NEW && originalExists)
        throw Error(ERROR_FILE_EXISTS, "Logical file already exists");
    if (!creates && !originalExists)
        throw Error(ERROR_FILE_NOT_FOUND, "Logical file does not exist");
    // CREATE_ALWAYS skips the initial copy, so Windows cannot inspect the original object's type or
    // read-only attribute at the private destination. Preserve those checks before creating that file.
    if (disposition == CREATE_ALWAYS && originalExists &&
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY)))
        throw Error(ERROR_ACCESS_DENIED, "Logical overwrite target is a directory or read-only");
    bool mutation = write || disposition != OPEN_EXISTING;
    auto physical = mutation ? materialize(path, disposition != CREATE_ALWAYS && disposition != CREATE_NEW)
                             : readPath(path);
    auto result = CreateFileW(physical.c_str(), access, sharing, security, disposition, flags, templateFile);
    auto error = GetLastError();
    if (result != INVALID_HANDLE_VALUE && mutation) {
        try {
            mark(path, false);
        } catch (...) {
            CloseHandle(result);
            throw;
        }
        if (disposition == OPEN_ALWAYS || disposition == CREATE_ALWAYS)
            error = originalExists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
    }
    SetLastError(error);
    return result;
}
bool FileStore::mutates(DWORD access, DWORD disposition, DWORD flags) {
    return (access & (GENERIC_WRITE | GENERIC_ALL | DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                      FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED)) ||
           (flags & FILE_FLAG_DELETE_ON_CLOSE) || disposition != OPEN_EXISTING;
}
void FileStore::reconcile(const std::wstring &path) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (!exists(backing(path)) && !erased(path) && exists(canonical(path)))
        mark(path, true);
}
std::wstring FileStore::resolve(const std::wstring &path) {
    StorageLock::Guard guard(*lock_);
    recover();
    return readPath(path);
}
std::wstring FileStore::prepareTarget(const std::wstring &path) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (same(canonical(path), logical_))
        throw Error(ERROR_ACCESS_DENIED, "Cannot replace the configured scope root");
    parent(path);
    auto target = backing(path);
    if (erased(path) && exists(target)) {
        auto attributes = GetFileAttributesW(target.c_str());
        if (attributes & FILE_ATTRIBUTE_DIRECTORY)
            RemoveDirectoryW(target.c_str());
        else
            DeleteFileW(target.c_str());
    }
    return target;
}
void FileStore::committed(const std::wstring &source, const std::wstring &destination) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (exists(canonical(source)))
        mark(source, true);
    mark(destination, false);
}
void FileStore::importFile(const std::wstring &physical, const std::wstring &destination, bool failIfExists) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (failIfExists && attributesUnlocked(destination) != INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_EXISTS, "Logical copy destination exists");
    parent(destination);
    // Network sources are outside local redirection, but copying one into a private
    // local destination must retain the original UNC path semantics.
    auto source =
        physical.starts_with(L"\\\\") || physical.starts_with(L"//")
            ? physical
            : extendedPath(canonical(physical));
    require(CopyFileW(source.c_str(), backing(destination).c_str(), FALSE), "Copy into private file");
    mark(destination, false);
}
void FileStore::replace(const std::wstring &replaced, const std::wstring &replacement,
                        const std::wstring &backup) {
    StorageLock::Guard guard(*lock_);
    recover();
    auto target = attributesUnlocked(replaced);
    if (target == INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_NOT_FOUND, "Replaced file is absent");
    if (attributesUnlocked(replacement) == INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_NOT_FOUND, "Replacement file is absent");
    if ((target | attributesUnlocked(replacement)) & FILE_ATTRIBUTE_DIRECTORY)
        throw Error(ERROR_ACCESS_DENIED, "ReplaceFile operates on files only");
    if (!backup.empty()) {
        parent(backup);
        require(CopyFileW(readPath(replaced).c_str(), backing(backup).c_str(), FALSE),
                "Create private backup");
        mark(backup, false);
    }
    renameFileUnlocked(replacement, replaced, MOVEFILE_REPLACE_EXISTING);
}
DWORD FileStore::attributes(const std::wstring &path) {
    StorageLock::Guard guard(*lock_);
    recover();
    return attributesUnlocked(path);
}
void FileStore::information(const std::wstring &path, WIN32_FILE_ATTRIBUTE_DATA &value) {
    StorageLock::Guard guard(*lock_);
    recover();
    require(GetFileAttributesExW(readPath(path).c_str(), GetFileExInfoStandard, &value),
            "Read logical file metadata");
}
void FileStore::setAttributes(const std::wstring &path, DWORD attributes) {
    StorageLock::Guard guard(*lock_);
    recover();
    auto current = attributesUnlocked(path);
    if (current == INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_NOT_FOUND, "Logical metadata target is absent");
    if (attributes & ~(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL |
                       FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_READONLY |
                       FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY))
        throw Error(ERROR_NOT_SUPPORTED, "Unsupported logical file attributes");
    require(SetFileAttributesW(materialize(path, true).c_str(), attributes),
            "Update private file attributes");
}
void FileStore::createDirectory(const std::wstring &path, LPSECURITY_ATTRIBUTES security) {
    StorageLock::Guard guard(*lock_);
    recover();
    createDirectoryUnlocked(path, security);
}
void FileStore::createDirectoryUnlocked(const std::wstring &path, LPSECURITY_ATTRIBUTES security) {
    if (attributesUnlocked(path) != INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_ALREADY_EXISTS, "Logical directory already exists");
    parent(path);
    auto physical = backing(path);
    if (!CreateDirectoryW(physical.c_str(), security)) {
        auto code = GetLastError();
        if (code != ERROR_ALREADY_EXISTS ||
            !(GetFileAttributesW(physical.c_str()) & FILE_ATTRIBUTE_DIRECTORY))
            throw Error(code, "Create private directory");
    }
    mark(path, false);
}
void FileStore::remove(const std::wstring &path, bool directory) {
    StorageLock::Guard guard(*lock_);
    recover();
    removeUnlocked(path, directory);
}
void FileStore::removeUnlocked(const std::wstring &path, bool directory) {
    if (same(canonical(path), logical_))
        throw Error(ERROR_ACCESS_DENIED, "Cannot delete the configured scope root");
    auto attributes = attributesUnlocked(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_NOT_FOUND, "Logical deletion target is absent");
    if (directory != bool(attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw Error(ERROR_ACCESS_DENIED, "File/directory deletion type mismatch");
    if (attributes & FILE_ATTRIBUTE_READONLY)
        throw Error(ERROR_ACCESS_DENIED, "Logical deletion target is read-only");
    auto physical = backing(path);
    if (directory) {
        if (!enumerateUnlocked(path, L"*").empty())
            throw Error(ERROR_DIR_NOT_EMPTY, "Logical directory is not empty");
        mark(path, true);
        if (exists(physical) && !RemoveDirectoryW(physical.c_str())) {
            auto code = GetLastError();
            mark(path, false);
            throw Error(code, "Delete private directory");
        }
        return;
    }
    mark(path, true);
    if (exists(physical) && !DeleteFileW(physical.c_str())) {
        auto code = GetLastError();
        mark(path, false);
        throw Error(code, "Delete private file");
    }
}
void FileStore::rename(const std::wstring &source, const std::wstring &destination, DWORD flags) {
    StorageLock::Guard guard(*lock_);
    recover();
    renameUnlocked(source, destination, flags);
}
void FileStore::renameUnlocked(const std::wstring &source, const std::wstring &destination, DWORD flags) {
    if (flags & MOVEFILE_DELAY_UNTIL_REBOOT)
        throw Error(ERROR_NOT_SUPPORTED, "Reboot-time renames are outside sandbox semantics");
    if (same(canonical(source), logical_) || same(canonical(destination), logical_))
        throw Error(ERROR_ACCESS_DENIED, "Cannot rename the configured scope root");
    auto attributes = attributesUnlocked(source);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_NOT_FOUND, "Logical rename source is absent");
    if (same(canonical(source), canonical(destination)))
        return;
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        renameFileUnlocked(source, destination, flags);
        return;
    }
    if (beneath(canonical(destination), canonical(source)))
        throw Error(ERROR_SHARING_VIOLATION, "Cannot move a directory beneath itself");
    if (attributesUnlocked(destination) != INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_ALREADY_EXISTS, "Logical rename destination exists");
    createDirectoryUnlocked(destination, nullptr);
    for (const auto &entry : enumerateUnlocked(source, L"*")) {
        auto from = canonical(source) + L"\\" + entry.cFileName,
             to = canonical(destination) + L"\\" + entry.cFileName;
        renameUnlocked(from, to, 0);
    }
    removeUnlocked(source, true);
}
void FileStore::renameFileUnlocked(const std::wstring &source, const std::wstring &destination, DWORD flags) {
    flags &= MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    auto target = attributesUnlocked(destination);
    if (target != INVALID_FILE_ATTRIBUTES &&
        (!(flags & MOVEFILE_REPLACE_EXISTING) || (target & FILE_ATTRIBUTE_DIRECTORY)))
        throw Error(target & FILE_ATTRIBUTE_DIRECTORY ? ERROR_ACCESS_DENIED : ERROR_ALREADY_EXISTS,
                    "Logical rename destination exists");
    if (target != INVALID_FILE_ATTRIBUTES && (target & FILE_ATTRIBUTE_READONLY))
        throw Error(ERROR_ACCESS_DENIED, "Logical rename destination is read-only");
    auto from = materialize(source, true);
    parent(destination);
    auto to = backing(destination);
    if (target == INVALID_FILE_ATTRIBUTES && exists(to)) {
        // stale private entry under a tombstone
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    if (target != INVALID_FILE_ATTRIBUTES)
        flags |= MOVEFILE_REPLACE_EXISTING;
    auto journal = extendedPath(private_) + L"\\rename.pending";
    std::wstring record = canonical(source) + L"\n" + canonical(destination);
    {
        Handle file(CreateFileW(journal.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                nullptr));
        require(file.get() != INVALID_HANDLE_VALUE, "Create private rename journal");
        DWORD count = 0, bytes = DWORD(record.size() * sizeof(wchar_t));
        require(WriteFile(file.get(), record.data(), bytes, &count, nullptr) && count == bytes &&
                    FlushFileBuffers(file.get()),
                "Persist private rename journal");
    }
    if (!MoveFileExW(from.c_str(), to.c_str(), flags | MOVEFILE_WRITE_THROUGH)) {
        auto code = GetLastError();
        DeleteFileW(journal.c_str());
        throw Error(code, "Rename private file");
    }
    mark(source, true);
    mark(destination, false);
    require(DeleteFileW(journal.c_str()), "Complete private rename journal");
}
void FileStore::copy(const std::wstring &source, const std::wstring &destination, bool failIfExists) {
    StorageLock::Guard guard(*lock_);
    recover();
    if (same(resolveLinks(source), resolveLinks(destination)))
        throw Error(ERROR_SHARING_VIOLATION, "Logical copy source and destination are identical");
    if (failIfExists && attributesUnlocked(destination) != INVALID_FILE_ATTRIBUTES)
        throw Error(ERROR_FILE_EXISTS, "Logical copy destination exists");
    parent(destination);
    require(CopyFileW(readPath(source).c_str(), backing(destination).c_str(), failIfExists),
            "Copy private file");
    mark(destination, false);
}
std::vector<WIN32_FIND_DATAW> FileStore::enumerate(const std::wstring &directory,
                                                   const std::wstring &pattern) {
    StorageLock::Guard guard(*lock_);
    recover();
    return enumerateUnlocked(directory, pattern);
}
std::vector<WIN32_FIND_DATAW> FileStore::enumerateUnlocked(const std::wstring &directory,
                                                           const std::wstring &pattern) {
    if (pattern.empty() || pattern.find_first_of(L"\\/:") != std::wstring::npos)
        throw Error(ERROR_INVALID_PARAMETER, "Enumeration pattern must be a filename pattern");
    auto logical = canonical(directory);
    auto attributes = attributesUnlocked(logical);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw Error(ERROR_PATH_NOT_FOUND, "Logical enumeration directory is absent");
    std::map<std::wstring, WIN32_FIND_DATAW, OrdinalLess> merged;
    for (const auto &root : {extendedPath(logical), backing(logical)}) {
        WIN32_FIND_DATAW item{};
        HANDLE search = FindFirstFileW((root + L"\\" + pattern).c_str(), &item);
        if (search == INVALID_HANDLE_VALUE) {
            auto code = GetLastError();
            if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
                continue;
            throw Error(code, "Enumerate overlay source");
        }
        do {
            std::wstring name = item.cFileName;
            if (name != L"." && name != L".." && !erased(logical + L"\\" + name))
                merged[name] = item;
            if (merged.size() > 100000) {
                FindClose(search);
                throw Error(ERROR_NOT_ENOUGH_MEMORY, "Overlay enumeration budget exceeded");
            }
        } while (FindNextFileW(search, &item));
        auto code = GetLastError();
        FindClose(search);
        if (code != ERROR_NO_MORE_FILES)
            throw Error(code, "Incomplete overlay enumeration");
    }
    std::vector<WIN32_FIND_DATAW> result;
    for (const auto &[name, value] : merged)
        result.push_back(value);
    return result;
}
}

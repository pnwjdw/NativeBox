#pragma once
#include "driverless/runtime/base.h"

namespace nb::runtime {
class FileStore {
    std::wstring logical_, private_, files_, deleted_, excluded_;
    std::unique_ptr<StorageLock> lock_;
    std::wstring relative(const std::wstring &path) const;
    std::wstring backing(const std::wstring &path) const;
    std::wstring marker(const std::wstring &path) const;
    bool erased(const std::wstring &path) const;
    void mark(const std::wstring &path, bool deleted);
    void parent(const std::wstring &path);
    std::wstring readPath(const std::wstring &path) const;
    std::wstring materialize(const std::wstring &path, bool preserve);
    DWORD attributesUnlocked(const std::wstring &path) const;
    void recover();
    void removeUnlocked(const std::wstring &path, bool directory);
    void renameUnlocked(const std::wstring &source, const std::wstring &destination, DWORD flags);
    void renameFileUnlocked(const std::wstring &source, const std::wstring &destination, DWORD flags);
    void createDirectoryUnlocked(const std::wstring &path, LPSECURITY_ATTRIBUTES security);
    std::vector<WIN32_FIND_DATAW> enumerateUnlocked(const std::wstring &directory, const std::wstring &pattern);

  public:
    // excludedRoot (optional) is passed through untouched, e.g. the sandbox manager's own storage.
    FileStore(std::wstring logicalRoot, std::wstring privateRoot, std::wstring excludedRoot = {});
    bool covers(const std::wstring &path) const;
    std::wstring logicalRoot() const { return logical_; }
    HANDLE open(const std::wstring &path, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES security,
                DWORD disposition, DWORD flags, HANDLE templateFile);
    DWORD attributes(const std::wstring &path);
    void information(const std::wstring &path, WIN32_FILE_ATTRIBUTE_DATA &value);
    void setAttributes(const std::wstring &path, DWORD attributes);
    void createDirectory(const std::wstring &path, LPSECURITY_ATTRIBUTES security = nullptr);
    void remove(const std::wstring &path, bool directory);
    void rename(const std::wstring &source, const std::wstring &destination, DWORD flags);
    void copy(const std::wstring &source, const std::wstring &destination, bool failIfExists);
    std::vector<WIN32_FIND_DATAW> enumerate(const std::wstring &directory, const std::wstring &pattern);
    // Whether a CreateFile request changes logical state and therefore opens the private copy.
    static bool mutates(DWORD access, DWORD disposition, DWORD flags);
    // Called after a mutating handle closes: a private copy deleted through the handle (delete-on-close,
    // disposition or handle rename) hides the original as well.
    void reconcile(const std::wstring &path);
    // Physical file that currently backs a logical path for reading.
    std::wstring resolve(const std::wstring &path);
    // Private destination for a handle based rename; the parent is materialized.
    std::wstring prepareTarget(const std::wstring &path);
    // Records a completed handle based rename inside this store.
    void committed(const std::wstring &source, const std::wstring &destination);
    // Copies a physical file from outside the store into a logical destination.
    void importFile(const std::wstring &physical, const std::wstring &destination, bool failIfExists);
    void replace(const std::wstring &replaced, const std::wstring &replacement, const std::wstring &backup);
};
}

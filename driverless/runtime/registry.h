#pragma once
#include "driverless/runtime/base.h"

namespace nb::runtime {
void createPrivateHive(const std::wstring &path, const std::wstring &offlineLibrary);

// Logical registry location: a root letter (U = HKEY_CURRENT_USER, M = HKEY_LOCAL_MACHINE,
// C = HKEY_CLASSES_ROOT) and a physical path below it (HKLM paths are already WOW64-normalized).
struct RegistryPath {
    wchar_t root = L'U';
    std::wstring path;
    REGSAM view = 0;  // KEY_WOW64_32KEY / KEY_WOW64_64KEY used to read originals of U and C
};

// Per-key copy-on-write registry. Reads use the original registry until a key is written; a written key is
// copied (values only) into a private application hive together with all of its ancestors, so a key that has
// no private copy never has private descendants. Deleted original keys are remembered as tombstones.
class RegistryStore {
    Key hive_;
    StorageLock lock_;
    std::wstring dataPath(const RegistryPath &key) const;
    std::wstring metaPath(const RegistryPath &key) const;
    bool privateExists(const RegistryPath &key) const;
    DWORD state(const RegistryPath &key) const;
    void setState(const RegistryPath &key, DWORD value);
    bool originalVisible(const RegistryPath &key) const;
    HKEY openOriginal(const RegistryPath &key, REGSAM access, LSTATUS &status) const;
    void materialize(const RegistryPath &key);
    bool existsUnlocked(const RegistryPath &key) const;
    std::vector<std::wstring> subkeysUnlocked(const RegistryPath &key) const;
    void deleteOne(const RegistryPath &key);
    void deleteTreeUnlocked(const RegistryPath &key);

  public:
    explicit RegistryStore(const std::wstring &privateDirectory);
    static bool writes(REGSAM access);
    // Returns a private or an original handle; isPrivate tells which one.
    HKEY open(const RegistryPath &key, REGSAM access, bool create, DWORD *disposition, bool &isPrivate);
    bool exists(const RegistryPath &key) const;
    bool hasPrivate(const RegistryPath &key) const;
    // Merged, ordinal-case-insensitively sorted subkey names.
    std::vector<std::wstring> subkeys(const RegistryPath &key) const;
    void removeKey(const RegistryPath &key);
    void removeTree(const RegistryPath &key);
    void clearTree(const RegistryPath &key);
    void flush();
};
}

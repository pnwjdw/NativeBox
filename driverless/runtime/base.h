#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

namespace nb::runtime {
struct Error : std::runtime_error {
    DWORD code;
    Error(DWORD value, const char *operation) : std::runtime_error(operation), code(value) {}
};
inline void require(bool value, const char *operation) {
    if (!value)
        throw Error(GetLastError(), operation);
}
class Handle {
    HANDLE handle_ = nullptr;

  public:
    explicit Handle(HANDLE value = nullptr) : handle_(value) {}
    ~Handle() {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const { return handle_; }
    HANDLE release() { return std::exchange(handle_, nullptr); }
};
class Key {
    HKEY key_ = nullptr;

  public:
    explicit Key(HKEY value = nullptr) : key_(value) {}
    ~Key() {
        if (key_)
            RegCloseKey(key_);
    }
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
    Key(Key &&other) noexcept : key_(other.key_) { other.key_ = nullptr; }
    Key &operator=(Key &&other) noexcept {
        if (this != &other) {
            if (key_)
                RegCloseKey(key_);
            key_ = other.key_;
            other.key_ = nullptr;
        }
        return *this;
    }
    HKEY get() const { return key_; }
    HKEY release() {
        auto value = key_;
        key_ = nullptr;
        return value;
    }
};
struct OrdinalLess {
    bool operator()(const std::wstring &left, const std::wstring &right) const {
        return CompareStringOrdinal(left.c_str(), int(left.size()), right.c_str(), int(right.size()), TRUE) ==
               CSTR_LESS_THAN;
    }
};
bool same(const std::wstring &left, const std::wstring &right);
std::wstring longForm(const std::wstring &path, unsigned depth = 0);
// Canonical path with directory symbolic links and junctions replaced by their targets.
std::wstring resolveLinks(const std::wstring &path);
bool beneath(const std::wstring &path, const std::wstring &root);
std::wstring canonical(const std::wstring &path);
// Physical Win32 path; keeps mirrored backing paths usable beyond MAX_PATH without
// requiring the instrumented application's manifest or machine-wide long-path policy.
std::wstring extendedPath(const std::wstring &path);
void noReparse(const std::wstring &path);
void directories(const std::wstring &path);
void registryCheck(LSTATUS code, const char *operation);
std::string sha256(const std::wstring &path);
class StorageLock {
    Handle file_;

  public:
    explicit StorageLock(const std::wstring &root);
    class Guard {
        HANDLE file_;
        OVERLAPPED offset_{};

      public:
        explicit Guard(const StorageLock &lock);
        ~Guard();
        Guard(const Guard &) = delete;
        Guard &operator=(const Guard &) = delete;
    };
};
}

#pragma once
#include "driverless/runtime/protocol.h"

namespace nb::runtime {
void trace(const Configuration &configuration, const char *category, const char *operation,
           const std::wstring &path, DWORD result) noexcept;
}

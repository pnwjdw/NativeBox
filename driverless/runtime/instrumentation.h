#pragma once
#include "driverless/runtime/protocol.h"

#ifdef NB_OFFICIAL_DETOURS
#include <detours.h>
#else
extern "C" {
LONG WINAPI DetourTransactionBegin();
LONG WINAPI DetourTransactionAbort();
LONG WINAPI DetourTransactionCommit();
LONG WINAPI DetourUpdateThread(HANDLE);
LONG WINAPI DetourAttach(PVOID *, PVOID);
BOOL WINAPI DetourRestoreAfterWith();
BOOL WINAPI DetourIsHelperProcess();
BOOL WINAPI DetourCreateProcessWithDllExW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
                                          DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION,
                                          LPCSTR, nb::runtime::CreateProcessRoutine);
}
#endif

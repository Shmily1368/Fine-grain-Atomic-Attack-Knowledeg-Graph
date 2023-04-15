#pragma once

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <wincrypt.h>

#pragma comment (lib,"Psapi.lib")

// Link with the Wintrust.lib file.

BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
BOOL WinVerifySignature(PCWSTR FileName);


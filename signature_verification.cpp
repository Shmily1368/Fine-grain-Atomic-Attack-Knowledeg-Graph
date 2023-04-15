// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved

#include "stdafx.h"
#include <tchar.h>
#include <strsafe.h>
#include "init_collector.h"
#include "signature_verification.h"
#include "global_enum_def.h"
#include "tool_functions.h"

#pragma warning(disable: 4996) // avoid GetVersionEx to be warned 

/*---------------------------------------------------------------
//
//获取进程完整路径
//
----------------------------------------------------------------*/
//Dos路径转换为Nt路径
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH])
{
	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	if (!pszFullPath)
		return FALSE;

	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);

	if (!hProcess)
	{
		CloseHandle(hProcess);

		return FALSE;
	}

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
	{
		CloseHandle(hProcess);

		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);

		return FALSE;
	}
	CloseHandle(hProcess);

	return TRUE;
}



//----------------------------------------------------------------------------
//
//  PrintError
//  Prints error information to the console
//
//----------------------------------------------------------------------------
void PrintError(_In_ DWORD Status)
{
	//wprintf(L"Error: 0x%08x (%d)\n", Status, Status);
}

//----------------------------------------------------------------------------
//
//  VerifyEmbeddedSignatures
//  Verifies all embedded signatures of a file
//
//----------------------------------------------------------------------------
bool VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
	_In_ HANDLE FileHandle,
	_In_ bool UseStrongSigPolicy)
{
	bool result = false;
	DWORD Error = ERROR_SUCCESS;
	bool WintrustCalled = false;
	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData = {};
	WINTRUST_FILE_INFO FileInfo = {};
	WINTRUST_SIGNATURE_SETTINGS SignatureSettings = {};
	CERT_STRONG_SIGN_PARA StrongSigPolicy = {};

	// Setup data structures for calling WinVerifyTrust
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO_);
	FileInfo.hFile = FileHandle;
	FileInfo.pcwszFilePath = FileName;
	WintrustData.pFile = &FileInfo;

	//
	// First verify the primary signature (index 0) to determine how many secondary signatures
	// are present. We use WSS_VERIFY_SPECIFIC and dwIndex to do this, also setting 
	// WSS_GET_SECONDARY_SIG_COUNT to have the number of secondary signatures returned.
	//
	SignatureSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
	SignatureSettings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
	SignatureSettings.dwIndex = 0;
	WintrustData.pSignatureSettings = &SignatureSettings;

	if (UseStrongSigPolicy != false)
	{
		StrongSigPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
		StrongSigPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
		StrongSigPolicy.pszOID = (LPSTR)(szOID_CERT_STRONG_SIGN_OS_CURRENT);
		WintrustData.pSignatureSettings->pCryptoPolicy = &StrongSigPolicy;
	}

	//wprintf(L"Verifying primary signature... ");
	Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	WintrustCalled = true;
	if (Error != ERROR_SUCCESS)
	{
		PrintError(Error);
		goto Cleanup;
	}

	//wprintf(L"Success!\n");

	//wprintf(L"Found %d secondary signatures\n", WintrustData.pSignatureSettings->cSecondarySigs);

	// Now attempt to verify all secondary signatures that were found
	for (DWORD x = 1; x <= WintrustData.pSignatureSettings->cSecondarySigs; x++)
	{
		//wprintf(L"Verify secondary signature at index %d... ", x);

		// Need to clear the previous state data from the last call to WinVerifyTrust
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			//No need to call WinVerifyTrust again
			WintrustCalled = false;
			PrintError(Error);
			goto Cleanup;
		}

		WintrustData.hWVTStateData = NULL;

		// Caller must reset dwStateAction as it may have been changed during the last call
		WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustData.pSignatureSettings->dwIndex = x;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			PrintError(Error);
			goto Cleanup;
		}

		//wprintf(L"Success!\n");
	}
	result = true;

Cleanup:

	//
	// Caller must call WinVerifyTrust with WTD_STATEACTION_CLOSE to free memory
	// allocate by WinVerifyTrust
	//
	if (WintrustCalled != false)
	{
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	}

	return result;
}


//----------------------------------------------------------------------------
//
//  VerifyCatalogSignature
//  Looks up a file by hash in the system catalogs. 
//
//----------------------------------------------------------------------------
bool VerifyCatalogSignature(_In_ HANDLE FileHandle,
	_In_ bool UseStrongSigPolicy)
{
	DWORD Error = ERROR_SUCCESS;
	bool Found = false;
	HCATADMIN CatAdminHandle = NULL;
	HCATINFO CatInfoHandle = NULL;
	DWORD HashLength = 0;
	PBYTE HashData = NULL;
	CERT_STRONG_SIGN_PARA SigningPolicy = {};

	if (UseStrongSigPolicy != false)
	{
		SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
		SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
		SigningPolicy.pszOID = (LPSTR)(szOID_CERT_STRONG_SIGN_OS_CURRENT);
		//if (!CryptCATAdminAcquireContext2(
		//	&CatAdminHandle,
		//	NULL,
		//	BCRYPT_SHA256_ALGORITHM,
		//	&SigningPolicy,
		//	0))
		//{
		//	Error = GetLastError();
		//	goto Cleanup;
		//}
	}
	else
	{
		//if (!CryptCATAdminAcquireContext2(
		//	&CatAdminHandle,
		//	NULL,
		//	BCRYPT_SHA256_ALGORITHM,
		//	NULL,
		//	0))
		//{
		//	Error = GetLastError();
		//	goto Cleanup;
		//}
	}

	// Get size of hash to be used
	//if (!CryptCATAdminCalcHashFromFileHandle2(
	//	CatAdminHandle,
	//	FileHandle,
	//	&HashLength,
	//	NULL,
	//	NULL))
	//{
	//	Error = GetLastError();
	//	goto Cleanup;
	//}

	HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
	if (HashData == NULL)
	{
		Error = ERROR_OUTOFMEMORY;
		goto Cleanup;
	}

	// Generate hash for a give file
	//if (!CryptCATAdminCalcHashFromFileHandle2(
	//	CatAdminHandle,
	//	FileHandle,
	//	&HashLength,
	//	HashData,
	//	NULL))
	//{
	//	Error = GetLastError();
	//	goto Cleanup;
	//}

	// Find the first catalog containing this hash
	CatInfoHandle = NULL;
	CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
		CatAdminHandle,
		HashData,
		HashLength,
		0,
		&CatInfoHandle);

	while (CatInfoHandle != NULL)
	{
		CATALOG_INFO catalogInfo = {};
		catalogInfo.cbStruct = sizeof(catalogInfo);
		Found = true;

		if (!CryptCATCatalogInfoFromContext(
			CatInfoHandle,
			&catalogInfo,
			0))
		{
			Error = GetLastError();
			break;
		}

		//wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

		// Look for the next catalog containing the file's hash
		CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
			CatAdminHandle,
			HashData,
			HashLength,
			0,
			&CatInfoHandle);
	}

	if (Found != true)
	{
		//wprintf(L"Hash was not found in any catalogs.\n");
	}

Cleanup:
	if (CatAdminHandle != NULL)
	{
		if (CatInfoHandle != NULL)
		{
			CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
		}

		CryptCATAdminReleaseContext(CatAdminHandle, 0);
	}

	if (HashData != NULL)
	{
		HeapFree(GetProcessHeap(), 0, HashData);
	}

	return Found;
}

std::string getOsInfo()
{
	// get os name according to version number  
	OSVERSIONINFO osver = { sizeof(OSVERSIONINFO) };
	GetVersionEx(&osver);
	std::string os_name;
	if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)
		os_name = "Windows 2000";
	else if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 1)
		os_name = "Windows XP";
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0)
		os_name = "Windows 2003";
	else if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 2)
		os_name = "windows vista";
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)
		os_name = "windows 7";
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 2)
		os_name = "windows 10";

	return os_name;
}

BOOL CheckFileTrust_Win7(LPCTSTR lpFileName)
{
	BOOL bRet = FALSE;
	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };
	CATALOG_INFO ci = { 0 };

	HCATADMIN hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
	{
		return FALSE;
	}

	HANDLE hFile = CreateFile(lpFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		0, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return FALSE;
	}

	DWORD dwCnt = 100;
	BYTE byHash[100] = { 0 };
	CryptCATAdminCalcHashFromFileHandle(hFile, &dwCnt, byHash, 0);
	CloseHandle(hFile);

	LPTSTR pszMemberTag = new TCHAR[(dwCnt + 1) * sizeof(TCHAR)];
	for (DWORD dw = 0; dw < dwCnt; ++dw)
	{
		_stprintf(&pszMemberTag[dw * 2], _T("%02X"), byHash[dw]);
	}


	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin,
		byHash, dwCnt, 0, NULL);
	if (NULL == hCatInfo)
	{
		wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
		wfi.pcwszFilePath = lpFileName;
		wfi.hFile = NULL;
		wfi.pgKnownSubject = NULL;

		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.dwUnionChoice = WTD_CHOICE_FILE;
		wd.pFile = &wfi;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wd.dwStateAction = WTD_STATEACTION_IGNORE;
		wd.dwProvFlags = WTD_SAFER_FLAG;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
	}
	else
	{
		CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);
		wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		wci.pcwszCatalogFilePath = ci.wszCatalogFile;
		wci.pcwszMemberFilePath = lpFileName;
		wci.pcwszMemberTag = pszMemberTag;

		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wd.pCatalog = &wci;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
		wd.dwProvFlags = 0;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
	}
	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HRESULT hr = WinVerifyTrust(NULL, &action, &wd);
	bRet = SUCCEEDED(hr);

	if (NULL != hCatInfo)
	{
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
	}
	CryptCATAdminReleaseContext(hCatAdmin, 0);
	delete[] pszMemberTag;
	return bRet;
}

BOOL CheckFileTrust_Win10(LPCTSTR FileName)
{
	BOOL bRet = FALSE;

	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	bool UseStrongSigPolicy = FALSE;
	FileHandle = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	bRet = VerifyEmbeddedSignatures(FileName, FileHandle, UseStrongSigPolicy);

	if (!bRet)
		bRet = VerifyCatalogSignature(FileHandle, UseStrongSigPolicy);

	return bRet;
}

BOOL WinVerifySignature(PCWSTR FileName)
{
	BOOL bRet = FALSE;

	if (ToolFunctions::GetSystemOs() == EM_OsVersion::WIN10)
	{
		bRet = CheckFileTrust_Win10(FileName); // 用于win8及以上版本
	} else if (ToolFunctions::GetSystemOs() == EM_OsVersion::WIN7) 
	{
		bRet = CheckFileTrust_Win7(FileName);  // 用于win7及以下版本
	}
	
	return bRet;
}


























//void CharToTchar(const char * _char, TCHAR * tchar)
//{
//	int iLength;
//
//	iLength = MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, NULL, 0);
//	MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, tchar, iLength);
//}
//
//BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
//{
//	LONG lStatus;
//	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
//	GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
//	HANDLE hFile;
//	DWORD dwHash;
//	BYTE bHash[100];
//	HCATINFO hCatInfo;
//	HCATADMIN hCatAdmin;
//
//	WINTRUST_DATA wd = { 0 };
//	WINTRUST_FILE_INFO wfi = { 0 };
//	WINTRUST_CATALOG_INFO wci = { 0 };
//
//	////set up structs to verify files with cert signatures
//	memset(&wfi, 0, sizeof(wfi));
//	wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
//	wfi.pcwszFilePath = pwszSourceFile;
//	wfi.hFile = NULL;
//	wfi.pgKnownSubject = NULL;
//
//	memset(&wd, 0, sizeof(wd));
//	wd.cbStruct = sizeof(WINTRUST_DATA);
//	wd.dwUnionChoice = WTD_CHOICE_FILE;
//	wd.pFile = &wfi;
//	wd.dwUIChoice = WTD_UI_NONE;
//	wd.fdwRevocationChecks = WTD_REVOKE_NONE;
//	wd.dwStateAction = 0;
//	wd.dwProvFlags = WTD_SAFER_FLAG;
//	wd.hWVTStateData = NULL;
//	wd.pwszURLReference = NULL;
//	wd.pPolicyCallbackData = NULL;
//	wd.pSIPClientData = NULL;
//	wd.dwUIContext = 0;
//
//	lStatus = WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
//
//	////if failed, try to verify using catalog files
//	if (lStatus != ERROR_SUCCESS)
//	{
//		//open the file
//		hFile = CreateFileW(pwszSourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//		if (hFile == INVALID_HANDLE_VALUE)
//			return FALSE;
//
//		dwHash = sizeof(bHash);
//		if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHash, bHash, 0))
//		{
//			CloseHandle(hFile);
//			return FALSE;
//		}
//
//		//Create a string form of the hash (used later in pszMemberTag)
//		LPWSTR pszMemberTag = new WCHAR[dwHash * 2 + 1];
//		for (DWORD dw = 0; dw < dwHash; ++dw)
//		{
//			//wsprintfW(&pszMemberTag[dw * 2], L"%02X", bHash[dw]);
//		}
//
//		if (!CryptCATAdminAcquireContext(&hCatAdmin, &DriverActionGuid, 0))
//		{
//			CloseHandle(hFile);
//			return FALSE;
//		}
//
//		//find the catalog which contains the hash
//		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);
//
//		if (hCatInfo)
//		{
//			CATALOG_INFO ci = { 0 };
//			CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);
//
//			memset(&wci, 0, sizeof(wci));
//			wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
//			wci.pcwszCatalogFilePath = ci.wszCatalogFile;
//			wci.pcwszMemberFilePath = pwszSourceFile;
//			wci.pcwszMemberTag = pszMemberTag;
//
//			memset(&wd, 0, sizeof(wd));
//			wd.cbStruct = sizeof(WINTRUST_DATA);
//			wd.dwUnionChoice = WTD_CHOICE_CATALOG;
//			wd.pCatalog = &wci;
//			wd.dwUIChoice = WTD_UI_NONE;
//			wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
//			wd.dwProvFlags = 0;
//			wd.hWVTStateData = NULL;
//			wd.pwszURLReference = NULL;
//			wd.pPolicyCallbackData = NULL;
//			wd.pSIPClientData = NULL;
//			wd.dwUIContext = 0;
//
//			lStatus = WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
//
//			CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
//		}
//
//
//		CryptCATAdminReleaseContext(hCatAdmin, 0);
//		delete[] pszMemberTag;
//		CloseHandle(hFile);
//	}
//
//	if (lStatus != ERROR_SUCCESS)
//		return false;
//	else
//		return true;
//}

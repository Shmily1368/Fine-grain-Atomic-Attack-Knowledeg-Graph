#define _UNICODE 1
#define UNICODE 1

#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>

#include "certificate_tool.h"
#include "tool_functions.h"

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

#pragma comment(lib, "crypt32.lib")
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#define CERTIFICATE_SUCC(result) ((result) == ERROR_SUCCESS)

std::unordered_map<std::wstring, SCertificateResult> CertificateTool::_certificate_cache_map;
RwLock CertificateTool::_certificate_cache_lock;
/*
bool CertificateTool::VerifyEmbeddedSignature(LPCWSTR file_name)
{
	try
	{
		auto iter_f = _certificate_cache_map.find(file_name);
		if (iter_f != _certificate_cache_map.end())
		{
			return iter_f->second;
		}

		HCATADMIN h_cat_admin = NULL;
		if (!CryptCATAdminAcquireContext(&h_cat_admin, NULL, 0))//acquires a handle to a catalog administrator context
		{
            LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: CryptCATAdminAcquireContext failed,errcode:" + std::to_wstring(GetLastError()), LogLevel::ERR);
			return false;
		}

		HANDLE h_file = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, //Creates or opens a file or I/O device.The function returns a handle that can be used to access the file or device for various types of I/O depending on the file or device and the flags and attributes specified.
			NULL, OPEN_EXISTING, 0, NULL);
		if (INVALID_HANDLE_VALUE == h_file)
		{
//             LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: CreateFileW failed,errcode:" + std::to_wstring(GetLastError()) +
//                 L" filename:" + file_name, LogLevel::ERR);
			CryptCATAdminReleaseContext(h_cat_admin, 0);
			return false;
		}

		bool result = false;
		BYTE hash[100];
		DWORD hash_size = 100;
		CryptCATAdminCalcHashFromFileHandle(h_file, &hash_size, hash, 0); // calculates the hash for a file
		CloseHandle(h_file);

		LPWSTR member_tag = new WCHAR[hash_size * 2 + 1];
        if (member_tag == nullptr)
        {
            LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: new member_tag failed,errcode:" + std::to_wstring(GetLastError()), LogLevel::ERR);
            return false;
        }

		for (DWORD dw = 0; dw < hash_size; ++dw)
		{
			wsprintfW(&member_tag[dw * 2], L"%02X", hash[dw]);
		}

		HCATINFO h_cat_info = CryptCATAdminEnumCatalogFromHash(h_cat_admin, hash, hash_size, 0, NULL);//enumerates the catalogs that contain a specified hash
		if (h_cat_info != NULL)
		{
			WINTRUST_CATALOG_INFO wintrust_catalog_info = { 0 };
			CATALOG_INFO catalog_info = { 0 };
			WINTRUST_DATA wintrust_data = { 0 };

			CryptCATCatalogInfoFromContext(h_cat_info, &catalog_info, 0);
			wintrust_catalog_info.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
			wintrust_catalog_info.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
			wintrust_catalog_info.pcwszMemberFilePath = file_name;
			wintrust_catalog_info.pcwszMemberTag = member_tag;
			wintrust_catalog_info.hCatAdmin = h_cat_admin;
			wintrust_catalog_info.pbCalculatedFileHash = hash;
			wintrust_catalog_info.cbCalculatedFileHash = hash_size;

			wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
			wintrust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
			wintrust_data.pCatalog = &wintrust_catalog_info;
			wintrust_data.dwUIChoice = WTD_UI_NONE;
			wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
			wintrust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
			wintrust_data.hWVTStateData = NULL;
			wintrust_data.pwszURLReference = NULL;
			wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;

			GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
			LONG verify_result = WinVerifyTrust(NULL, &action, &wintrust_data);// performs a trust verification action on a specified object
			result = CERTIFICATE_SUCC(verify_result);

			// Any hWVTStateData must be released by a call with close;
			wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
			WinVerifyTrust(NULL, &action, &wintrust_data);

			CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
		}
        delete[] member_tag; member_tag = nullptr;

		if (!result)
		{
			WINTRUST_FILE_INFO wintrust_file_info = { 0 };
			WINTRUST_DATA wintrust_data = { 0 };

			wintrust_file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
			wintrust_file_info.pcwszFilePath = file_name;
			wintrust_file_info.hFile = NULL;
			wintrust_file_info.pgKnownSubject = NULL;

			wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
			wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
			wintrust_data.pFile = &wintrust_file_info;
			wintrust_data.dwUIChoice = WTD_UI_NONE;
			wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
			wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
			wintrust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
			wintrust_data.hWVTStateData = NULL;
			wintrust_data.pwszURLReference = NULL;

			GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
			LONG verify_result = WinVerifyTrust(NULL, &action, &wintrust_data);// performs a trust verification action on a specified object
			result = CERTIFICATE_SUCC(verify_result);

			wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
			WinVerifyTrust(NULL, &action, &wintrust_data);
		}

		CryptCATAdminReleaseContext(h_cat_admin, 0);
		
        _certificate_cache_lock.WriteLock();
		_certificate_cache_map[file_name] = result;
        _certificate_cache_lock.WriteUnlock();
		return result;
	}
	catch (...)
	{
		LoggerRecord::WriteLog(L"certificate::VerifyEmbeddedSignature error:", LogLevel::ERR);
		return FALSE;
	}
}
*/

EM_CertificateResult CertificateTool::VerifyEmbeddedSignature(LPCWSTR file_name)
{
    EM_CertificateResult certResult = CERTIFICATE_RESULT__MALICIOUS;
    try {
        auto iter_f = _certificate_cache_map.find(file_name);
        if (iter_f != _certificate_cache_map.end()) {
            return iter_f->second.emResult;
        }

        HCATADMIN h_cat_admin = NULL;
        if (!CryptCATAdminAcquireContext(&h_cat_admin, NULL, 0))//acquires a handle to a catalog administrator context
        {
            LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: CryptCATAdminAcquireContext failed,errcode:" + std::to_wstring(GetLastError()), LogLevel::ERR);
            return certResult;
        }

        HANDLE h_file = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, //Creates or opens a file or I/O device.The function returns a handle that can be used to access the file or device for various types of I/O depending on the file or device and the flags and attributes specified.
            NULL, OPEN_EXISTING, 0, NULL);
        if (INVALID_HANDLE_VALUE == h_file) {
            //             LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: CreateFileW failed,errcode:" + std::to_wstring(GetLastError()) +
            //                 L" filename:" + file_name, LogLevel::ERR);
            CryptCATAdminReleaseContext(h_cat_admin, 0);
            return certResult;
        }

        bool result = false;
        LONG verify_result;
        BYTE hash[100];
        DWORD hash_size = 100;
        CryptCATAdminCalcHashFromFileHandle(h_file, &hash_size, hash, 0); // calculates the hash for a file
        CloseHandle(h_file);

        LPWSTR member_tag = new WCHAR[hash_size * 2 + 1];
        if (member_tag == nullptr) {
            LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: new member_tag failed,errcode:" + std::to_wstring(GetLastError()), LogLevel::ERR);
            return certResult;
        }

        for (DWORD dw = 0; dw < hash_size; ++dw) {
            wsprintfW(&member_tag[dw * 2], L"%02X", hash[dw]);
        }

        HCATINFO h_cat_info = CryptCATAdminEnumCatalogFromHash(h_cat_admin, hash, hash_size, 0, NULL);//enumerates the catalogs that contain a specified hash
        if (h_cat_info != NULL) {
            WINTRUST_CATALOG_INFO wintrust_catalog_info = { 0 };
            CATALOG_INFO catalog_info = { 0 };
            WINTRUST_DATA wintrust_data = { 0 };

            CryptCATCatalogInfoFromContext(h_cat_info, &catalog_info, 0);
            wintrust_catalog_info.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
            wintrust_catalog_info.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
            wintrust_catalog_info.pcwszMemberFilePath = file_name;
            wintrust_catalog_info.pcwszMemberTag = member_tag;
            wintrust_catalog_info.hCatAdmin = h_cat_admin;
            wintrust_catalog_info.pbCalculatedFileHash = hash;
            wintrust_catalog_info.cbCalculatedFileHash = hash_size;

            wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
            wintrust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
            wintrust_data.pCatalog = &wintrust_catalog_info;
            wintrust_data.dwUIChoice = WTD_UI_NONE;
            wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
            wintrust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            wintrust_data.hWVTStateData = NULL;
            wintrust_data.pwszURLReference = NULL;
            wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            verify_result = WinVerifyTrust(NULL, &action, &wintrust_data);// performs a trust verification action on a specified object
            result = CERTIFICATE_SUCC(verify_result);            
            // Any hWVTStateData must be released by a call with close;
            wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &action, &wintrust_data);

            CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
        }
        delete[] member_tag; member_tag = nullptr;

        if (!result) {
            WINTRUST_FILE_INFO wintrust_file_info = { 0 };
            WINTRUST_DATA wintrust_data = { 0 };

            wintrust_file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
            wintrust_file_info.pcwszFilePath = file_name;
            wintrust_file_info.hFile = NULL;
            wintrust_file_info.pgKnownSubject = NULL;

            wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
            wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
            wintrust_data.pFile = &wintrust_file_info;
            wintrust_data.dwUIChoice = WTD_UI_NONE;
            wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
            wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
            wintrust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            wintrust_data.hWVTStateData = NULL;
            wintrust_data.pwszURLReference = NULL;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            verify_result = WinVerifyTrust(NULL, &action, &wintrust_data);// performs a trust verification action on a specified object
            result = CERTIFICATE_SUCC(verify_result);
            wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &action, &wintrust_data);
        }

        CryptCATAdminReleaseContext(h_cat_admin, 0);

        if (verify_result != ERROR_SUCCESS)      
            LoggerRecord::WriteLog(L"CertificateTool::VerifyEmbeddedSignature: verify_result:" + std::to_wstring(verify_result), LogLevel::ERR);

        switch (verify_result) {
        case ERROR_SUCCESS:          
            certResult = CERTIFICATE_RESULT__NORMAL;
            break;
        case TRUST_E_NOSIGNATURE:              
            certResult = CERTIFICATE_RESULT__MALICIOUS;         
            break;
        case TRUST_E_EXPLICIT_DISTRUST:          
        case TRUST_E_SUBJECT_NOT_TRUSTED:
        case CRYPT_E_SECURITY_SETTINGS:
        case CERT_E_UNTRUSTEDTESTROOT:
        case CERT_E_UNTRUSTEDCA:            
        case CERT_E_UNTRUSTEDROOT:
            /*
               A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.
            */
            certResult = CERTIFICATE_RESULT__NOTTRUSTED;
            break;
        case CERT_E_EXPIRED:
            /*
                A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.
            */
            certResult = CERTIFICATE_RESULT__EXPIRED;
            break;  
        case CERT_E_REVOKED:
            /*
                A certificate was explicitly revoked by its issuer.
            */
            certResult = CERTIFICATE_RESULT_REVOKED;
            break;
            
        default:          
            certResult = CERTIFICATE_RESULT__MALICIOUS;
            break;
        }

        _certificate_cache_lock.WriteLock();
        if (certResult == CERTIFICATE_RESULT__NORMAL)
        {            
            std::string strThumbPrint;
            GetCertificateThumbPrint(file_name, strThumbPrint);
            SCertificateResult scertResult;
            scertResult.emResult = certResult;
            scertResult.thumbPrint = strThumbPrint;
            _certificate_cache_map[file_name] = scertResult;
            LoggerRecord::WriteLog(L"certificate::VerifyEmbeddedSignature file_name:" + std::wstring(file_name) +
                L" ThumbPrint " + ToolFunctions::StringToWString(strThumbPrint), LogLevel::DEBUG);
        }
            
        _certificate_cache_lock.WriteUnlock();
        return certResult;
    }
    catch (...) {
        LoggerRecord::WriteLog(L"certificate::VerifyEmbeddedSignature error:", LogLevel::ERR);
        return certResult;
    }
    return certResult;
}


int CertificateTool::GetCertificateResult(LPCWSTR file_name) 
{
    int res = -1;
    _certificate_cache_lock.WriteLock();

    auto iter_f = _certificate_cache_map.find(file_name);
    if (iter_f != _certificate_cache_map.end()) {
        res = iter_f->second.emResult;
    }

    _certificate_cache_lock.WriteUnlock();
    return res;
}

int CertificateTool::GetCertificateThumbPrint(LPCWSTR file_name, std::string &thumbPrint)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;  
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;
    LPBYTE pvData = nullptr;

    __try {
        // Get message handle and store handle from the signed file.
        //查询签名信息
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
            file_name,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            &hMsg,
            NULL);
        if (!fResult) {
            _tprintf(_T("CryptQueryObject failed with %u\n"), GetLastError());
            __leave;
        }
        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }
        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
            _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
            __leave;
        }
        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            (PVOID)pSignerInfo,
            &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }       
        // certificate store.
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;
        pCertContext = CertFindCertificateInStore(hStore,
            ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            (PVOID)&CertInfo,
            NULL);
        if (!pCertContext) {
            _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
                GetLastError());
            __leave;
        }
        
        ULONG cbData = 0;
        if (!(CertGetCertificateContextProperty(
            pCertContext,
            CERT_SHA1_HASH_PROP_ID,
            NULL,
            &cbData))) {
            _tprintf(_T("CertGetCertificateContextProperty failed with %x\n"),
                GetLastError());
            __leave;
        }
        //--------------------------------------------------------------------
        // The call succeeded. Use the size to allocate memory for the 
        // property.
        if (!(pvData = (BYTE*)malloc(cbData))) {          
                _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
                __leave;
        }      
        // Allocation succeeded. Retrieve the property data.
        if (!(CertGetCertificateContextProperty(
            pCertContext,
            CERT_SHA1_HASH_PROP_ID,
            pvData,
            &cbData))) {

        } else {            
            char chData[10] = { 0 };
            for (int i = 0; i < cbData; i++) {
                sprintf_s(chData, 10, "%02x", pvData[i]);
                thumbPrint += chData;               
            }           
        }        
    }
    __finally {       
        if (pSignerInfo != NULL) LocalFree(pSignerInfo);       
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
        if (hStore != NULL) CertCloseStore(hStore, 0);
        if (hMsg != NULL) CryptMsgClose(hMsg);
        if (pvData != nullptr) free(pvData);        
    }
    return 0;
}

#include "stdafx.h"
#include "zone_identifier.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

ZoneIdentifier::ZoneIdentifier() {
}


ZoneIdentifier::~ZoneIdentifier() {
}

bool ZoneIdentifier::GetZoneId(wchar_t * pFileName, DWORD * zoneId) 
{
    bool res = false;
    HRESULT hResult = S_OK;
    IZoneIdentifier2 *pZoneIdentifier2 = NULL;
    IPersistFile * pPersistFile = NULL;

    ::CoInitialize(NULL);
    do {
        hResult = ::CoCreateInstance(CLSID_PersistentZoneIdentifier,
            NULL,
            CLSCTX_SERVER,
            IID_IZoneIdentifier2,
            (void **)&pZoneIdentifier2);
        if (SUCCEEDED(hResult)) {
            DWORD dwPolicy = URLPOLICY_ALLOW;

            hResult = pZoneIdentifier2->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
            if (hResult != S_OK) {
                LoggerRecord::WriteLog(L"certificate::GetZoneId QueryInterface error:" + to_wstring(GetLastError()), LogLevel::ERR);
                break;
            }
            else {
                hResult = pPersistFile->Load(pFileName, 0);
                if (hResult != S_OK) {
                    LoggerRecord::WriteLog(L"certificate::GetZoneId Load error:" + to_wstring(GetLastError()), LogLevel::ERR);
                    break;
                }
                hResult = pZoneIdentifier2->GetId(zoneId);
                if (hResult != S_OK) {
                    LoggerRecord::WriteLog(L"certificate::GetZoneId GetId error:" + to_wstring(GetLastError()), LogLevel::ERR);
                    break;
                }
                wchar_t* famName[1024];
                hResult = pZoneIdentifier2->GetLastWriterPackageFamilyName(famName);
                res = true;
            }
        }
    } while (0);

    if (pZoneIdentifier2)
        pZoneIdentifier2->Release();
    if (pPersistFile)
        pPersistFile->Release();

    ::CoUninitialize();

    return res;
}

bool ZoneIdentifier::GetZoneTransfer(LPCWSTR pFileName, int & ZoneId, wstring &ReferrerUrl, wstring & HostUrl)
{  
    DWORD num = 0;
    WCHAR *pwszBuf = new WCHAR[MAX_PATH + 1]; 
    if (!pwszBuf)
        return false;
    memset(pwszBuf, 0, MAX_PATH + 1);
    // ZoneId
    num = GetPrivateProfileString(_T("ZoneTransfer"), _T("ZoneId"), _T(""), pwszBuf, MAX_PATH, pFileName);
    if (num == 0)
    {       
        return false;
    }
    ZoneId = _ttoi(pwszBuf);
    // ReferrerUrl
    num = GetPrivateProfileString(_T("ZoneTransfer"), _T("ReferrerUrl"), _T(""), pwszBuf, MAX_PATH, pFileName);
    if (num > 0) {
        ReferrerUrl = pwszBuf;
    }
    // HostUrl
    num = GetPrivateProfileString(_T("ZoneTransfer"), _T("HostUrl"), _T(""), pwszBuf, MAX_PATH, pFileName);
    if (num > 0) {
        HostUrl = pwszBuf;
    }

    delete[] pwszBuf; pwszBuf = NULL;
    return true;
}

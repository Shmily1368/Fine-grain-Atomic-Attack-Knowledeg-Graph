#pragma once
#include <Windows.h>

class ZoneIdentifier {
    SINGLETON_DEFINITION(ZoneIdentifier);
private:
    ZoneIdentifier();
    ~ZoneIdentifier();
public:
    static bool GetZoneId(wchar_t *pFileName, DWORD *zoneId);
    static bool GetZoneTransfer(LPCWSTR pFileName, int &ZoneId, wstring &ReferrerUrl, wstring &HostUrl);
};

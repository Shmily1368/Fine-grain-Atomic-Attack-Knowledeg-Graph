#pragma once
#include <unordered_map>
#include <Windows.h>
#include "publicstruct.h"

class CertificateTool
{
public:
	//static bool VerifyEmbeddedSignature(LPCWSTR file_name);
    static EM_CertificateResult VerifyEmbeddedSignature(LPCWSTR file_name);
	static size_t CertificateCacheSize() { return _certificate_cache_map.size(); }
    static int GetCertificateResult(LPCWSTR file_name);
private:
    static int GetCertificateThumbPrint(LPCWSTR file_name, std::string &thumbPrint);
private:
	static std::unordered_map<std::wstring, SCertificateResult> _certificate_cache_map;
    static RwLock _certificate_cache_lock;
};


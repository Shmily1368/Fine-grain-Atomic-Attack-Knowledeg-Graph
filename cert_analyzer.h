#pragma once

#define _CRT_NON_CONFORMING_SWPRINTFS
//#define _CRT_SECURE_NO_WARNINGS redefination;

#define MY_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define szOID_RFC3161_counterSign "1.3.6.1.4.1.311.3.3.1"
#define szOID_NESTED_SIGNATURE    "1.3.6.1.4.1.311.2.4.1"

#include <Windows.h>
#include <WinTrust.h>
#include <list>
#include <Mscat.h>
#include <SoftPub.h>
#include <strsafe.h>
#include <WinCrypt.h>

#include <math.h>
#include <map>
#include <algorithm>
#include <string>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib,"Advapi32")  // 添加该库静态编译才通过
#pragma comment(lib, "Wintrust.lib")

typedef struct _SIGN_COUNTER_SIGN {
	std::string SignerName;
	std::string MailAddress;
	std::string TimeStamp;
} SIGN_COUNTER_SIGN, *PSIGN_COUNTER_SIGN;

/// Per certificate node.
typedef struct _CERT_NODE_INFO {
	std::string SubjectName;
	std::string IssuerName;
	std::string Version;
	std::string Serial;
	std::string Thumbprint;
	std::string NotBefore;
	std::string NotAfter;
	std::string SignAlgorithm;
	std::wstring CRLpoint;
	int SubjectPublicKeyLength;
	std::string SubjectPublicKey;
} CERT_NODE_INFO, *PCERT_NODE_INFO;

/// Per signature node.
typedef struct _SIGN_NODE_INFO {
	std::string DigestAlgorithm;
	std::string Version;
	SIGN_COUNTER_SIGN CounterSign;
	std::list<CERT_NODE_INFO> CertChain;
} SIGN_NODE_INFO, *PSIGN_NODE_INFO;

typedef struct _SIGNDATA_HANDLE {
	DWORD dwObjSize;
	PCMSG_SIGNER_INFO pSignerInfo;
	HCERTSTORE hCertStoreHandle;
} SIGNDATA_HANDLE, *PSIGNDATA_HANDLE;


BOOL CheckFileDigitalSignature(LPCWSTR FilePath, LPCWSTR CataPath, std::wstring & CataFile, std::string & SignType, std::list<SIGN_NODE_INFO> & SignChain);

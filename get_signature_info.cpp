#include "stdafx.h"
#include <fstream>
#include <tchar.h>

#include "init_collector.h"
#include "get_signature_info.h"

using namespace std;

/* Data type transform: string to wstring */
std::wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

/* Data type transform: wstring to string */
string ws2s(wstring& inputws)
{
	LPCWSTR pwszSrc = inputws.c_str();
	int nLen = WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, NULL, 0, NULL, NULL);
	if (nLen <= 0) return std::string("");
	char* pszDst = new char[nLen];
	if (NULL == pszDst) return std::string("");
	WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, pszDst, nLen, NULL, NULL);
	pszDst[nLen - 1] = 0;
	std::string strTemp(pszDst);
	delete[] pszDst;
	return strTemp;
}

/* 验证根证书CA是否在issuer_trusted.txt中 */
bool IsIssuerInTrustList(string issuer_name)
{
	bool bRet = FALSE;

	ifstream fin("issuer_trusted.txt");

	string str;
	while (getline(fin, str))//每次读取一行数据，直到读取失败
	{
		if (str == issuer_name)
		{
			bRet = TRUE;
			break;
		}
	}

	fin.close();

	return bRet;
}

/* 验证证书是否被受信任的根证书机构有效签名 */
BOOL IsSignatureTrusted(string filePath, CERT_NODE_INFO &cert_node_info)
{

	bool bRet = FALSE;
	wstring wstr = s2ws(filePath);
	PCWSTR pwzFilePath = wstr.c_str();
	if (WinVerifySignature(pwzFilePath))
	{
		std::wstring    CataFile;
		std::string     SignType;
		std::list<SIGN_NODE_INFO> SignChain;

		BOOL bReturn = CheckFileDigitalSignature(pwzFilePath, NULL, CataFile, SignType, SignChain);

		string issuer_root;

		if (bReturn)
		{

			std::list<SIGN_NODE_INFO>::iterator iter = SignChain.begin();
			for (; iter != SignChain.end(); iter++)
			{

				std::list<CERT_NODE_INFO>::iterator iter2 = iter->CertChain.end();
				iter2--;
				issuer_root = iter2->IssuerName;
				if (IsIssuerInTrustList(issuer_root))
				{
					bRet = TRUE;
					std::list<CERT_NODE_INFO>::iterator iter1 = iter->CertChain.begin();
					cert_node_info = *iter1;
					break;
				}
			}

		}

	}
	return bRet;
}


SIGN_DATA GetSignatureInfo(string filePath)
{
	//String ^temp_s = gcnew String(filePath.c_str());
	//if (CLRDetermine::IsManaged(temp_s) == CompilationMode::CLR) {
	//	SIGN_DATA sign_data;
	//	sign_data.signature = false;
	//	return sign_data;
	//}
	if (!InitCollector::GetCollector()->sig_verification())
	{
		SIGN_DATA sign_data;
		sign_data.signature = false;
		return sign_data;
	}
	CERT_NODE_INFO cert_node_info;
	BOOL signature = IsSignatureTrusted(filePath, cert_node_info);

	SIGN_DATA sign_data;
	sign_data.signature = signature;

	sign_data.SubjectName = cert_node_info.SubjectName;
	sign_data.IssuerName = cert_node_info.IssuerName;
	sign_data.Version = cert_node_info.Version;
	sign_data.Serial = cert_node_info.Serial;
	sign_data.Thumbprint = cert_node_info.Thumbprint;
	sign_data.NotBefore = cert_node_info.NotBefore;
	sign_data.NotAfter = cert_node_info.NotAfter;
	sign_data.SignAlgorithm = cert_node_info.SignAlgorithm;
	sign_data.CRLpoint = ws2s(cert_node_info.CRLpoint);
	sign_data.SubjectPublicKeyLength = cert_node_info.SubjectPublicKeyLength;
	sign_data.SubjectPublicKey = cert_node_info.SubjectPublicKey;

	return sign_data;

}
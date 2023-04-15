#pragma once
#include <Windows.h>
#include <vector>
#include <string>

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
} CERT_NODE_INFO, *PCERT_NODE_INFO;

class SignatureDetector {
public:
    SignatureDetector();
    ~SignatureDetector();
private:
    //字符转换替换
   // int IsCharacterToStrip(int character);
    //删减字符串
    void StripString(std::string& stringArg);
    //算法 倒置序列号信息
    BOOL CalculateSignSerial(BYTE *pbData, DWORD cbData, std::string & strSerial);
    //计算版本号信息
    BOOL CalculateSignVersion(DWORD dwVersion, std::string & Version);
    BOOL CalculateDigestAlgorithm(LPCSTR pszObjId, std::string & strAlgorithm);
    //获取证书的算法
    BOOL CalculateCertAlgorithm(LPCSTR pszObjId, std::string & Algorithm);
    //获取字符串信息
    BOOL GetStringFromCertContext(PCCERT_CONTEXT pCertContext, DWORD Type, DWORD Flag, std::string & String);
    //获取加签信息
    BOOL GetCounterSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pTargetSigner);
    //签名时间戳
    BOOL GetSignTimeStamp(CONST PCMSG_SIGNER_INFO SignerInfo, string & strTime);
    //获取签名指纹信息
    BOOL CalculateHashOfBytes(BYTE *pbBinary, ALG_ID Algid, DWORD dwBinary, std::string & strThumbprint);
    std::string TimeToString(FILETIME *pftIn, SYSTEMTIME *pstIn = NULL);
public:
    int GetSignatureResult(LPCWSTR file_name, std::vector<CERT_NODE_INFO>& vcert);
};


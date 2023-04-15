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
    //�ַ�ת���滻
   // int IsCharacterToStrip(int character);
    //ɾ���ַ���
    void StripString(std::string& stringArg);
    //�㷨 �������к���Ϣ
    BOOL CalculateSignSerial(BYTE *pbData, DWORD cbData, std::string & strSerial);
    //����汾����Ϣ
    BOOL CalculateSignVersion(DWORD dwVersion, std::string & Version);
    BOOL CalculateDigestAlgorithm(LPCSTR pszObjId, std::string & strAlgorithm);
    //��ȡ֤����㷨
    BOOL CalculateCertAlgorithm(LPCSTR pszObjId, std::string & Algorithm);
    //��ȡ�ַ�����Ϣ
    BOOL GetStringFromCertContext(PCCERT_CONTEXT pCertContext, DWORD Type, DWORD Flag, std::string & String);
    //��ȡ��ǩ��Ϣ
    BOOL GetCounterSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pTargetSigner);
    //ǩ��ʱ���
    BOOL GetSignTimeStamp(CONST PCMSG_SIGNER_INFO SignerInfo, string & strTime);
    //��ȡǩ��ָ����Ϣ
    BOOL CalculateHashOfBytes(BYTE *pbBinary, ALG_ID Algid, DWORD dwBinary, std::string & strThumbprint);
    std::string TimeToString(FILETIME *pftIn, SYSTEMTIME *pstIn = NULL);
public:
    int GetSignatureResult(LPCWSTR file_name, std::vector<CERT_NODE_INFO>& vcert);
};


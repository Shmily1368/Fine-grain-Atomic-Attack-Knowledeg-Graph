#include "stdafx.h"
#include "SignatureDetector.h"
#include <Windows.h>
#include <stdio.h>
#include <WinTrust.h>
#include <wincrypt.h>
#include <xstring>
#include <algorithm>
#include <map>
#include <tchar.h>
#pragma comment(lib, "Crypt32.lib")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define szOID_NESTED_SIGNATURE "1.3.6.1.4.1.311.2.4.1"

using namespace std;


SignatureDetector::SignatureDetector() {
}


SignatureDetector::~SignatureDetector() {
}



//字符转换替换
int IsCharacterToStripEx(int character) {
    return 0 == character || '\t' == character || '\n' == character || '\r' == character;
}
//删减字符串
void SignatureDetector::StripString(std::string& stringArg) {
    stringArg.erase(remove_if(stringArg.begin(), stringArg.end(), IsCharacterToStripEx), stringArg.end());
}

//算法 倒置序列号信息
BOOL SignatureDetector::CalculateSignSerial(BYTE *pbData, DWORD cbData, std::string & strSerial)
{
    BOOL    bReturn = FALSE;
    DWORD   dwSize = 0x400;
    BYTE    abSerial[0x400] = { 0 };
    CHAR    NameBuff[0x400] = { 0 };

    strSerial.clear();
    for (UINT uiIter = 0; uiIter < cbData && uiIter < 0x400; uiIter++) {
        abSerial[uiIter] = pbData[cbData - 1 - uiIter];
    }
    bReturn = CryptBinaryToStringA(abSerial, cbData, CRYPT_STRING_HEX, NameBuff, &dwSize);
    if (!bReturn) {
        return FALSE;
    }
    DWORD dwIter1 = 0;
    DWORD dwIter2 = 0;
    for (dwIter1 = 0; dwIter1 < dwSize; dwIter1++) {
        if (!isspace(NameBuff[dwIter1])) {
            NameBuff[dwIter2++] = NameBuff[dwIter1];
        }
    }
    NameBuff[dwIter2] = '\0';
    strSerial = std::string(NameBuff);
    StripString(strSerial);
    return TRUE;
}

//计算版本号信息
BOOL SignatureDetector::CalculateSignVersion(DWORD dwVersion, std::string & Version) 
{
    switch (dwVersion) {
    case CERT_V1:
        Version = "V1";
        break;
    case CERT_V2:
        Version = "V2";
        break;
    case CERT_V3:
        Version = "V3";
        break;
    default:
        Version = "Unknown";
        break;
    }
    StripString(Version);
    return TRUE;
}

BOOL SignatureDetector::CalculateDigestAlgorithm(LPCSTR pszObjId, std::string & strAlgorithm)
{
    if (!pszObjId) {
        strAlgorithm = "Unknown";
    }
    else if (!strcmp(pszObjId, szOID_OIWSEC_sha1)) {
        strAlgorithm = "SHA1";
    }
    else if (!strcmp(pszObjId, szOID_RSA_MD5)) {
        strAlgorithm = "MD5";
    }
    else if (!strcmp(pszObjId, szOID_NIST_sha256)) {
        strAlgorithm = "SHA256";
    }
    else {
        strAlgorithm = std::string(pszObjId);
    }
    StripString(strAlgorithm);
    return TRUE;
}


//获取证书的算法
BOOL SignatureDetector::CalculateCertAlgorithm(LPCSTR pszObjId, std::string & Algorithm) 
{
    if (!pszObjId) {
        Algorithm = "Unknown";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA1RSA)) {
        Algorithm = "sha1RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_sha1RSASign)) {
        Algorithm = "sha1RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD5RSA)) {
        Algorithm = "md5RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_md5RSA)) {
        Algorithm = "md5RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD2RSA)) {
        Algorithm = "md2RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA256RSA)) {
        Algorithm = "sha256RSA(RSA)";
    }
    else {
        Algorithm = pszObjId;
    }
    StripString(Algorithm);
    return TRUE;
}

//获取字符串信息
BOOL SignatureDetector::GetStringFromCertContext(PCCERT_CONTEXT pCertContext, DWORD Type, DWORD Flag, std::string & String) 
{
    DWORD dwData = 0x00;
    LPSTR pszTempName = NULL;

    dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, NULL, 0);
    if (!dwData) {
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }
    pszTempName = (LPSTR)LocalAlloc(LPTR, dwData * sizeof(CHAR));
    if (!pszTempName) {
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }
    dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, pszTempName, dwData);
    if (!dwData) {
        LocalFree(pszTempName);
        return FALSE;
    }
    String = std::string(pszTempName);
    StripString(String);
    LocalFree(pszTempName);
    return TRUE;
}

//获取加签信息
BOOL SignatureDetector::GetCounterSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pTargetSigner)
{
    BOOL    bSucceed = FALSE;
    BOOL    bReturn = FALSE;
    DWORD   dwObjSize = 0x00;
    DWORD   n = 0x00;

    if (!pSignerInfo || !pTargetSigner) {
        return FALSE;
    }
    __try {
        *pTargetSigner = NULL;
        for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++) {
            if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign)) {
                break;
            }
        }
        if (n >= pSignerInfo->UnauthAttrs.cAttr) {
            bSucceed = FALSE;
            __leave;
        }
        bReturn = CryptDecodeObject(ENCODING, PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            NULL,
            &dwObjSize);
        if (!bReturn) {
            bSucceed = FALSE;
            __leave;
        }
        *pTargetSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwObjSize);
        if (!*pTargetSigner) {
            bSucceed = FALSE;
            __leave;
        }
        bReturn = CryptDecodeObject(ENCODING, PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            (PVOID)*pTargetSigner,
            &dwObjSize);
        if (!bReturn) {
            bSucceed = FALSE;
            __leave;
        }
        bSucceed = TRUE;
    }
    __finally {
    }
    return bSucceed;
}

//系统时间转换成字符串
std::string SignatureDetector::TimeToString(FILETIME *pftIn, SYSTEMTIME *pstIn) 
{	//两种时间转换方式  只需传入一个有效参数即可 

    SYSTEMTIME st = { 0 };
    CHAR szBuffer[256] = { 0 };
    if (!pstIn) {
        if (!pftIn) {
            return std::string("");
        }
        FileTimeToSystemTime(pftIn, &st);
        //修改时间
        if ((st.wHour + 8) > 24) {
            st.wDay = st.wDay + 1;
        }
        st.wHour = (st.wHour + 8) % 24;
        pstIn = &st;
    }
    _snprintf_s(szBuffer, 256, "%04d/%02d/%02d %02d:%02d:%02d",
        pstIn->wYear,
        pstIn->wMonth,
        pstIn->wDay,
        pstIn->wHour,
        pstIn->wMinute,
        pstIn->wSecond
    );
    return std::string(szBuffer);
}

//签名时间戳
BOOL SignatureDetector::GetSignTimeStamp(CONST PCMSG_SIGNER_INFO SignerInfo, string & strTime)
{
    BOOL bReturn = FALSE;
    DWORD       n = 0x00;
    DWORD       dwData = 0x00;
    FILETIME    lft, ft;
    SYSTEMTIME  st;

    // Find szOID_RSA_signingTime OID.
    for (n = 0; n < SignerInfo->AuthAttrs.cAttr; n++) {
        if (!lstrcmpA(SignerInfo->AuthAttrs.rgAttr[n].pszObjId, szOID_RSA_signingTime)) {
            break;
        }
    }
    if (n >= SignerInfo->AuthAttrs.cAttr) {
        return FALSE;
    }
    // Decode and get FILETIME structure.
    dwData = sizeof(ft);
    bReturn = CryptDecodeObject(ENCODING, szOID_RSA_signingTime,
        SignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
        SignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
        0,
        (PVOID)&ft,
        &dwData
    );
    if (!bReturn) {
        return FALSE;
    }
    // Convert.
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    strTime = TimeToString(NULL, &st);
    return TRUE;
}

#define SHA1LEN  20
#define MD5LEN   16
//获取签名指纹信息
BOOL SignatureDetector::CalculateHashOfBytes(BYTE *pbBinary, ALG_ID Algid, DWORD dwBinary, std::string & strThumbprint) 
{
    BOOL        bReturn = FALSE;
    DWORD       dwLastError = 0;
    HCRYPTPROV  hProv = 0;
    HCRYPTHASH  hHash = 0;
    DWORD       cbHash = 0;
    BYTE        rgbHash[SHA1LEN] = { 0 };
    CHAR        hexbyte[3] = { 0 };
    CONST CHAR  rgbDigits[] = "0123456789abcdef";
    std::string CalcHash;

    bReturn = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!bReturn) {
        dwLastError = GetLastError();
        return FALSE;
    }
    bReturn = CryptCreateHash(hProv, Algid, 0, 0, &hHash);
    if (!bReturn) {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    bReturn = CryptHashData(hHash, pbBinary, dwBinary, 0);
    if (!bReturn) {
        dwLastError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    if (CALG_SHA1 == Algid) {
        cbHash = SHA1LEN;
    }
    else if (CALG_MD5 == Algid) {
        cbHash = MD5LEN;
    }
    else {
        cbHash = 0;
    }
    hexbyte[2] = '\0';
    bReturn = CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);
    if (!bReturn) {
        dwLastError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    for (DWORD i = 0; i < cbHash; i++) {
        hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
        hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
        CalcHash.append(hexbyte);
    }
    strThumbprint = CalcHash;
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return TRUE;
}

int SignatureDetector::GetSignatureResult(LPCWSTR file_name, std::vector<CERT_NODE_INFO>& vcert)
{
    DWORD dwEncoding, dwFormatType = 0;
    DWORD dwContentType = 0;		// CERT_QUERY_CONTENT_PKCS7_SIGNED;
    HCERTSTORE hCertStore = NULL;	//接收存储证书库的句柄
    HCRYPTMSG hcryptMsg = NULL;	    //接收打开的加密消息的句柄

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        file_name,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hCertStore,
        &hcryptMsg,
        NULL)) {
        printf("CryptQueryObject handle failed. err:%u \n", GetLastError());
        return -1;
    }

    if (!hCertStore || !hcryptMsg) {
        printf("CryptQueryObject handle is null. err:%d \n", GetLastError);
        return -1;
    }

    //1.获取 SignerInfo大小
    DWORD dwSignerInfoSize;
    if (!CryptMsgGetParam(hcryptMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfoSize)) {
        CertCloseStore(hCertStore, 0);
        CryptMsgClose(hcryptMsg);
        printf("CryptMsgGetParam failed. err:%d \n", GetLastError);
        return -1;
    }

    //2.开辟空间
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfoSize);
    if (!pSignerInfo) {
        CertCloseStore(hCertStore, 0);
        CryptMsgClose(hcryptMsg);
        printf("new PCMSG_SIGNER_INFO failed:%d \n", GetLastError);
        return -1;
    }

    //3.获取签名证书信息  将信息存放于 pSignerInfo 中
    if (!CryptMsgGetParam(hcryptMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfoSize)) {
        CertCloseStore(hCertStore, 0);
        CryptMsgClose(hcryptMsg);
        printf("CryptMsgGetParam failed. err:%d \n", GetLastError);
        return -1;
    }

    // 签名证书信息不为空  获取第一个
    if (pSignerInfo != NULL) {
        // 1.填充证书结构体 发布者和序列号信息
        CERT_INFO CertInfo;
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;

        // 2.查找证书数据   
        // 从当前PE文件的证书句柄库中查找证书  发布者为xxx 序列号为xxx的证书
        PCCERT_CONTEXT pCurrCertContext = NULL;
        pCurrCertContext = CertFindCertificateInStore(hCertStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
        if (!pCurrCertContext) {
            CertCloseStore(hCertStore, 0);
            CryptMsgClose(hcryptMsg);
            printf("CertFindCertificateInStore failed %d ", GetLastError);
            return -1;
        }
        CERT_NODE_INFO  CertNode;
        // Get certficate subject.   颁发给
        auto bReturn = GetStringFromCertContext(pCurrCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, CertNode.SubjectName);
        // Get certificate thumbprint. 指纹
        bReturn = CalculateHashOfBytes(pCurrCertContext->pbCertEncoded, CALG_SHA1, pCurrCertContext->cbCertEncoded, CertNode.Thumbprint);

        vcert.push_back(CertNode);

        //释放    
        CertFreeCertificateContext(pCurrCertContext);
    }

    //获取嵌套签名证书链
    BOOL fResult = FALSE;
    DWORD dwSize;
    PCMSG_SIGNER_INFO pNestSignerInfo = NULL;   
    for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++) 
    {
        HCRYPTMSG hMsg = NULL;
        if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_NESTED_SIGNATURE) == 0) {
            //查找所有的嵌套签名
            for (int i = 0; i < pSignerInfo->UnauthAttrs.rgAttr[n].cValue; i++) {

                hMsg = CryptMsgOpenToDecode(ENCODING, 0, 0, NULL, NULL, NULL);
                if (NULL == hMsg) {
                    continue;
                }

                fResult = CryptMsgUpdate(hMsg,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[i].pbData,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[i].cbData,
                    TRUE);

                if (!fResult) {
                    continue;
                }

                fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSize);

                if (!fResult) {
                    _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());

                }

                pNestSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!pNestSignerInfo) {
                    _tprintf(_T("Unable to allocate memory for timestamp info.\n"));
                    continue;

                }
                fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pNestSignerInfo, &dwSize);
                if (!fResult) {
                    _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
                    continue;
                }


                // 签名证书信息不为空  获取第一个
                if (pNestSignerInfo != NULL) {
                    // 1.填充证书结构体 发布者和序列号信息
                    CERT_INFO CertInfo;
                    CertInfo.Issuer = pNestSignerInfo->Issuer;
                    CertInfo.SerialNumber = pNestSignerInfo->SerialNumber;

                    // 2.查找证书数据   
                    // 从当前PE文件的证书句柄库中查找证书  发布者为xxx 序列号为xxx的证书
                    PCCERT_CONTEXT pCurrCertContext = NULL;
                    pCurrCertContext = CertFindCertificateInStore(hCertStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
                    if (!pCurrCertContext) {
                        CertCloseStore(hCertStore, 0);
                        CryptMsgClose(hMsg);
                        printf("CertFindCertificateInStore failed %d ", GetLastError);
                        return -1;
                    }
                    CERT_NODE_INFO  CertNode;
                    // Get certficate subject.   颁发给
                    auto bReturn = GetStringFromCertContext(pCurrCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, CertNode.SubjectName);
                    // Get certificate thumbprint. 指纹
                    bReturn = CalculateHashOfBytes(pCurrCertContext->pbCertEncoded, CALG_SHA1, pCurrCertContext->cbCertEncoded, CertNode.Thumbprint);

                    vcert.push_back(CertNode);

                    //释放 
                    if (hMsg != NULL)     
                    {
                        CryptMsgClose(hMsg);
                        hMsg = NULL;
                    }
                    if (pNestSignerInfo != NULL) 
                    {
                        LocalFree(pNestSignerInfo);
                        pNestSignerInfo = NULL;
                    }   

                    CertFreeCertificateContext(pCurrCertContext);
                }               
            }
        }
    }

    //释放句柄
    CertCloseStore(hCertStore, 0);
    CryptMsgClose(hcryptMsg);

    if (pSignerInfo != NULL) {
        LocalFree(pSignerInfo);
        pSignerInfo = NULL;
    }

    return 0;
}

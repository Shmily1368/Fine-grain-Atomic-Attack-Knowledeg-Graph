#pragma once
#include <string>
#include <stdint.h>
#include <set>
// 
struct SAttrributes
{
	std::string Field;                  // �ֶ���
    std::string Target;                 // ��Ҫƥ�������
    int	Match;                          // ƥ�䷽ʽ������0����ȫƥ��1��

    inline bool operator<(const SAttrributes& rhs) const {
        if (Field < rhs.Field) return true;
        return false;
    }

};

// 
struct SRule {
    int rule_id;                        // �����ţ�������ȫ��Ψһ��
    std::string Description;            // �Ըù���ļ������;
    std::string	TTP;                    // �����Ӧ��TTP��ţ���Ӧ������Ϊ0��
    std::set<SAttrributes> Attrributes; // ��Ҫƥ�������

    inline bool operator<(const SRule& rhs) const {
        if (rule_id < rhs.rule_id) return true;
        if (rule_id == rhs.rule_id && Description < rhs.Description) return true;
        return false;
    }
};
// 
struct SProcessAccess {
    DWORD SourceProcessId;                    // Դ����ID
    DWORD SourceThreadId;                     // Դ�߳�ID
    std::string SourceImage;                    // Դ����·��
    DWORD TargetProcessId;                    // Ŀ�����ID
    std::string TargetImage;                    // Ŀ�����·��
    ULONG64 GrantedAccess;                      // ��־λ
};
// 
struct SDriverLoaded {  
    DWORD Signed;                                   // �Ƿ�ǩ��
    std::string Signature;                          // ǩ������
    std::string SignatureStatus;                    // ֤��״̬
    std::string ImageLoaded;                        // ����·��
    std::string Hashes;                             // hashֵ
};
// 
struct SFileIoTags {
    bool read_tag;                                   // ����ǩ
    bool write_tag;                                  // д��ǩ��

    SFileIoTags::SFileIoTags() {       
        read_tag = false;
        write_tag = false;
    }
    SFileIoTags::SFileIoTags(bool rtg, bool wtg) {
        read_tag = rtg;
        write_tag = wtg;
    }
};
// 
struct SFileHash {
    std::wstring file_md5;
    long file_size;
};
struct SCertificateResult {
    EM_CertificateResult emResult;
    std::string thumbPrint;
    std::string subjectname;
    inline bool operator<(const SCertificateResult& rhs) const {
        if (emResult < rhs.emResult) return true;
        if (emResult == rhs.emResult && thumbPrint < rhs.thumbPrint) return true;
        if (emResult == rhs.emResult && thumbPrint == rhs.thumbPrint && subjectname < rhs.subjectname) return true;
        return false;
    }
};

// ����
typedef struct _SKU_INFO {
    char psz_process_unique_identifier[50];
    int pid;
}SKU_INFO, *PSKU_INFO;

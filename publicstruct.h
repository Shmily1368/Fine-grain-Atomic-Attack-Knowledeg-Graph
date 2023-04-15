#pragma once
#include <string>
#include <stdint.h>
#include <set>
// 
struct SAttrributes
{
	std::string Field;                  // 字段名
    std::string Target;                 // 需要匹配的内容
    int	Match;                          // 匹配方式，正则0，完全匹配1；

    inline bool operator<(const SAttrributes& rhs) const {
        if (Field < rhs.Field) return true;
        return false;
    }

};

// 
struct SRule {
    int rule_id;                        // 规则编号，自增，全局唯一；
    std::string Description;            // 对该规则的简短描述;
    std::string	TTP;                    // 规则对应的TTP编号，对应不上则为0；
    std::set<SAttrributes> Attrributes; // 需要匹配的内容

    inline bool operator<(const SRule& rhs) const {
        if (rule_id < rhs.rule_id) return true;
        if (rule_id == rhs.rule_id && Description < rhs.Description) return true;
        return false;
    }
};
// 
struct SProcessAccess {
    DWORD SourceProcessId;                    // 源进程ID
    DWORD SourceThreadId;                     // 源线程ID
    std::string SourceImage;                    // 源进程路径
    DWORD TargetProcessId;                    // 目标进程ID
    std::string TargetImage;                    // 目标进程路径
    ULONG64 GrantedAccess;                      // 标志位
};
// 
struct SDriverLoaded {  
    DWORD Signed;                                   // 是否签名
    std::string Signature;                          // 签发机构
    std::string SignatureStatus;                    // 证书状态
    std::string ImageLoaded;                        // 驱动路径
    std::string Hashes;                             // hash值
};
// 
struct SFileIoTags {
    bool read_tag;                                   // 读标签
    bool write_tag;                                  // 写标签；

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

// 进程
typedef struct _SKU_INFO {
    char psz_process_unique_identifier[50];
    int pid;
}SKU_INFO, *PSKU_INFO;

#pragma once

#include <set>
#include <vector>
#include <string>

#include "event_identifier.h"
#include "event_record.h"
#include "event_record_pruner.h"
#include "concurrentqueue.h"

struct ProcessFilterData
{
	DWORD process_id;
	String file_path;
	String file_name;
	EM_CertificateResult certificate_result;
};
using ProcessFilterDataMap = std::unordered_map<DWORD, ProcessFilterData*>;

const int KProviderSize = 11;
const int KOpcodeSize = 256;
const std::string addressmap_file = "addressmap";
void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname);

class Filter
{
	SINGLETON_DEFINITION(Filter);

public:
	void Init();
    void LogCacheSize();
	bool FilterBeforeRecInstance(uint_32 provider_id, int_32 opcode, DWORD process_id);
	bool FilterAfterRecInstance(EventRecord* rec);
	bool IsSuperWhiteListProcess(DWORD pid);
    // add by zxw on 20200724
    bool IsSuperWhiteListProcessEx(DWORD pid);
	// add by zxw on 20191029 是否特权pid进程
	bool IsPrivilegeProcess(DWORD pid);
	// 设置本机IP,如果有更新返回true否则false
	bool SetLoclaIPbyEventRecord(EventRecordTcpip* rec);
	// 获取本机IP
	std::string GetLocalIP();
	//
	// 添加目录白名单
	void AddRansomWhiteDir();
	bool IsRansomBlackProcess(EventRecord* record);
	//
	static void insert_systemcall_name_list(std::string);
	static EventRecord* APIFilter(EventRecord* record);
	static bool FilterAfterParseRecord(EventRecord* record);

	static void insert_process_id_black_list(DWORD process_id) 
	{ 
		LoggerRecord::WriteLog(L"insert_process_id_black_list process_id = " + std::to_wstring(process_id), LogLevel::WARN);
		process_id_black_list.insert(process_id); 
	}	
	static bool query_process_id_black_list(DWORD process_id) 
	{
		if (process_id_black_list.count(process_id)) return true; else return false;
	}
	static void remove_process_id_black_list(DWORD process_id) 
	{
		process_id_black_list.erase(process_id);
	}
	static void insert_process_id_white_list(DWORD process_id) 
	{
		process_id_white_list.insert(process_id);
	}
	static bool query_process_id_white_list(DWORD process_id) 
	{
		if (process_id_white_list.count(process_id)) return true; else return false;
	}
	static void insert_event_process_white_list(uint_32 provider_id, uint_32 opcode) 
	{
		event_process_white_list.insert((uint_64)provider_id * 100 + opcode);
	}
	static void insert_event_output_white_list(EventIdentifier event_id) 
	{
		event_output_white_list.insert(event_id);
	}
	static void insert_api_name_white_list(std::string api_name)
	{
		api_name_white_list.insert(api_name);
	}

	// add by zxw on 20191119
	static void insert_ransom_dir_white_list(std::wstring ransom_dir)
	{
		if (!ransom_dir_white_list.count(ransom_dir))
			ransom_dir_white_list.insert(ransom_dir);
	}
	static bool query_ransom_dir_white_list(std::wstring ransom_dir)
	{
		for each (auto var in ransom_dir_white_list)
		{
			if (ransom_dir.find(var) != std::string::npos)
			{
				return true;
			}			
		}
		return false;
	}
	
	static void insert_ransom_suffix_white_list(std::string suffix)
	{
		if (!ransom_suffix_white_list.count(suffix))
			ransom_suffix_white_list.insert(suffix);
	}
	static bool query_ransom_suffix_white_list(std::string suffix)
	{
        if (ransom_suffix_white_list.size() <= 0 || suffix.length() <= 0)
        {
            return false;
        }

		for each (auto var in ransom_suffix_white_list)
		{
			if (suffix.find(var) != std::string::npos)
			{
				return true;
			}
		}

		return false;
	}
	static void insert_ransom_process_id_black_list(DWORD process_id)
	{
		if (ransom_process_id_black_list.find(process_id) == ransom_process_id_black_list.end())
		{
			ransom_process_id_black_list.insert(process_id);
		}		
	}
	static bool query_ransom_process_id_black_list(DWORD process_id)
	{
		if (ransom_process_id_black_list.count(process_id)) return true; else return false;
	}
    static void erase_ransom_process_id_black_list(DWORD process_id)
    {
        if (ransom_process_id_black_list.find(process_id) != ransom_process_id_black_list.end())
        {
            ransom_process_id_black_list.erase(process_id);
        }
    }

    // add by zxw on 20200811
    static void insert_tid_pruner_black_list(DWORD thread_id) {
        if (tid_pruner_black_list.find(thread_id) == tid_pruner_black_list.end()) {
            tid_pruner_black_list.insert(thread_id);
            //LoggerRecord::WriteLog(L"insert_tid_pruner_black_list " + std::to_wstring(thread_id), DEBUG);
        }
    }
    static bool query_tid_pruner_black_list(DWORD thread_id) {
        if (tid_pruner_black_list.count(thread_id)) return true; else return false;
    }
    static void erase_tid_pruner_black_list(DWORD thread_id) {
        if (tid_pruner_black_list.find(thread_id) != tid_pruner_black_list.end()) {
            tid_pruner_black_list.erase(thread_id);
        }
    }
    static int get_tid_pruner_black_list_size() {
        return tid_pruner_black_list.size();
    }
    
    static void insert_pid_pruner_black_list(DWORD process_id) {
        if (!pid_pruner_black_list.count(process_id)) {
            pid_pruner_black_list.insert(process_id);
            //LoggerRecord::WriteLog(L"insert_pid_pruner_black_list " + std::to_wstring(process_id), DEBUG);
        }
    }
    static bool query_pid_pruner_black_list(DWORD process_id) {
        if (pid_pruner_black_list.count(process_id)) return true; else return false;
    }
    static void erase_pid_pruner_black_list(DWORD process_id) {
        if (pid_pruner_black_list.count(process_id)) {
            pid_pruner_black_list.erase(process_id);
        }
    }
    static int get_pid_pruner_black_list_size() {
        return pid_pruner_black_list.size();
    }

    static void insert_pid_pruner_white_list(DWORD process_id) {
        if (pid_pruner_white_list.find(process_id) == pid_pruner_white_list.end()) {
            pid_pruner_white_list.insert(process_id);
            //LoggerRecord::WriteLog(L"insert_pid_pruner_white_list " + std::to_wstring(process_id), DEBUG);
        }
    }
    static bool query_pid_pruner_white_list(DWORD process_id) {
        if (pid_pruner_white_list.count(process_id)) return true; else return false;
    }
    static void erase_pid_pruner_white_list(DWORD process_id) {
        if (pid_pruner_white_list.find(process_id) != pid_pruner_white_list.end()) {
            pid_pruner_white_list.erase(process_id);
        }
    }
    static int get_pid_pruner_white_list() {
        return pid_pruner_white_list.size();
    }
    /*
	// 
	static void insert_processid_parentid_map(DWORD process_id, DWORD parent_id)
	{
		processid_parentid_map.insert(std::pair<DWORD, DWORD>(process_id, parent_id));
	}
	static void erase_processid_parentid_map(DWORD process_id)
	{
		if (processid_parentid_map.count(process_id) != 0)
		{
			processid_parentid_map.erase(process_id);
		}		
	}
	// 
    */
	static bool isSystemCallNeeded(int);
	static bool isEventNeeded(EventIdentifier);
	static bool AddEvent(EventIdentifier);
	static bool AddSystemCall(int);
	static size_t QueryEventListSize();
	static size_t QuerySystemCallListSize();
    static String GetEventName(EventIdentifier ID);
	static bool DelEvent(EventIdentifier);
	static bool DelSystemCall(int);
	static void set_systemcall_list(std::string);
	static void SignatureFileFilter();
	static bool QuerySystemcallName(std::string&);
	//int get_enableflag();
	//void CreatEnableFlag();
	static void InitSystemcallEventList();
	static void InsetUselessAPIList(std::wstring);
	static bool QueryUselessAPIList(std::wstring);
	static void set_signature_file_path(std::string);

	void OnExeImageLoad(DWORD pid, const String& file_path);
	void OnExeCertificateResult(DWORD pid, EM_CertificateResult result);
	void OnProcessEnd(DWORD pid);
    // add by zxw on 20200811
    void OnProcessStart(EventRecordProcess* rec);
    void OnThreadEnd(DWORD tid, DWORD pid);
    void OnThreadStart(EventRecordThread* rec);
    void OnPhfDetectorResult(DWORD pid);

	bool IsProcessCertificate(DWORD pid) const;

	void InitSuperWhiteList(const STRING_VECTOR& list_init);
	void AddSuperWhiteList(const STRING_VECTOR& list_add);
	void RemoveSuperWhiteList(const STRING_VECTOR& list_remove);
	void ChangeSuperWhiteList(const String& file_name_s, const String& file_name_d);
	// add by zxw on 20191206
	//void AddRansomSuffixWhiteList(const STRING_VECTOR& list_add);
    void AddRansomSuffixWhiteList(const STRING_VECTOR& list_add, int is_terminate);
    void UpdateRansomDetector();
    bool GetRansomDetector() { return _current_ransom_detector; }
    //
    bool GetRansomTerminate() { return _ranssom_is_terminate; }
    // add by zxw on 20201021
    void RuleMatchSwitch(std::string rule_match);
    // add by zxw on 20210508
    void AddCertificateWhiteListBuffer(const std::vector<SCertificateResult>& list_add);
    bool IsInCertificateWhiteList(std::string thumbPrint, std::string subjectname);
    void AddSurpCertificateWhiteListBuffer(DWORD pid);
    bool IsCertificateWhiteListProcess(DWORD pid);
       
	String GetProcessFileName(DWORD pid) const;

	void SetCollectorGear(CollectorGear gear);
	CollectorGear GetCollectorGear();
    
private:
	// if event is in this list, then it should be a useless API;
	static std::set<std::wstring> useless_API_list;
	// if event is not in this list, than it should not be pass to the parseEventRecord()
	static std::unordered_set<uint_64> event_process_white_list;
	// if event is not in this list, than it should not be pass to output
	static std::set<EventIdentifier> event_output_white_list;
	static std::set<DWORD> process_id_black_list;
	static std::set<DWORD> process_id_white_list;
	static std::set<std::string> api_name_white_list;
    // add by zxw on 20200811
    static std::unordered_map<DWORD, std::unordered_set<DWORD>> parentid2childid_map_;
    static std::unordered_map<DWORD, std::unordered_set<DWORD>> pid2tid_map_;
    static std::unordered_set<DWORD> tid_pruner_black_list;
    static std::unordered_set<DWORD> pid_pruner_black_list;
    static std::unordered_set<DWORD> pid_pruner_white_list;

	//bool event_filter_list[KProviderSize][KOpcodeSize];
	//int provider_modulo_mapping_hash[KProviderSize];
	static std::set<int> systemcall_list;
	static std::set<EventIdentifier> event_list;
	static std::set<std::string> systemcall_name_list;
	static std::set<std::string> signature_systemcall_name_list;
	static std::set<EventIdentifier> signature_event_list;
	static std::string signature_file_path;
	static void InsertEventIdentifier(EventIdentifier);

	bool _FilterByGear(DWORD process_id, uint_32 provider_id) const;
	void _OnAddSuperWhiteList(const String& file_name);
	void _OnRemoveSuperWhiteList(const String& file_name);

	moodycamel::ConcurrentQueue<String> _super_white_list_config_add_buffer;
	moodycamel::ConcurrentQueue<String> _super_white_list_config_remove_buffer;
	STRING_SET _super_white_list_config;
    // mod by zxw on 20200525
	moodycamel::ConcurrentQueue<ProcessFilterData> _super_white_list_wait_buffer;
    //moodycamel::ConcurrentQueue<ProcessFilterData*> _super_white_list_wait_buffer;
	std::unordered_set<DWORD> _super_white_list;

	mutable RwLock _process_filter_data_lock;
	ProcessFilterDataMap _process_filter_data_map;

	CollectorGear _current_gear;
	// add by zxw on 20191029 添加特权pid特殊处理,获取本机IP
	DWORD _privilege_pid = 0;
	// add by zxw on 20191122 添加explorer pid特殊处理
	static DWORD _explorer_pid;
    // add by zxw on 20200724 add autorunsc64.exe pid
    DWORD _autorunsc64_pid = 0;
    std::string _autorunsc64_path;
	
	std::string _local_ip;
	// add by zxw on 20191119 
    bool _current_ransom_detector;
	static std::set<std::wstring> ransom_dir_white_list;		// 添加ransom目录白名单
	// add by zxw on 20191206 
	mutable RwLock _ransom_suffix_data_lock;
	moodycamel::ConcurrentQueue<String> _ransom_suffix_white_list_add_buffer;
	static std::set<String> ransom_suffix_white_list;			// 添加ransom后缀白名单	
	static std::set<DWORD> ransom_process_id_black_list;		// 检测进程黑名单
    //
    int _ranssom_is_terminate = 0;
	//static std::unordered_map<DWORD, DWORD> processid_parentid_map;
    // add by zxw on 20210508
    moodycamel::ConcurrentQueue<SCertificateResult> _certificate_white_list_add_buffer;
    static std::set<SCertificateResult> certificate_white_list;	// 添加企业证书白名单	

    moodycamel::ConcurrentQueue<DWORD> _super_certificate_white_list_add_buffer;
    std::unordered_set<DWORD> _super_certificate_white_list;
};

void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname);

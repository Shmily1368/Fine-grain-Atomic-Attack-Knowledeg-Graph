#pragma once

#include "event_record.h"
#include "event_record_callstack.h"
#include "event_record_subclass.h"
#include "spin_lock.h"

struct KeyloggerApiData
{
	DWORD process_id;
	DWORD thread_id;
	int_64 timestamp;
	String api_name;

	KeyloggerApiData(DWORD process_id_t, DWORD thread_id_t, int_64 timestamp_t, const String& api_name_t)
		: process_id(process_id_t), thread_id(thread_id_t), timestamp(timestamp_t), api_name(api_name_t)
	{

	}

};
using KeyloggerApiDataQueue = std::queue<KeyloggerApiData>;
using ThreadKeyloggerApiDataQueueMap = std::map<DWORD, KeyloggerApiDataQueue>;

using KeyloggerProcessSet = std::set<DWORD>;

class PhfDetector 
{
	SINGLETON_DEFINITION(PhfDetector);

public:
	PhfDetector();
	~PhfDetector();

	void Init();
	EventRecord* PushBack(EventRecordCallstack* event_record);
	void ProcessSystemCall(EventRecordPerfInfo* ev);

	void NotifyProcessStart(DWORD ppid, std::wstring imageFileName, ULONG64 timestamp);
	void TryDetectPhf();
	void NotifyProcessEnd(DWORD ppid, ULONG64 timestamp);
    void NotifyThreadEnd(DWORD ttid);

	bool isUselessApi(const string & api);

	void ActiveDetectPhfFlag() { _detect_phf_flag = true; }

	static std::unordered_map<DWORD, int_32> thread_2_keyloggercout_map;
    // remove by zxw on 20200716 use threadid cache
	//static KeyloggerProcessSet keylogger_process_cache;
    static KeyloggerProcessSet keylogger_thread_cache;
   
private:
	ThreadKeyloggerApiDataQueueMap _thread_keylogger_api_queue_map; 
    ThreadKeyloggerApiDataQueueMap _thread_reflective_api_queue_map;
	bool _detect_phf_flag;
private:
    // 线程时间戳缓存
    std::unordered_map<DWORD, int_64> _thread_keylogger_timestamp_map;
    void KeyloggerEraseMap(DWORD tid);
    bool KeyloggerPruner(DWORD tid, int_64 timestamp);
};
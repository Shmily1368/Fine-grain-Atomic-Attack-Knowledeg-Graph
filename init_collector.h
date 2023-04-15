/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(版本号);
	Description:	初始化采集器的类;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  unknown    |	0.1.0	 |	unknown		  | Create file
----------------------------------------------------------------------------
  chips      |	1.0.0	 |	chips		  | 1.更改函数类型，部分虚函数使用纯虚函数，部分虚函数转为普通函数，整理函数排列，拆分部分代码到子类，修改函数风格以统一;
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#define STANDALONE_COLLECTOR 1  
#define USE_LOCAL_TRUST_LIST 1 //关闭pipe通信

//#define MaxWaitSendQueueSize 500000

#include "event_record_manager.h"
#include <evntrace.h>
#include "etw_configuration.h"
#include "concurrent_queue.h"
#include "concurrentqueue.h"
#include "phf_detector.h"
#include "init_collector_factory.h"

typedef VOID (WINAPI *consume_event_func_ptr) (PEVENT_RECORD);
using EventRecordQueue = moodycamel::ConcurrentQueue<EventRecord*>;

class Output;
class InitCollector
{
	friend class InitCollectorFactory;

public:
	InitCollector(EM_InitCollectorMode mode);
	virtual ~InitCollector();

	static uint_64 PARSE_EVENT_COUNT;
	static bool one_hour_cache_clean_flag;

public:
	static InitCollector* GetCollector() { return _instance; }

	virtual void Init() = 0;
	virtual void Excute() = 0;
	virtual void Clean();

	EM_InitCollectorMode GetMode() const { return _mode; }
	LocalDetectorMode GetDetectorMode() const { return _detector_mode; }
	void StopETWSession() { _etw_configuration.StopEtwSession(); }
	void OutputEventRecord(EventRecord* rec);

	void PushSendRecord(EventRecord* rec);
	EventRecord* PopSendRecord();
	size_t WaitSendDataSize();

	void SetProcessLastEvent(DWORD pid, uint_32 provider_id, uint_32 opcode);
	void GetProcessLastEvent(DWORD pid, uint_32& provider_id, uint_32& opcode);

protected:
	void InitEventStruct();

	virtual void InitFilter() = 0;
	void InitCallStackEnableEvent();
	void InitOutput();
	void InitDefaultValue();
	void InitVerification();
	void InitDLLModuleTree();
	void InitKeyAndMouseHook();
	virtual void InitThreadTask();
	virtual void GetSystemContext(); //when collector start,we need to get file/registry/.... object exist in system 
	void ParseAPISignatureFile(std::string file_name);
	std::set<std::string> signature_dll_file_path_;

	EM_InitCollectorMode _mode;
	LocalDetectorMode _detector_mode;
	ETWConfiguration _etw_configuration;
	EventRecordQueue _wait_send_data_queue;

	using OutputList = std::list<Output*>;
	OutputList _output_list;

	std::unordered_map<DWORD, uint_64> _process_last_event;
// add by zxw on 20200109
private:
    mutable RwLock _swap_data_lock;
    bool _swap_flag = false;
//
// add by zxw on 20210508
private:    
    void UpdateUuidEventRecord(EventRecord* rec);                               // 事件添加UUID参数
    bool GetUuidbyProcessId(DWORD process_id, std::wstring& strUuid);           // 获取UUID参数
    void insert_process_id_uuid_map(DWORD process_id, std::wstring strUUID);    // 进程创建时插入
    void erase_process_id_uuid_map(DWORD process_id);                           // 进程退出是删除
    bool query_process_id_uuid_map(DWORD process_id, std::wstring& strUuid);    // 查询
    std::unordered_map<DWORD, std::wstring> _process_uuid_map;                  // 进程ID&UUID缓存map
//
private:
	static InitCollector* _instance;

	DEFINE_PROPERTY_READONLY(bool, insert_child_process);
	DEFINE_PROPERTY_READONLY(bool, sig_verification);
};


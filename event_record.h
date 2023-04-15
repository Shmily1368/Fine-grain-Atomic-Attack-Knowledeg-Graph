#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-3-28
// Updated 2018-4-28

#include "parameter_index.h"
#include "event_identifier.h"
#include <Windows.h>
#include <evntrace.h>

#define EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE L""
#define EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE 0

class ParameterValue
{
public:
	ULONG64 d;
	std::wstring s;
	ParameterValue():d(0),s(L""){}
};

class EventRecord
{
    friend class EventRecordPruner;
	friend class EventRecordManager;
	friend class ExtraTraceSession;
	friend class Output;
	friend class OutputKafka;
	friend class UnitTest;
	friend class OutputJson;
	friend class RecordQueue;
	friend class AvroSnappy;
    friend class public_json_interface;
//public:
//	static int constructor_num;
//	static int destruct_num;
public:
	EventRecord();
	EventRecord(PEVENT_RECORD raw_rec);
	virtual ~EventRecord();

	void copy(EventRecord *origin);
	virtual void InitFrom(EventRecord* origin);

	std::wstring GetStringParameter(parameter_index_enum);
	ULONG64 GetDataParameter(parameter_index_enum);
	bool SetParameter(parameter_index_enum, std::wstring);
	bool SetParameter(parameter_index_enum, ULONG64);

	virtual bool isUseless();
	virtual void InitParse();
	virtual int parse() = 0; //pure virtual function
	int get_process_id_();
	int get_thread_id_();
	//unsigned long long get_time_stamp_() { return time_stamp_; }
	ULONG64 get_time_stamp_() { return time_stamp_; }
	std::string& get_callstack_() { return callstack_; };
	std::vector<std::string>& get_topnapi_() { return topNAPI; };
	EventIdentifier& get_event_identifier_();
	void set_event_identifier_(EventIdentifier);
	void SetProcessTcpPreEventRecord(EventRecord* temp) { process_tcp_pre_eventrecord[process_id_] = temp->get_thread_id_(); }

	static void clear_process_tcp_pre_eventrecord() { process_tcp_pre_eventrecord.clear(); }
	static void SetRunningModeFlag(char flag) { running_mode_flag_ = flag; }

    static bool query_process_id2process_name_map_(DWORD pid) { 
        if (process_id2process_name_map_.count(pid)) return true; else return false;
    }

    // 
    static void update_process_id2network_time_map_(DWORD pid, ULONG64 ulTime);
    static ULONG64 get_process_network_timestamp(DWORD pid);
    //
	//for time translate, calculate nanoseconds since 1970.1.1 0:0:0:000
	static BOOL init;
	void QPCtimeToSystime();
	void init_timecal();

	//first start time 
	static LARGE_INTEGER frequency;
	static ULONG64 start_etwtime;
	static ULONG64 start_systemtime;

	virtual bool Output();

protected:
	static std::unordered_map<DWORD, DWORD> thread_id2process_id_map_;
	static std::vector<DWORD> processor_id2thread_id_list_;
	static std::unordered_map<DWORD, std::wstring> process_id2process_name_map_;
    // pid&network timestamp
    static std::unordered_map<DWORD, ULONG64> process_id2network_time_map_;
	static std::unordered_map<DWORD, DWORD> process_tcp_pre_eventrecord;
	ULONG64 time_stamp_;
	short processor_id_;
	DWORD process_id_;
	DWORD thread_id_;
	EventIdentifier event_identifier_;
	std::string callstack_;
	std::vector<std::string> topNAPI;
	//std::vector<std::string> callback_;
	std::string event_name_;
	bool useless;
	std::vector<ParameterValue> parameter_list_;

	// running mode: "realtime" or "writelogfile" or "parselogfile"
	static char running_mode_flag_;
};

using EventRecordVector = std::vector<EventRecord*>;
using EventRecordList = std::list<EventRecord*>;

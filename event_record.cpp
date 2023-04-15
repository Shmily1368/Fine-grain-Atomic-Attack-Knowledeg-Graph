#include "stdafx.h"
#include "event_record.h"
#include "parameter_index.h"
#include "event_record_manager.h"
#include "init_collector.h"
#include "setting.h"
#include "thread_task_manager.h"

#define EPOCHFILETIME   (116444736000000000UL)

char EventRecord::running_mode_flag_;

std::unordered_map<DWORD, DWORD> EventRecord::process_tcp_pre_eventrecord;
BOOL  EventRecord::init = FALSE;
LARGE_INTEGER EventRecord::frequency;
ULONG64 EventRecord::start_etwtime;
ULONG64 EventRecord::start_systemtime;

//int EventRecord::constructor_num = 0;
//int EventRecord::destruct_num = 0;
EventRecord::EventRecord()
{
	useless = false;
	OBJECT_MEMORY_MONITOR_CTOR(EventRecord);
	//constructor_num++;
}

EventRecord::EventRecord(PEVENT_RECORD raw_rec)
	: time_stamp_(raw_rec->EventHeader.TimeStamp.QuadPart)
	, processor_id_(raw_rec->BufferContext.ProcessorNumber)
	, process_id_(raw_rec->EventHeader.ProcessId)
	, thread_id_(raw_rec->EventHeader.ThreadId)
	, event_identifier_(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Opcode)
	, callstack_(EMPTY_STRING)
	, event_name_(EMPTY_STRING)
	, useless(false)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecord);
    if (!init)
        init_timecal();
}

EventRecord::~EventRecord()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecord);
	//destruct_num++;
}

bool EventRecord::isUseless()
{
	return useless;
}

void EventRecord::InitParse()
{

}

void EventRecord::copy(EventRecord *origin)
{
	*origin = *this;
	origin->parameter_list_.assign(parameter_list_.begin(), parameter_list_.end());
}

void EventRecord::InitFrom(EventRecord* origin)
{
	time_stamp_ = origin->time_stamp_;
	processor_id_ = origin->processor_id_;
	process_id_ = origin->process_id_;
	thread_id_ = origin->thread_id_;
	event_identifier_ = origin->event_identifier_;
	callstack_ = origin->callstack_;
	event_name_ = origin->event_name_;
	useless = origin->useless;
	std::copy(origin->parameter_list_.begin(), origin->parameter_list_.end(), std::back_inserter(parameter_list_));
}

wstring EventRecord::GetStringParameter(parameter_index_enum parameter_name)
{
	int parameter_postion = EventRecordManager::GetInstance().query_parameter_posistion(event_identifier_, parameter_name);
	if (parameter_postion == -1 || parameter_postion >= parameter_list_.size()) {
		return EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE;
	}
	else {
		return parameter_list_[parameter_postion].s;
	}

	return EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE;
}

ULONG64 EventRecord::GetDataParameter(parameter_index_enum parameter_name)
{
	int parameter_postion = EventRecordManager::GetInstance().query_parameter_posistion(event_identifier_, parameter_name);
	if (parameter_postion == -1) {
		return EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE;
	}
	else {
		return parameter_list_[parameter_postion].d;
	}
	return EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE;
}

bool EventRecord::SetParameter(parameter_index_enum parameter_name, wstring parameter_value)
{
	int parameter_postion = EventRecordManager::GetInstance().get_parameter_posistion(event_identifier_, parameter_name);
	if (parameter_postion == parameter_list_.size())
	{
		ParameterValue new_parameter;
		new_parameter.s = parameter_value;
		parameter_list_.push_back(new_parameter);
	}
	else if (parameter_postion > parameter_list_.size())
	{
		//TODO: add log
	}
	else
	{
		parameter_list_[parameter_postion].s = parameter_value;
	}

	return true;
}

bool EventRecord::SetParameter(parameter_index_enum parameter_name, ULONG64 parameter_value)
{
	int parameter_postion = EventRecordManager::GetInstance().get_parameter_posistion(event_identifier_, parameter_name);
	if (parameter_postion == parameter_list_.size())
	{
		ParameterValue new_parameter;
		new_parameter.d = parameter_value;
		parameter_list_.push_back(new_parameter);
	}
	else if (parameter_postion > parameter_list_.size())
	{
		//TODO: add log
	}
	else
	{
		parameter_list_[parameter_postion].d = parameter_value;
	}

	return true;
}

int EventRecord::get_process_id_()
{
	return process_id_;
}

int EventRecord::get_thread_id_()
{
	return thread_id_;
}

void EventRecord::set_event_identifier_(EventIdentifier temp_identifier)
{
	event_identifier_ = temp_identifier;
}
// add by zxw on 20210507
void EventRecord::update_process_id2network_time_map_(DWORD pid, ULONG64 ulTime)
{
    if (process_id2network_time_map_.count(pid))
    {
        process_id2network_time_map_[pid] = ulTime;
    }
}
// add by zxw on 20210507
ULONG64 EventRecord::get_process_network_timestamp(DWORD pid) 
{
    auto it = process_id2network_time_map_.find(pid);
    if (it != process_id2network_time_map_.end())
    {
        return it->second;
    }
    return 0;
}

void EventRecord::QPCtimeToSystime()
{  
	if (!init)
		init_timecal();
    if (frequency.QuadPart != 0) {
        ULONG64 intervaltime = (ULONG64)((time_stamp_ - start_etwtime) * 10000000.0 / frequency.QuadPart); //100-ns 
        time_stamp_ = (start_systemtime + intervaltime) * 100;
    }
	//cout << time_stamp_ << endl;
}

void EventRecord::init_timecal()
{   //Get first timestamp and interval time, to translate time into calculate nanoseconds since 1970.1.1 0:0:0:000
	if (!QueryPerformanceFrequency(&frequency))
	{
        LoggerRecord::WriteLog(L"init_timecal QueryPerformanceFrequency failed err:" + to_wstring(GetLastError()), LogLevel::ERR);
        return;
	}
    
	start_etwtime = time_stamp_;
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	ULONG64 current_tics = (unsigned __int64)ft.dwLowDateTime + (((unsigned __int64)ft.dwHighDateTime) << 32);
	//SystemTimeToFileTime(&sttime, (LPFILETIME)&start_systemtime);
	start_systemtime = current_tics - EPOCHFILETIME;  // FILETIME start from 1960.1.1,should translate into 1970
	init = true;
}

EventIdentifier& EventRecord::get_event_identifier_()
{
	return event_identifier_;
}

bool EventRecord::Output()
{
	QPCtimeToSystime();
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);
	return true;
}

#include "stdafx.h"
#include <functional>
#include <fstream>
#include <io.h>

#include "init_collector_online_parse.h"
#include "event_record_subclass.h"
#include "global_enum_def.h"
#include "setting.h"
#include "obtain_entry_address.h"
#include "ntkernel_provider_guid.h"
#include "thread_task_manager.h"
#include "filter.h"
#include "named_pipe_client.h"
#include "tool_functions.h"
#include "event_record_pruner.h"
#include "macro_detector.h"
#include "extra_trace_session.h"
#include "system_call_detector.h"
#include "security_trace_session.h"
#include "sysmon_trace_session.h"

std::vector<std::unordered_map<DWORD, ULONG64>> InitCollectorOnlineParse::last_detect_time(2);	// remotedesktop

DWORD InitCollectorOnlineParse::application_frame_host_pid = 0;

EventRecordQueue InitCollectorOnlineParse::_switch_event_queue;

void InitCollectorOnlineParse::InitPipe()
{
	LoggerRecord::WriteLog(L"InitNamePipe", INFO);
	//pipe.CreateNamedPipeInServer();
	NamedPipeClient::GetInstance().InitPipe();
	LoggerRecord::WriteLog(L"InitNamePipeSuccess", INFO);
}

void InitCollectorOnlineParse::Init()
{
	//EventRecord::SetRunningModeFlag(Setting::GetInstance().GetChar("mode"));
	EventRecord::SetRunningModeFlag(Setting::GetInstance().collector_mode());
	
	InitDefaultValue();
	InitEventStruct();//get eventstruct from format.txt
	InitOutput();
	InitFilter();
	InitThreadTask(); //create thread for image certificate,visible window, 锟斤拷时锟斤拷锟竭筹拷 and ipconfig;
	if (_detector_mode == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK)
	{
		InitCallStackEnableEvent();
		LoggerRecord::WriteLog(L"InitCallstackDetectorMode", INFO);
	}
	else
	{
		SystemCallDetector::GetInstance().Init();
		LoggerRecord::WriteLog(L"InitSysCallDetectorMode", INFO);
	}
#ifndef STANDALONE_COLLECTOR
	InitPipe();
#endif
	//GetSystemContext();
	//InitKeyAndMouseHook(); //To get Keyboard and mouse info,only use  in Wushang's part

	MacroDetector::GetInstance().Init();
    // add by zxw on 20200303 new security audit
    SecurityTraceSession::GetInstance().Init();

	rapidjson::Document j_val;
	j_val.SetObject();
	rapidjson::Value value_t;
	value_t.SetString("CLIENT_START", j_val.GetAllocator());
	j_val.AddMember("CMD", value_t, j_val.GetAllocator());
	NamedPipeClient::GetInstance().WritePipe(j_val);
}

void InitCollectorOnlineParse::Excute()
{
	//cout << "we get online " << endl;
	ExtraTraceSession::GetInstance().StartSession();
	SecurityTraceSession::GetInstance().StartSession();
    SysmonTraceSession::GetInstance().StartSession();
	int status = _etw_configuration.ConfigureEtwSession(true, ConsumeEvent);
	if (status == -1)
    {
#ifdef OUTPUT_COMMAND_LINE      
		std::cout << "You may have problem in start collector, Please connect with Administrator" << std::endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"You may have problem in start collector, Please connect with Administrator", ERR);
	}
	LoggerRecord::WriteLog(L"InitCollectorOnlineParse::Excute: ETW session exit", LogLevel::ERR);
}

void InitCollectorOnlineParse::Clean()
{
    ExtraTraceSession::GetInstance().StopSession();
    SecurityTraceSession::GetInstance().StopSession();
    SysmonTraceSession::GetInstance().StopSession();
    Sleep(100);
	ThreadTaskManager::GetInstance().Clean();
}

void InitCollectorOnlineParse::CacheClean()
{
	if (one_hour_cache_clean_flag)
	{
		ToolFunctions::CleanCache();

        // add by zxw on 20200424 clean fileio cache
        EventRecordPruner::GetInstance().CleanCache();

		//EventRecordCallstack cache clean
		{
			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_1;
			vector_empty_1.swap(EventRecordCallstack::process_address_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_2;
			vector_empty_2.swap(EventRecordCallstack::process_address_useless_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_3;
			vector_empty_3.swap(EventRecordCallstack::APIaddress_keepon_cache);

			std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>> vector_empty_4;
			vector_empty_4.swap(EventRecordCallstack::process_API_address_cache);
		}

		one_hour_cache_clean_flag = false;
	}
}

void InitCollectorOnlineParse::PushSwitchEventRecord(EventRecord* switch_rec)
{
	_switch_event_queue.enqueue(switch_rec);
}

void InitCollectorOnlineParse::InitFilter()
{
	LoggerRecord::WriteLog(L"InitFilter", INFO);
	Filter::GetInstance().Init();
}

VOID WINAPI InitCollectorOnlineParse::ConsumeEvent(PEVENT_RECORD p_event)
{
	EventRecord* switch_rec;
	while (_switch_event_queue.try_dequeue(switch_rec))
	{
		_ProcessEventRecord(switch_rec);
	}

	CacheClean();

	if (!Filter::GetInstance().FilterBeforeRecInstance(p_event->EventHeader.ProviderId.Data1, p_event->EventHeader.EventDescriptor.Opcode, p_event->EventHeader.ProcessId)) return;
    
	EventRecord* rec = EventRecordManager::GetInstance().ParseEventRecord(p_event);
	if (!rec)
	{
        LoggerRecord::WriteLog(L"EventRecord new failed errcode:" + std::to_wstring(GetLastError()), ERR);
		return;
	}
 
	rec->InitParse();

	// add by zxw on 20191030
	// 特权进程,获取本机ip但是不上报事件
	if (Filter::GetInstance().IsPrivilegeProcess(rec->get_process_id_()))
	{
		if (rec->get_event_identifier_().provider_id() == ETWTcpIp)
		{
			// 设置本机IP
			Filter::GetInstance().SetLoclaIPbyEventRecord((EventRecordTcpip*)rec);
		}
		
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}
	//


	if (!Filter::GetInstance().FilterAfterRecInstance(rec))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}

	_ProcessEventRecord(rec);
}

void InitCollectorOnlineParse::InitThreadTask()
{
	//if (Setting::GetInstance().GetBool("enable_performance_monitor"))
	if (Setting::GetInstance().enable_performace_monitor())
	{
		ThreadTaskManager::GetInstance().AddTask(MONITOR_TASK_MODE);
	}

	ThreadTaskManager::GetInstance().AddTask(GET_VISIBLE_WINDOW_TASK_MODE);
	ThreadTaskManager::GetInstance().AddTask(CERTIFICATE_IMAGE_TASK_MODE);
	//ThreadTaskManager::GetInstance().AddTask(GET_IPCONFIG_TASK_MODE);6锟铰凤拷DARPA锟斤拷目锟斤拷cross machine;锟斤拷时锟斤拷锟斤拷要
	ThreadTaskManager::GetInstance().AddTask(TIMER_TASK_MODE);

    // add by zxw on 2200915
    ThreadTaskManager::GetInstance().AddTask(GET_DEVICE_ARRIVAL_TASK_MODE);
    // add by zxw on 20201012
    if (Setting::GetInstance().enable_rule_match())
    {
        ThreadTaskManager::GetInstance().AddTask(RULE_MATCHER_TASK_MODE);
    }
    // add by zxw on 2201027
    ThreadTaskManager::GetInstance().AddTask(GEE_HASH_TASK_MODE);
    
#ifndef STANDALONE_COLLECTOR
	ThreadTaskManager::GetInstance().AddTask(PIPE_READ_TASK_MODE);
#endif
	//ThreadTaskManager::GetInstance().AddTask(PARSE_EVENT_TASK_MODE);

	ThreadTaskManager::GetInstance().MonitorTask();
    
}

void InitCollectorOnlineParse::_ProcessEventRecord(EventRecord* rec)
{
	rec->parse();
	
	GetCollector()->SetProcessLastEvent(rec->get_process_id_(), rec->get_event_identifier_().provider_id(), rec->get_event_identifier_().opcode());

	//get process_id to filter
	//mainly filter PID in black list, because fileiofilecreate and fileiocreate is need to match rename event and macro ,we do not filter it here
	if (!Filter::FilterAfterParseRecord(rec))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}
	
	rec->SetProcessTcpPreEventRecord(rec);
	if (!rec->Output())
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
	}
}

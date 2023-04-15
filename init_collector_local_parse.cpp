#include "stdafx.h"
#include <functional>
#include <fstream>

#include "init_collector_local_parse.h"
#include "callstack_pruning.h"
#include "event_record_subclass.h"
#include "global_enum_def.h"
#include "setting.h"
#include "obtain_entry_address.h"
#include "ntkernel_provider_guid.h"
#include "thread_task_manager.h"
#include "filter.h"
#include "event_record_pruner.h"

const int PARSE_EVENT_NUM_SLEEP = 5000;

using namespace std;
unsigned long long InitCollectorOfflineParse::event_count;
RecordQueuePerProcess InitCollectorOfflineParse::call_stack_queue;
RecordQueuePerProcess InitCollectorOfflineParse::event_queue;
unsigned long long InitCollectorOfflineParse::call_stack_count;

void InitCollectorOfflineParse::InitCallStackRvaAndDriveMap()
{
	LoggerRecord::WriteLog(L"InitCallStackRvaAndDriveMap", INFO);
// 	ObtainEntryAddress::drivemap.GetDeviceDriveMapFromFile(Setting::GetInstance().GetString("offline_drive_map_file")); 
// 	ObtainEntryAddress::ReadDLLmodualTree(Setting::GetInstance().GetString("offline_dll_rva_folder_path"));
	ObtainEntryAddress::drivemap.GetDeviceDriveMapFromFile(Setting::GetInstance().offline_drive_map_file());
	ObtainEntryAddress::ReadDLLmodualTree(Setting::GetInstance().offline_dll_rva_folder());
}

void InitCollectorOfflineParse::Init()
{
	//EventRecord::SetRunningModeFlag(Setting::GetInstance().GetChar("mode"));
	EventRecord::SetRunningModeFlag(Setting::GetInstance().collector_mode());

	InitDefaultValue();
	InitCallStackRvaAndDriveMap();
	InitEventStruct();
	InitOutput();
	InitFilter();
}

void InitCollectorOfflineParse::Excute()
{
	_etw_configuration.ConsumeLogFile(ConsumeEvent);
	CleanQueue();
}

void InitCollectorOfflineParse::Clean()
{
	
}

void InitCollectorOfflineParse::CacheClean()
{
	if (one_hour_cache_clean_flag)
	{
		EventRecordPruner::GetInstance().CleanCache();

		{
			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vecEmpty_1;
			vecEmpty_1.swap(EventRecordCallstack::process_address_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vecEmpty_2;
			vecEmpty_2.swap(EventRecordCallstack::process_address_useless_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vecEmpty_3;
			vecEmpty_3.swap(EventRecordCallstack::APIaddress_keepon_cache);

			std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>> vecEmpty_4;
			vecEmpty_4.swap(EventRecordCallstack::process_API_address_cache);
		}

		one_hour_cache_clean_flag = false;
	}
}

void InitCollectorOfflineParse::InitFilter()
{
	LoggerRecord::WriteLog(L"InitFilter", INFO);

	//if (Setting::GetInstance().GetString("offline_process_filter_mode(normal,father&child,all)") == "father&child")
	if (Setting::GetInstance().offline_process_filter_mode() == "father&child")
	{
		m_insert_child_process = true;
	}

	Filter::GetInstance().insert_process_id_black_list(-1);
	Filter::GetInstance().insert_event_process_white_list(ETWStackWalk, 32);

	for (auto ix : EventRecordManager::GetInstance().event_strucp_map)
	{
		const EventIdentifier& event_identifier = ix.first;
		Filter::GetInstance().insert_event_process_white_list(event_identifier.provider_id(), event_identifier.opcode());
	}

	//if (Setting::GetInstance().GetString("offline_process_filter_mode(normal,father&child,all)") != "all")
	if (Setting::GetInstance().offline_process_filter_mode() != "all")
	{
		//string output_whitelist_processid = Setting::GetInstance().GetString("offline_output_whitelist_processid");
		String output_whitelist_processid = Setting::GetInstance().offline_output_whitelist_process_id();
		while (output_whitelist_processid != "")
		{
			size_t pos = output_whitelist_processid.find('_');
			if (pos == String::npos)
			{
				int pid = stoi(output_whitelist_processid);
				Filter::insert_process_id_white_list(pid);
				break;
			}
			Filter::insert_process_id_white_list(stoi(output_whitelist_processid.substr(0, pos - 1)));
			output_whitelist_processid.erase(0, pos);
		}
	}
}

VOID WINAPI InitCollectorOfflineParse::ConsumeEvent(PEVENT_RECORD p_event)
{
	CacheClean();

	if (!Filter::GetInstance().FilterBeforeRecInstance(p_event->EventHeader.ProviderId.Data1, p_event->EventHeader.EventDescriptor.Opcode, p_event->EventHeader.ProcessId)) return;

	EventRecord* event_record = EventRecordManager::GetInstance().ParseEventRecord(p_event);
	++PARSE_EVENT_COUNT;
	//if parse_event_number % 5000 sleep 1s if output is not fast
	if (PARSE_EVENT_COUNT % PARSE_EVENT_NUM_SLEEP == 0)
	{
		Sleep(1000);
	}
	event_record->parse();

	//mainly filter PID in black list, because fileiofilecreate and fileiocreate is need to match rename event and macro ,we do not filter it here
	if (!Filter::FilterAfterParseRecord(event_record))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(event_record);
		return;
	}

	event_record->SetProcessTcpPreEventRecord(event_record);
	ParseProviderId(event_record);
	return;
}

/**
 *  @date       2019/01/11
 *  @brief      根据ProviderId 解析不同的event
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks	顺便修改了数字变成宏定义
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseProviderId(EventRecord* _event_record)
{
	switch (_event_record->get_event_identifier_().provider_id())
	{
	case ETWFileIo:
	{
		ParseETWFileIoEvent(_event_record);
		break;
	}
	case ETWImage:
	{
		ParseETWImageEvent(_event_record);
		break;
	}
	case ETWStackWalk:
	{
		ParseETWStackWalkEvent(_event_record);
		break;
	}
	case ETWThread:
	{
		ParseETWThreadEvent(_event_record);
		break;
	}
	default:
	{
		ParseDefaultEvent(_event_record);
		break;
	}
	}
	return;
}

void InitCollectorOfflineParse::CleanQueue()
{
	std::pair<void*, void*> ret_pair;
	event_queue.Alignment(call_stack_queue);
	while (true) 
	{ //&& event_queue.CheckAlignment(call_stack_queue)
		ret_pair = event_queue.output(call_stack_queue);
		if (!ret_pair.first) break;

		OutputEventRecord((EventRecord*)ret_pair.first);
		OutputEventRecord((EventRecord*)ret_pair.second);
	}

	call_stack_count = 0;
	event_count = 0;
	call_stack_queue.ClearDeque();
	event_queue.ClearDeque();
}

/**
 *  @date       2019/01/11
 *  @brief      解析ETWFileIo事件
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseETWFileIoEvent(EventRecord* _event_record)
{
	EventMacroResult* macro_event = new EventMacroResult(dynamic_cast<EventRecordFileio*>(_event_record));
	if (macro_event->Output())
	{
		InitCollector::GetCollector()->PushSendRecord(macro_event);
	}
	else
	{
		SAFE_DELETE(macro_event);
	}

	int event_opcode = _event_record->get_event_identifier_().opcode();

	if (!ParseOPCode(_event_record))
	{
		return;
	}
	InitCollector::GetCollector()->PushSendRecord(_event_record);
}
/**
 *  @date       2019/01/10
 *  @brief      根据opcode 解析不同的event
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return		bool false则为这条event  记录我们不需要关心 反之需要
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
bool InitCollectorOfflineParse::ParseOPCode(EventRecord* _event_record)
{
	cout << "we get_____________" << endl;
	int event_opcode = _event_record->get_event_identifier_().opcode();

	switch (event_opcode)
	{
	case EM_FileioEventOPC::FileioRenameEvent:  //FileIoRename
	case EM_FileioEventOPC::FileIoRenamePath:  //FileIoRenamePath  (appear in WIN10)
	{
		((EventRecordFileio*)(_event_record))->renameCache();
		return false;
		//break;
	}
	case EM_FileioEventOPC::FileioFileCreateEvent:  //FileIoFileCreate  
	{
		
		EventRecord* rename_event = ((EventRecordFileio*)(_event_record))->renameCache();
		if (rename_event) 
		{
			rename_event->QPCtimeToSystime();
			InitCollector::GetCollector()->PushSendRecord(rename_event);
		}

		//do not send FileIoFileCreate,delete and return 
		delete _event_record;
		return false;
	}
	case EM_FileioEventOPC::FileioCreateEvent: 
	{
		//do not send FileIoCreate,delete and return 
		delete _event_record;
		return false;
	}
	case EM_FileioEventOPC::FileIoRead:    //FileIoRead
	case EM_FileioEventOPC::FileIoWirte:    //FileIoWrite
	{
		//if (!((EventRecordFileio*)(_event_record))->purnFileIoRead()) 
		if (!EventRecordPruner::GetInstance().PrunFileIoReadWrite(dynamic_cast<EventRecordFileio*>(_event_record)))
		{
			delete _event_record;
			return false;
		}
		return true;
	}
	default:
		return true;
	}
}

/**
 *  @date       2019/01/11
 *  @brief      解析ETWImage事件
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseETWImageEvent(EventRecord* _event_record)
{
	if ((_event_record->get_event_identifier_().opcode() == EM_ImageEventOPC::ImageDCStart || _event_record->get_event_identifier_().opcode() == EM_ImageEventOPC::ImageLoad))
	{
		EventRecord * temp = new EventRecordImage;
		_event_record->copy(temp);
		if (ThreadTaskManager::GetInstance().AddEventRecord(CERTIFICATE_IMAGE_TASK_MODE, temp) == false)
		{
			delete temp;
		}
	}
	InitCollector::GetCollector()->PushSendRecord(_event_record);
}

/**
 *  @date       2019/01/11
 *  @brief      解析ETWStackWalk事件
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseETWStackWalkEvent(EventRecord* _event_record)
{
	if (!CallstackPruning::pruning(_event_record))
	{
		SAFE_DELETE(_event_record);
		return;
	}
	InitCollector::GetCollector()->PushSendRecord(_event_record);
}

/**
 *  @date       2019/01/11
 *  @brief      解析ETWThread事件
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseETWThreadEvent(EventRecord* _event_record)
{
	//if (_event_record->get_event_identifier_().opcode == EM_ThreadEventOPC::ThreadEnd)
	//{
	//	ThreadTaskManager::GetInstance().AddEventRecord(GET_THREAD_END_EVENT_TASK_MODE, _event_record);
	//	return;
	//}
	//else
	//{
	InitCollector::GetCollector()->PushSendRecord(_event_record);
	//}
}

/**
 *  @date       2019/01/11
 *  @brief      解析Default事件
 *  @param[in]  EventRecord* event事件的指针
 *  @param[out]
 *  @return
 *  @pre
 *  @remarks
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.0
 */
void InitCollectorOfflineParse::ParseDefaultEvent(EventRecord* _event_record)
{
	InitCollector::GetCollector()->PushSendRecord(_event_record);
}
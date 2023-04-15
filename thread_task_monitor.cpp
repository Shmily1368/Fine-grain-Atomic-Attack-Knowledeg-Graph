#include "stdafx.h"
#include "thread_task_monitor.h"
#include "global_enum_def.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "obtain_entry_address.h"
#include "certificate_tool.h"
#include "tool_functions.h"
#include "event_record_pruner.h"
#include "filter.h"

#include <windows.h> 
#include <wbemidl.h> 
#include <psapi.h>

//需要读写锁;
void MemoryMonitor()
{
	/*long long memory_size = 0;
	string temp;
	for (auto i = EventRecordCallstack::process_address_cache.begin(); i != EventRecordCallstack::process_address_cache.end(); i ++)
	{

		memory_size += i->second.size() * 8;
		memory_size += 4;
	}
	memory_size = memory_size / 1024;
	temp = "DebugThread::EventRecordCallstack::process_address_cache memory use: " + std::to_string(memory_size) + "KB";
	cout << temp.c_str() <<endl;
	LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp) , LogLevel::INFO);

	memory_size = 0;
	for (auto i = EventRecordCallstack::process_address_useless_cache.begin(); i != EventRecordCallstack::process_address_useless_cache.end(); i++)
	{

		memory_size += i->second.size() * 8;
		memory_size += 4;
	}
	memory_size = memory_size / 1024;
	temp = "DebugThread::EventRecordCallstack::process_address_useless_cache memory use: " + std::to_string(memory_size) + "KB";
	cout << temp.c_str() << endl;
	LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp), LogLevel::INFO);

	memory_size = 0;
	for (auto i = EventRecordCallstack::APIaddress_keepon_cache.begin(); i != EventRecordCallstack::APIaddress_keepon_cache.end(); i++)
	{

		memory_size += i->second.size() * 8;
		memory_size += 4;
	}
	memory_size = memory_size / 1024;
	temp = "DebugThread::EventRecordCallstack::APIaddress_keepon_cache memory use: " + std::to_string(memory_size) + "KB";
	cout << temp.c_str() << endl;
	LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp), LogLevel::INFO);


	memory_size = 0;
	for (auto i = EventRecordCallstack::process_API_address_cache.begin(); i != EventRecordCallstack::process_API_address_cache.end(); i++)
	{

		for (auto j = i->second.begin(); j != i->second.end(); j++)
		{
			memory_size += 8;
			memory_size += j->second.capacity();
		}
		memory_size += 4;
	}
	memory_size = memory_size / 1024;
	temp = "DebugThread::EventRecordCallstack::process_API_address_cache memory use: " + std::to_string(memory_size) + "KB";
	cout << temp.c_str() << endl;
	LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp), LogLevel::INFO);*/
}


void MonitorThreadTask::_Excute()
{
    // add by zxw on 20191225
//     Sleep(MS_ONE_SECOND);
//     SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    bool isFirst = true;
	uint_32 counter = 0;
	while (!_stop_flag)
	{
		++counter;
		if (counter % 10 == 0)
		{
			//counter = 0;

			_DataCacheMonitor();
			_ProcessMemoryMonitor();
#ifdef OBJECT_MEMORY_MONITOR
			_MemoryLeakMonitor();
#endif
		}
        // add by zxw on 20200821
        if (counter % 100 == 0) // every 100 s 
        {           
            if (isFirst)
            {
                isFirst = false;
                SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
                LoggerRecord::WriteLog(L"first start SetProcessWorkingSetSize Process Mem WorkingSetSize: " + std::to_wstring(_mem_WorkingSetSize) + L" MB" +
                    L" PagefileUsage: " + std::to_wstring(_mem_PagefileUsage) + L" MB", INFO);
            }
        }
        // add by zxw on 20191225 SetProcessWorkingSetSize
        if (counter % 1000 == 0) // every 1000 s 
        {
            counter = 0;
            if (_mem_WorkingSetSize > MAX_MEM_SET_SIZE) // mem > 120MB
            {                
                SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
                LoggerRecord::WriteLog(L"SetProcessWorkingSetSize Process Mem WorkingSetSize: " + std::to_wstring(_mem_WorkingSetSize) + L" MB" +
                    L" PagefileUsage: " + std::to_wstring(_mem_PagefileUsage) + L" MB", INFO);
            }
        }
        //
		Sleep(MS_ONE_SECOND);
	}
}
/*
void MonitorThreadTask::_ProcessMemoryMonitor()
{
	HANDLE handle = GetCurrentProcess();
	PROCESS_MEMORY_COUNTERS_EX pmc = { 0 };
	if (!GetProcessMemoryInfo(handle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
	{
		LoggerRecord::WriteLog(L"error in get process Mem", INFO);
	}
	else
	{
		int_32 mem_count = (int_32)(pmc.PagefileUsage / (1024 * 1024));
		LoggerRecord::WriteLog(L"Process Mem: " + std::to_wstring(mem_count) + L" MB", INFO); //  //在任务管理器中显示为：内存（专用工作集） //这是任务管理器的默认显示项！ (虚拟内存);
	}
}
*/
void MonitorThreadTask::_ProcessMemoryMonitor()
{
    int_32 mem_pagefileusage = 0;
    int_32 mem_workingsetsize = 0;
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    OSVERSIONINFO osvi;
    memset(&osvi, 0, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);


    HANDLE handle = GetCurrentProcess();
    if (handle)
    {          
        PROCESS_MEMORY_COUNTERS_EX procCnt = { 0 };
        if (GetProcessMemoryInfo(handle, (PPROCESS_MEMORY_COUNTERS)&procCnt, sizeof(procCnt)))
        {
            mem_workingsetsize = procCnt.WorkingSetSize * 1.0f / 1048576;
            mem_pagefileusage = (int_32)(procCnt.PagefileUsage / (1024 * 1024));
        }
        else
            LoggerRecord::WriteLog(L"GetProcessMemoryInfo error in get process Mem, errcode = " + std::to_wstring(GetLastError()), LogLevel::ERR);
       
        if (osvi.dwMajorVersion >= 6)
        {
            PSAPI_WORKING_SET_INFORMATION workSet;
            memset(&workSet, 0, sizeof(workSet));
            BOOL bRet = QueryWorkingSet(handle, &workSet, sizeof(workSet));
            if (bRet || (!bRet && GetLastError() == ERROR_BAD_LENGTH))
            {
                int nSize = sizeof(workSet.NumberOfEntries) + workSet.NumberOfEntries * sizeof(workSet.WorkingSetInfo);
                char* pBuf = new char[nSize];
                if (pBuf)
                {
                    QueryWorkingSet(handle, pBuf, nSize);
                    PSAPI_WORKING_SET_BLOCK* pFirst = (PSAPI_WORKING_SET_BLOCK*)(pBuf + sizeof(workSet.NumberOfEntries));
                    INT64 dwMem = 0;
                    for (ULONG_PTR nMemEntryCnt = 0; nMemEntryCnt < workSet.NumberOfEntries; nMemEntryCnt++, pFirst++)
                    {
                        if (pFirst->Shared == 0) dwMem += si.dwPageSize;
                    }
                    delete pBuf;
                    pBuf = NULL;

                    if (workSet.NumberOfEntries > 0)
                    {
                        mem_workingsetsize = dwMem / 1048576;
                    }
                }
            }
            else
            {
                LoggerRecord::WriteLog(L"error in get process Mem, errcode = " + std::to_wstring(GetLastError()), LogLevel::ERR);
            }
        }
        CloseHandle(handle);
    }
    else
    {
        LoggerRecord::WriteLog(L"error in get process Mem GetCurrentProcess failed, errcode = " + std::to_wstring(GetLastError()), LogLevel::ERR);
    }
    _mem_WorkingSetSize = mem_workingsetsize;
    _mem_PagefileUsage = mem_pagefileusage;
    LoggerRecord::WriteLog(L"Process Mem: " + std::to_wstring(mem_workingsetsize) + L" MB", INFO); //  //在任务管理器中显示为：内存（专用工作集） //这是任务管理器的默认显示项！ (虚拟内存);
}

void MonitorThreadTask::_DataCacheMonitor()
{
	size_t wait_send_num;
	if (InitCollector::GetCollector())
		wait_send_num = InitCollector::GetCollector()->WaitSendDataSize();
#ifdef OUTPUT_COMMAND_LINE       
	cout << "DebugThread::wait_send_dataqueue size: " << wait_send_num << endl;
#endif // OUTPUT_COMMAND_LINE;
// 	size_t wait_parse_count = InitCollector::wait_parse_event_queue.size_approx();
// 	cout << "DebugThread::wait_parse_event_queue size: " << wait_parse_count << endl;

	LoggerRecord::WriteLog(L"DebugThread: wait_send_dataqueue: " + std::to_wstring(wait_send_num), INFO);
//	LoggerRecord::WriteLog(L"DebugThread: wait_parse_event_queue: " + std::to_wstring(wait_parse_count), INFO);

	LoggerRecord::WriteLog(L"FileKeyMap: " + std::to_wstring(EventRecordFileio::file_key2file_info_map.size()), INFO);
	LoggerRecord::WriteLog(L"FileObjectMap: " + std::to_wstring(EventRecordFileio::file_object2file_info_map.size()), INFO);
	LoggerRecord::WriteLog(L"FileRenameMap: " + std::to_wstring(EventRecordFileio::fileiorename_cache_map.size()), INFO);

	LoggerRecord::WriteLog(L"Certificate_map: " + std::to_wstring(CertificateTool::CertificateCacheSize()), INFO);

	LoggerRecord::WriteLog(L"ObtainEntryAddress: DLLmodualTree count = " + std::to_wstring(ObtainEntryAddress::DLLmodualTree.size()), INFO);
	LoggerRecord::WriteLog(L"ObtainEntryAddress: exe_node_map count = " + std::to_wstring(ObtainEntryAddress::exe_node_map.size()), INFO);
	LoggerRecord::WriteLog(L"ObtainEntryAddress: module_btree_map count = " + std::to_wstring(ObtainEntryAddress::module_btree_map.size()), INFO);

    // registry cache
    LoggerRecord::WriteLog(L"EventRecordRegistry::key_handle2key_name_map: " + std::to_wstring(EventRecordRegistry::key_handle2key_name_map.size()), INFO);
    LoggerRecord::WriteLog(L"EventRecordRegistry::thread2_keyname: " + std::to_wstring(EventRecordRegistry::thread2_keyname.size()), INFO); 

	EventRecordPruner::GetInstance().LogCacheSize();

    // add by zxw on 20200812
    Filter::GetInstance().LogCacheSize();

}

MonitorThreadTask::MonitorThreadTask()
	: BaseThreadTask(MONITOR_TASK_MODE)
{
	
}

MonitorThreadTask::~MonitorThreadTask()
{

}

void MonitorThreadTask::Log()
{

}

void MonitorThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitMonitorThreadTask", INFO);
#ifdef OUTPUT_COMMAND_LINE       
	cout << "InitMonitorThreadTask" << endl;
#endif // OUTPUT_COMMAND_LINE;
}

#ifdef OBJECT_MEMORY_MONITOR

void MonitorThreadTask::_MemoryLeakMonitor()
{
	AutoLock lock(_lock);

	for (auto i : _object_info_map)
	{
		std::wstring temp = L"MonitorThreadTask::_MemoryLeakMonitor: object is " + ToolFunctions::StringToWString(i.first) \
			+ L" ,construction_num = " + std::to_wstring(i.second.construction_num) \
			+ L" ,destructor_num = " + std::to_wstring(i.second.destructor_num);
		LoggerRecord::WriteLog(temp, LogLevel::INFO);
		std::wcout << temp << endl;
	}
}

void MonitorThreadTask::AddObjectInfo(EM_MonitorObjectInfoType type, const string& object_name)
{
	AutoLock lock(_lock);

	if (_object_info_map.find(object_name) != _object_info_map.end())
	{
		ObjectInfo& object_info = _object_info_map[object_name];
		if (type == EM_MonitorObjectInfoType::CONSTRUCTION_TYPE)
		{
			object_info.construction_num++;
		}
		else
		{
			object_info.destructor_num++;
		}
	}
	else
	{
		ObjectInfo object_info;
		object_info.construction_num = 1;
		_object_info_map[object_name] = object_info;
	}
}

#endif


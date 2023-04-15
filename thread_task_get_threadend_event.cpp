#include "stdafx.h"
#include "thread_task_get_threadend_event.h"
#include "init_collector.h"
#include "global_enum_def.h"

GetThreadEndEventThreadTask::GetThreadEndEventThreadTask()
	: BaseThreadTask(GET_THREAD_END_EVENT_TASK_MODE)
{
	
}

GetThreadEndEventThreadTask::~GetThreadEndEventThreadTask()
{

}

//every ThreadEnd event enter	,after 10S put it into wait send queue 
void GetThreadEndEventThreadTask::_Excute()
{
	while (!_stop_flag) 
	{
		void* threaditem;
		uint_64 current_time_back;
		uint_64 current_time;
		FILETIME ft;
		if (!_threadend_dataqueue.empty()) 
		{
			//Sleep(5000);
			GetSystemTimeAsFileTime(&ft);
			current_time_back = (uint_64)ft.dwLowDateTime + (((uint_64)ft.dwHighDateTime) << 32);
			current_time = (current_time_back - EPOCHFILETIME) * 100;

			bool flag = _threadend_dataqueue.front_pop(threaditem);
			if (!flag) continue;
			while (current_time - ((EventRecord*)threaditem)->get_time_stamp_() < NS_TEN_SECOND)
			{
				Sleep(MS_ONE_SECOND);
				current_time += NS_TEN_SECOND;
			}
			InitCollector::GetCollector()->PushSendRecord((EventRecord*)threaditem);
		}
		else
		{
			Sleep(MS_ONE_SECOND);
		}
	}
}

void GetThreadEndEventThreadTask::Log()
{
	LoggerRecord::WriteLog(L"GetThreadEndEventThreadTask: " + std::to_wstring(_threadend_dataqueue.size()), INFO);
}

void GetThreadEndEventThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitThreadEnd", INFO);
}

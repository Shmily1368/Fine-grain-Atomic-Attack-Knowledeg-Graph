#include "stdafx.h"
#include "common.h"
#include "thread_task_manager.h"
#include "thread_task_base.h"
#include "thread_task_get_visiblewindow.h"
#include "thread_task_cerficate_image.h"
#include "thread_task_count_timer.h"
#include "thread_task_get_threadend_event.h"
#include "thread_task_hook_keyandmouse.h"
#include "thread_task_output_record.h"
#include "thread_task_get_ipconfig.h"
#include "thread_task_monitor.h"
#include "thread_task_pipe_read.h"
#include "thread_task_parse_event.h"
#include "thread_task_get_devicearrival.h"
#include "thread_task_rule_matcher.h"
#include "thread_task_get_hash.h"
#include <thread>

void ThreadTaskManager::MonitorTask()
{
	_monitor_stop = false;
	_monitor_thread = std::thread(&ThreadTaskManager::_MonitorTask, this);
	//_monitor_thread.detach();
}

bool ThreadTaskManager::GetVisibleWindow(EM_ThreadTaskMode type, DWORD pid) 
{
    if (type == GET_VISIBLE_WINDOW_TASK_MODE) {
       
        if (_thread_task_map.find(type) != _thread_task_map.end()) {
            GetVisibleWindowThreadTask* task = (GetVisibleWindowThreadTask*)_thread_task_map[type];
            if (task == nullptr)
            {
                return false;
            }
            return task->QueryVisiblebyProcessId(pid);
        }
    }

    return false;
}

bool ThreadTaskManager::AddEventRecord(EM_ThreadTaskMode type, EventRecord* record)
{
    // mod by zxw on 20201012 add RULE_MATCHER_TASK_MODE
	if (type == CERTIFICATE_IMAGE_TASK_MODE || type == RULE_MATCHER_TASK_MODE || type == GEE_HASH_TASK_MODE)
	{
		//_lock.lock();

		if (_thread_task_map.find(type) != _thread_task_map.end())
		{
			BaseThreadTask* task = _thread_task_map[type];
			task->AddData(record);
			return true;
		}

		//_lock.unlock();
	}

	return false;
}

void ThreadTaskManager::AddTask(EM_ThreadTaskMode type)
{
	AutoLock lock(_lock);

	if (_thread_task_map.find(type) == _thread_task_map.end())//the same thread task just allow one
	{
		BaseThreadTask* task = NULL;
		switch (type)
		{
		case GET_VISIBLE_WINDOW_TASK_MODE:
			task = new GetVisibleWindowThreadTask();
			break;
		case CERTIFICATE_IMAGE_TASK_MODE:
			task = new CertificateImageThreadTask();
			break;
		case HOOK_KEY_MOUSE_TASK_MODE:
			task = new HookKeyAndMouseThreadTask();
			break;
		case TIMER_TASK_MODE:
			task = new TimerCountThreadTask();
			break;
		case OUTPUT_RECORD_TASK_MODE:
			task = new OutputRecordThreadTask();
			break;
		case GET_IPCONFIG_TASK_MODE:
			task = new GetIpConfigThreadTask();
			break;
		case MONITOR_TASK_MODE:
			task = new MonitorThreadTask();
			break;
		case PIPE_READ_TASK_MODE:
			task = new PipeReadThreadTask();
			break;
		case PARSE_EVENT_TASK_MODE:
			task = new ParseEventThreadTask();
			break;
        case GET_DEVICE_ARRIVAL_TASK_MODE:
            task = new GetDeviceArrivalThreadTask();
            break;
        case RULE_MATCHER_TASK_MODE:
            task = new RuleMatcherThreadTask();
            break;
        case GEE_HASH_TASK_MODE:
            task = new GetHashThreadTask();
            break;
            
		}

		if (task)
		{
			task->Init();
			task->Start();

			_thread_task_map[type] = task;
		}
	}
}

void ThreadTaskManager::StopTask(EM_ThreadTaskMode type)
{
	AutoLock lock(_lock);

	auto iter_f = _thread_task_map.find(type);
	if (iter_f != _thread_task_map.end())
	{
		BaseThreadTask* task = iter_f->second;
		task->Stop();

		SAFE_DELETE(task);
		_thread_task_map.erase(iter_f);
	}
}

void ThreadTaskManager::Clean()
{
	_monitor_stop = true;
	if (_monitor_thread.joinable())
	{
		_monitor_thread.join();
	}

	auto iter = _thread_task_map.begin();
	while (iter != _thread_task_map.end())
	{
		BaseThreadTask* task = iter->second;
		task->Stop();

		SAFE_DELETE(task);
		iter = _thread_task_map.erase(iter);
	}
}

#ifdef OBJECT_MEMORY_MONITOR
void ThreadTaskManager::OnObjectCtor(const string& type_name)
{
	//because _thread_task_map only write in init process.so dont use lock 

	if (_thread_task_map.find(MONITOR_TASK_MODE) != _thread_task_map.end())
	{
		if (MonitorThreadTask* task = dynamic_cast<MonitorThreadTask*>(_thread_task_map[MONITOR_TASK_MODE]))
		{
			task->AddObjectInfo(EM_MonitorObjectInfoType::CONSTRUCTION_TYPE, type_name);
		}
	}
}

void ThreadTaskManager::OnObjectDtor(const string& type_name)
{
	if (_thread_task_map.find(MONITOR_TASK_MODE) != _thread_task_map.end())
	{
		if (MonitorThreadTask* task = dynamic_cast<MonitorThreadTask*>(_thread_task_map[MONITOR_TASK_MODE]))
		{
			task->AddObjectInfo(EM_MonitorObjectInfoType::DESTRUCTION_TYPE, type_name);
		}
	}
}
#endif

void ThreadTaskManager::_MonitorTask()
{
	Sleep(MS_ONE_SECOND * 5);

	while (!_monitor_stop) 
	{
		//Sleep(MS_ONE_SECOND);
        Sleep(MS_ONE_SECOND * 5);

		AutoLock lock(_lock);

		for (auto iter = _thread_task_map.begin(); iter != _thread_task_map.end(); iter++)
		{
			BaseThreadTask* task = iter->second;
			task->Log();
		}
	}
}

/********************************************************************
	Created:		2019-01-09
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task manager;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/01/09 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/
#pragma once
#include <vector>
#include <mutex>

#include "thread_task_base.h"
#include "event_record_subclass.h"

class ThreadTaskManager
{
public:
	SINGLETON_DEFINITION(ThreadTaskManager);

	void MonitorTask();
    // add by zxw on 20201229
    bool GetVisibleWindow(EM_ThreadTaskMode type, DWORD pid);

	bool AddEventRecord(EM_ThreadTaskMode type, EventRecord* record);
	void AddTask(EM_ThreadTaskMode type);
	void StopTask(EM_ThreadTaskMode type);
	void Clean();

#ifdef OBJECT_MEMORY_MONITOR
	void OnObjectCtor(const string& type_name);
	void OnObjectDtor(const string& type_name);
#endif
	//void AddMultiTasks();

private:
	ThreadTaskManager(void) { _monitor_stop = false; };
	~ThreadTaskManager(void) {};

	void _MonitorTask();

private:
	std::map<EM_ThreadTaskMode, BaseThreadTask*> _thread_task_map;

	bool _monitor_stop;
	Mutex _lock;
	std::thread _monitor_thread;
};
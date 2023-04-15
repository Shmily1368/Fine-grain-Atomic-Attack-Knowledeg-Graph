/********************************************************************
	Created:		2019-03-28
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to monitor system status;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/03/28 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#include "thread_task_base.h"
#include "global_enum_def.h"

#ifdef OBJECT_MEMORY_MONITOR
class ObjectInfo
{
public:
	ObjectInfo() {
		construction_num = 0; 
		destructor_num = 0;
	};
	~ObjectInfo() {};

	ULONG construction_num;
	ULONG destructor_num;
};
#endif

class MonitorThreadTask : public BaseThreadTask
{
private:
    int_32 _mem_WorkingSetSize;
    int_32 _mem_PagefileUsage;    
private:
	virtual void _Excute();

	void _ProcessMemoryMonitor();
	void _DataCacheMonitor();

#ifdef OBJECT_MEMORY_MONITOR
	Mutex _lock;
	std::unordered_map<string, ObjectInfo> _object_info_map;
	void _MemoryLeakMonitor();
#endif

public:
	MonitorThreadTask();
	~MonitorThreadTask();
	virtual void Log();
	virtual void Init();
#ifdef OBJECT_MEMORY_MONITOR
	void AddObjectInfo(EM_MonitorObjectInfoType type, const string& object_name);
#endif
};
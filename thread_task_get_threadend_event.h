/********************************************************************
	Created:		2019-01-15
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to get threadend event;
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
#include "thread_task_base.h"
#include "event_record.h"
#include "concurrent_queue.h"

class GetThreadEndEventThreadTask : public BaseThreadTask
{
private:
	concurrent_queue<void*> _threadend_dataqueue;// delay deal ThreadEnd event
	virtual void _Excute();
public:
	GetThreadEndEventThreadTask();
	~GetThreadEndEventThreadTask();
	virtual void Log();
	virtual void Init();
};


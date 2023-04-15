/********************************************************************
	Created:		2019-01-15
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to set flag with timer;
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

class TimerCountThreadTask : public BaseThreadTask
{
private:
	virtual void _Excute();
public:
	TimerCountThreadTask();
	~TimerCountThreadTask();

	virtual void Log();
	virtual void Init();
};
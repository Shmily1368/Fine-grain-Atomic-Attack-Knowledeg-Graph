/********************************************************************
	Created:		2020-09-29
	Author:			zxw;
	Version:		1.0.0(version);
	Description:	thread task to match rule;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2020-09-29 |	1.0.0	 |	zxw		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"
#include "event_record.h"
#include "concurrent_queue.h"
#include "event_identifier.h"
#include "publicstruct.h"

class RuleMatcherThreadTask : public BaseThreadTask
{
private:
    concurrent_queue<EventRecord*> _certificate_data_queue;
	Semaphore _signal;
	

private:
	virtual void _Excute() override;

public:
    RuleMatcherThreadTask();
	~RuleMatcherThreadTask();
	virtual void Log() override;
	virtual void Init() override;
	virtual void Stop() override;
	virtual void AddData(EventRecord* record) override;
};
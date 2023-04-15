/********************************************************************
	Created:		2019-01-15
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to output record in wait_send_dataqueue;
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

class OutputRecordThreadTask : public BaseThreadTask
{
private:
	virtual void _Excute();
public:
	OutputRecordThreadTask();
	~OutputRecordThreadTask();

	virtual void Log();
	virtual void Init();
// add by zxw on 20200525
private:
    unsigned long long m_outputlast = 0;
    unsigned long long m_outputcounts = 0;
    DWORD m_stime = clock();
};
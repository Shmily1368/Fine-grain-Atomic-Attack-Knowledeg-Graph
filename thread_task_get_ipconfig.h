/********************************************************************
	Created:		2019-03-14
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to get machine's ip;
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

class GetIpConfigThreadTask : public BaseThreadTask
{
private:
	virtual void _Excute();
	string ip_backup;
public:
	GetIpConfigThreadTask();
	~GetIpConfigThreadTask();

	virtual void Log();
	virtual void Init();
};



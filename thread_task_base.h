/********************************************************************
	Created:		2019-01-09
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task base class;
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
#include "event_record.h"
#include <thread>

class BaseThreadTask
{
protected:
	EM_ThreadTaskMode _mode;
	std::thread _thread;
	bool _stop_flag;

protected:
	virtual void _Excute() = 0;

public:
	BaseThreadTask(EM_ThreadTaskMode mode);
	virtual ~BaseThreadTask(void);

	virtual void Init() = 0;
	virtual void Start();
	virtual void Stop();
	virtual void Log() = 0;
	virtual void AddData(EventRecord* record);
};
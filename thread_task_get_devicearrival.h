/********************************************************************
	Created:		2020-09-14
	Author:			zxw;
	Version:		1.0.0(version);
	Description:	thread task to get DRIVE_REMOVABLE;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2020/09/14 |	1.0.0	 |	zxw		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"

#include <windows.h>
#include <windef.h>

class GetDeviceArrivalThreadTask : public BaseThreadTask
{
private:
	virtual void _Excute();

public:
    GetDeviceArrivalThreadTask();
	~GetDeviceArrivalThreadTask();

	virtual void Log();
	virtual void Init();
    virtual void Stop();
private:
    HWND _hwnd = nullptr;
};
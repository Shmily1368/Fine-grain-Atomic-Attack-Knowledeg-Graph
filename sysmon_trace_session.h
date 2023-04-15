/********************************************************************
    Created:		2020-10-26
    Author:			zxw;
    Version:		1.0.0(version);
    Description:	get sysmon event;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2020-10-2 |	1.0.0	 |	zxw		  | Create file
----------------------------------------------------------------------------
*********************************************************************/
#pragma once
#include <windows.h>
#include <winevt.h>

class SysmonTraceSession
{
	SINGLETON_DEFINITION(SysmonTraceSession);
	DISABLE_COPY(SysmonTraceSession);

public:
    SysmonTraceSession();
	~SysmonTraceSession();

    void Init();
	bool StartSession();
	void StopSession();

    bool MakeSysmonEvent(std::unordered_map<String, String> mdata);
private:
	void _SessionExec();
	static VOID WINAPI _ConsumeEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

private:  
	std::thread _session_worker;
	EVT_HANDLE hSubscription = NULL;   
    bool _end_flag = false;
};
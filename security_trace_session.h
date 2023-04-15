#pragma once

#include <windows.h>
#include <winevt.h>

class SecurityTraceSession
{
	SINGLETON_DEFINITION(SecurityTraceSession);
	DISABLE_COPY(SecurityTraceSession);

public:
	SecurityTraceSession();
	~SecurityTraceSession();

    void Init();
	bool StartSession();
	void StopSession();

private:
	void _SessionExec();
	static VOID WINAPI _ConsumeEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

private:

	std::thread _session_worker;
	EVT_HANDLE hSubscription = NULL;
    bool _end_flag = false;
};
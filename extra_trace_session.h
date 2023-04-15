#pragma once

#include <windows.h>
#include <evntrace.h>

class ExtraTraceSession
{
	SINGLETON_DEFINITION(ExtraTraceSession);
	DISABLE_COPY(ExtraTraceSession);

public:
	ExtraTraceSession();
	~ExtraTraceSession();
    // add by zxw on 20200427 
    void SetTraceProperties(EVENT_TRACE_PROPERTIES* pSessionProperties, ULONG BufferSize);
    // add by zxw on 20201228
    bool StartTraceExec();
	bool StartSession();
	void StopSession();

private:
	void _SessionExec();
    void _EventMonitorExec();
	static VOID WINAPI _ConsumeEvent(PEVENT_RECORD ev_rec);

	void _CheckPowerShellConfig();

private:
	PEVENT_TRACE_PROPERTIES _session_prop;
	TRACEHANDLE _session_handle;

	std::thread _session_worker;
    bool _end_flag = false;
};
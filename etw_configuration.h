/********************************************************************
	Created:		2018-04-09
	Author:			chips;
	Version:		1.1.0(版本号);
	Description:	用于etw数据配置;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/04/09 |	1.0.0	 |	Zhenyuan	  | Create file
----------------------------------------------------------------------------
  2019/01/04 |	1.1.0	 |	chips		  | 删除额外的对成员变量进行配置的函数，在类构造时引入配置;
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#include <Windows.h>
#include <evntrace.h>

class ETWConfiguration
{
public:
	// store the events whose call stack was enable
	static std::set<int> enable_stack_events_set_;

	ETWConfiguration();
	~ETWConfiguration();
    // add by zxw on 20200427 
    void SetTraceProperties(EVENT_TRACE_PROPERTIES* pSessionProperties, ULONG BufferSize, bool is_real_time);
	int ConfigureEtwSession(bool is_real_time, void __stdcall consum_event_realtime(PEVENT_RECORD));
	ULONG StopEtwSession();
	void ConsumeLogFile(void __stdcall consum_event_realtime(PEVENT_RECORD));

	inline void SetLogfilePath(std::wstring logfile_path) {
		logfile_path_ = logfile_path;
	}
	void SetEnableStackEvents(std::vector<CLASSIC_EVENT_ID> enable_stack_events);
private:
    void _EventMonitorExec();
private:
	bool _low_mode;
	ULONG enable_flag_;
	std::wstring logfile_path_; 
	std::vector<CLASSIC_EVENT_ID> enable_stack_events_;

	TRACEHANDLE SessionHandle_ = 0;
	EVENT_TRACE_PROPERTIES* pSessionProperties_ = NULL;

	// logman stop "NT Kernel Logger" -ets
	inline void Preemption() { system("logman stop \"NT Kernel Logger\" -ets"); }
	void SetupEventConsumer(void __stdcall consum_event_realtime(PEVENT_RECORD));
	inline void SetupEventStackwalk();
};


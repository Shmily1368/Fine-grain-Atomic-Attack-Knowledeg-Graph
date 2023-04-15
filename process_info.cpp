#include "stdafx.h"
#include "process_info.h"

std::map<DWORD, ProcessInfoItem> ProcessInfo::process_info; //for scheduler communicate and match process name <-> path 
bool ProcessInfoItem::_time_init_flag = FALSE;
LARGE_INTEGER ProcessInfoItem::frequency;
ULONG64 ProcessInfoItem::start_QPCtime;
ULONG64 ProcessInfoItem::start_systime;


void ProcessInfoItem::TranslateQPCtimeToSystime() {
	if (_time_init_flag) {
		ULONG64 intervaltime = (ULONG64)((timestamp_ - start_QPCtime) * 10000000.0 / frequency.QuadPart); //100-ns 
		timestamp_ = (start_systime + intervaltime) * 100;
	}
	else {
		_time_init_flag = TRUE;
		QueryPerformanceFrequency(&frequency);
		start_QPCtime = timestamp_;
		FILETIME ft;
		GetSystemTimeAsFileTime(&ft);
		ULONG64 current_tics = (unsigned __int64)ft.dwLowDateTime + (((unsigned __int64)ft.dwHighDateTime) << 32);
		start_systime = current_tics - EPOCHFILETIME;
		timestamp_ = start_systime*100;
	}
}
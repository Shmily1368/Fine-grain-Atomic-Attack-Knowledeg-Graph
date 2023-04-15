#pragma once
#ifndef PROCESS_INFO_H_  
#define PROCESS_INFO_H_  

#include <string>
#include <map>
#include <Windows.h>

class ProcessInfoItem {  //pipe translate this struct 
public:
	DWORD process_id_;
	DWORD parent_id_;
	std::wstring file_name_;
	std::wstring file_path_;
	ULONG64 timestamp_;
	static bool _time_init_flag;
	static LARGE_INTEGER frequency;
	static ULONG64 start_QPCtime;
	static ULONG64 start_systime;

	ProcessInfoItem() {};
	ProcessInfoItem(DWORD process_id, ULONG64 timestamp, DWORD parent_id = -1, std::wstring file_name = L"", std::wstring file_path = L"") : process_id_(process_id), parent_id_(parent_id), file_name_(file_name), file_path_(file_path), timestamp_(timestamp)
	{};
	~ProcessInfoItem() {};
	void TranslateQPCtimeToSystime();
};

class ProcessInfo {
public:
	static std::map<DWORD, ProcessInfoItem> process_info;
};

#endif //PROCESS_INFO_H_

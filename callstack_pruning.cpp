#include "stdafx.h"
#include "callstack_pruning.h"
#include <Windows.h>
#include <unordered_map>
#include "event_record_callstack.h"
#include "phf_detector.h"
#include "tool_functions.h"

std::unordered_map<ULONG64, ExeModuleAddress> CallstackPruning::processid_exemoduleaddress_map_;
std::unordered_map<DWORD, std::string> CallstackPruning::processid_lastapiname_map_;
std::unordered_map<DWORD, ULONG64> CallstackPruning::processid_lastentryaddress_map_;

CallstackPruning::CallstackPruning()
{
}


CallstackPruning::~CallstackPruning()
{
}

bool CallstackPruning::pruning(EventRecord* callstack_record) 
{
	return pruningwithAPIName(callstack_record);
}

bool CallstackPruning::pruningwithAPIName(EventRecord* callstack_record) 
{
	int thread_id_ = callstack_record->get_thread_id_();
	const std::string& callstack_str = callstack_record->get_callstack_();
	if (callstack_str.empty())
	{
		return false;
	}
    // add by zxw on 20200805
    if (strstr(callstack_str.c_str(), "NOOAPI") != nullptr ||
        strstr(callstack_str.c_str(), "NOMODULE") != nullptr ||
        strstr(callstack_str.c_str(), "NOAPI") != nullptr) {
        return false;
    }

	if (processid_lastapiname_map_.count(thread_id_) == 0) 
	{
		processid_lastapiname_map_[thread_id_] = callstack_str;
		return true;
	}
	else 
	{
		if (processid_lastapiname_map_[thread_id_] == callstack_str)
		{
			//return true;
			//optimize,fix chips;merge this in signature.h
			//optimize 2, fix chips;这里计算过后面就不需要计算了，未来优化phfdetect,可以提升效率;
			//optimize 3, fix by many; change the way to prun;
			if (callstack_str == "GetAsyncKeyState" || callstack_str == "GetKeyboardState" || callstack_str == "GetKeyState" || callstack_str == "NtUserGetKeyState" || callstack_str == "NtUserGetKeyboardState")
			{               
				//return PhfDetector::keylogger_process_cache.count(callstack_record->get_process_id_()) == 0;
                return PhfDetector::keylogger_thread_cache.count(callstack_record->get_thread_id_()) == 0;
				//return true;
// 				if (PhfDetector::phf_detector_check_flag)
// 				{
// 					PhfDetector::thread_2_keyloggercout_map.clear();
// 				}
// 
// 				if (PhfDetector::thread_2_keyloggercout_map.find(thread_id_) != PhfDetector::thread_2_keyloggercout_map.end())
// 				{
// 					if (PhfDetector::thread_2_keyloggercout_map[thread_id_] > 20)
// 					{
// 						return false;
// 					}
// 
// 					PhfDetector::thread_2_keyloggercout_map[thread_id_] += 1;
// 				}
// 				else
// 				{
// 					PhfDetector::thread_2_keyloggercout_map[thread_id_] = 1;
// 				}
// 
// 				return true;
			}
		}
		else 
		{
			processid_lastapiname_map_[thread_id_] = callstack_str;
			return true;
		}
	}
    
	return false;
    
}

bool CallstackPruning::pruningwithEntryAddress(EventRecord* event_record) 
{
	if (event_record->get_callstack_().empty()) 
	{
		return false;
	}

	EventRecordCallstack* callstack_record = (EventRecordCallstack*)event_record;
	ULONG64 top_address = callstack_record->getTopAddress();
	if (top_address) 
	{
		int thread_id = callstack_record->get_thread_id_();
		if (processid_lastentryaddress_map_.count(thread_id) == 0 || processid_lastentryaddress_map_[thread_id] != top_address)
		{
			processid_lastentryaddress_map_[thread_id] = top_address;
			return true;
		}
	}

	return false;
}

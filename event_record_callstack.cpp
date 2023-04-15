#include "stdafx.h"
#include "callstack_pruning.h"
#include "event_record_manager.h"
#include "obtain_entry_address.h"
#include "event_record_callstack.h"
#include "event_record.h"
#include "tool_functions.h"
#include "init_collector_local_collect.h"
#include "init_collector_online_parse.h"
#include "init_collector.h"
#include "setting.h"
#include "callstack_pruning.h"
#include "phf_detector.h"
#include "thread_task_manager.h"
#include "filter.h"
#include <evntrace.h>
#include <tdh.h>
#include <Windows.h>
#include <sstream>
#include <unordered_set>
#include <string>

using namespace std;
ULONG64 EventRecordCallstack::parse_api_level_number = 0;
using std::cout;

std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::process_address_cache;
std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>>EventRecordCallstack::process_API_address_cache;
std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::process_address_useless_cache;
std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::APIaddress_keepon_cache;

std::function<void(EventRecordCallstack*)> EventRecordCallstack::_parse_func = nullptr;

#ifdef USE_RAW_SIGNATURE

STRING_STRING_UMAP api_filename_mapping = 
{
	{"GetKeyState", "user32.dll"},
	{"GetKeyboardState", "user32.dll"},
	{"GetAsyncKeyState", "user32.dll"},
	{"NtUserGetKeyState", "win32u.dll"},		//Win10 API;
	{"NtUserGetKeyboardState", "win32u.dll"},	//Win10 API;
	{"GetDC", "user32.dll"},
	{"NtUserGetDC", "win32u.dll"},
	{"BitBlt", "gdi32.dll"},
	{"StretchBlt", "gdi32.dll"},
	{"CreateDIBSection", "gdi32.dll"},			//Win10 API;
	{"CreateCompatibleDC", "gdi32.dll"},
	{"CreateCompatibleBitmap", "gdi32.dll"},
	{"SetBkColor", "gdi32.dll"},
	{"SelectObject", "gdi32.dll"},
	{"SelectObjectImpl", "gdi32full.dll"},		//Win10 API;
	{"NtGdiSelectBitmap", "win32u.dll"},			//Win10 API;
	{"ZwCreateNamedPipeFile", "ntdll.dll"},
	{"CreatePipe", "KernelBase.dll"},
	{"ZwOpenProcess", "ntdll.dll"},
	{"OpenProcess", "KernelBase.dll"},
	{"ZwAllocateVirtualMemory", "ntdll.dll"},
	{"VirtualAllocEx", "KernelBase.dll"},
	//{"VirtualAlloc", "KernelBase.dll"},
	{"ZwWriteVirtualMemory", "ntdll.dll"},
	{"WriteProcessMemory", "KernelBase.dll"},
	{"ZwQueryInformationProcess","ntdll.dll"},
	{"K32GetProcessImageFileName","kernel32.dll"},
	{"ZwDeviceIoControlFile","ntdll.dll"},
	{"CryptImportKey","cryptsp.dll"},
};

STRING_SET api_need_set = 
{
	"GetKeyState",
	"GetKeyboardState",
	"GetAsyncKeyState",
	"NtUserGetKeyState",			//Win10 API;
	"NtUserGetKeyboardState",		//Win10 API;
	"GetDC",
	"NtUserGetDC",					//Win10 API;
	"NtGdiCreateDIBSection",		//Win10 API;
	"CreateCompatibleDC",
	"CreateCompatibleBitmap",
	"CreateDIBSection",				//Win10 API;
	"NtGdiCreateCompatibleDC",		//Win10 API;
	"NtGdiCreateCompatibleBitmap",	//Win10 API;
	"BitBlt",
	"NtGdiBitBlt",					//Win10 API;
	"StretchBlt",
	"NtGdiStretchBlt",				//Win10 API;
	"SetBkColor", //1973703913(\\Windows\\SysWOW64\\gdi32.dll:SetBkColor),1973702794(\\Windows\\SysWOW64\\gdi32.dll:SelectObject)
	"NtGdiSelectBitmap",			//Win10 API;
	"SelectObject",
	"SelectObjectImpl",				//Win10 API;
	"NtGdiSelectBitmap",			//Win10 API;
	"ZwCreateNamedPipeFile",
	"CreatePipe",
	"ZwOpenProcess",
	"OpenProcess",
	"ZwAllocateVirtualMemory",
	"VirtualAllocEx",
	//"VirtualAlloc",
	"ZwWriteVirtualMemory",
	"WriteProcessMemory",
	"K32GetProcessImageFileName",
	"CryptImportKey",
};

#else

STRING_STRING_UMAP api_filename_mapping;
STRING_SET api_need_set;

#endif //USE_RAW_SIGNATURE;

STRING_SET api_ntdll_need_set_win7 = 
{
	"ZwCreateNamedPipeFile",
	"ZwOpenProcess",
	"ZwAllocateVirtualMemory",   //process injection
	"ZwWriteVirtualMemory",
	"ZwQueryObject",
	"ZwQueryInformationProcess",
    "ZwFlushInstructionCache",
};

STRING_SET api_ntdll_need_set_win10 =
{
	"ZwCreateNamedPipeFile",
	"ZwOpenProcess",
	"ZwWriteVirtualMemory",
	"ZwQueryInformationProcess",
    "ZwFlushInstructionCache",
};

STRING_SET api_keepon_set_win7 = 
{
	"ZwFreeVirtualMemory",		// remotedesktop, GdipSaveImageToStream;
	"ZwOpenSection",			// audiorecord, waveinopen;
	"ZwWaitForSingleObject",	// waveinaddbuffer;
	"ZwDeviceIoControlFile",
    "ZwAllocateVirtualMemory",
    "ZwFlushInstructionCache",
    "ZwProtectVirtualMemory",
    "ZwLockVirtualMemory",
};

STRING_SET api_keepon_set_win10 =
{
	"ZwFreeVirtualMemory",		// remotedesktop, GdipSaveImageToStream;
	"ZwOpenSection",			// audiorecord, waveinopen;
	"ZwWaitForSingleObject",	// waveinaddbuffer;
	"ZwAllocateVirtualMemory",  // VirtualAllocExNuma;
	"ZwDeviceIoControlFile",
    "ZwFlushInstructionCache",
    "ZwProtectVirtualMemory",
    "ZwLockVirtualMemory",
};

EventRecordCallstack::EventRecordCallstack(PEVENT_RECORD raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordCallstack);

	ULONG64* p_data = (ULONG64*)raw_rec->UserData;
	USHORT data_size = raw_rec->UserDataLength;
	ULONG64 etw_stack_address;

	event_identifier_ = EventIdentifier(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Opcode);

	time_stamp_ = *p_data++;
	process_id_ = *(DWORD*)p_data;
	thread_id_ = *((DWORD*)p_data + 1);
	p_data++;
	//cout << p_data << " pdata"<<endl;

	if (process_id_ == 0 || process_id_ == 4 || process_id_ == GetCurrentProcessId())//3440
	{
		return;
	}

	USHORT stack_size = data_size / 8 - 2;
	for (int i = 0; i < stack_size; i++)
	{
		etw_stack_address = *(p_data + i);
		//cout << etw_stack_address << " etw_stack_address " << i<<endl;
		entry_address_vector_[i] = etw_stack_address;
		++vector_size;
		/*if (entry_address_vector_[i] >= entry_address_vector_[i + 1])cout << "da" << endl;
		else { cout << "xiao" << endl; }*/
		if (etw_stack_address >= 0xfffff00000000000) // kernel address
		{
			//cout <<i<< " get kernel " <<etw_stack_address<< endl; //0 4 10
			kernel_start = i;
		}
	}
	//cout << endl;

	return;
}

EventRecordCallstack::EventRecordCallstack(int pid, int tid, ULONG64 timestamp)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordCallstack);

	thread_id_ = tid;
	process_id_ = pid;
	time_stamp_ = timestamp;
	event_identifier_.provider_id(ETWStackWalk);
	event_identifier_.opcode(32);
	callstack_ = "";
	label_ = "";
}

EventRecordCallstack::~EventRecordCallstack()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordCallstack);
}

void EventRecordCallstack::Init()
{
	if (Setting::GetInstance().optimize_api_parse())
	{
		switch (ToolFunctions::GetSystemOs())
		{
		case EM_OsVersion::WIN7:		_parse_func = ParseTopLevelAPIwithOptimize; break;
		case EM_OsVersion::WIN10:		_parse_func = ParseTopLevelAPIwithOptimizeWin10; break;
		case EM_OsVersion::WS2012_R2:	_parse_func = ParseTopLevelAPIwithOptimizeWS2012R2; break;
		default:	break;
		}
	}
	else
	{
		switch (ToolFunctions::GetSystemOs())
		{
		case EM_OsVersion::WIN7:
		case EM_OsVersion::WIN10:		_parse_func = std::bind(ParseTopLevelAPIwithRunqinTrick, std::placeholders::_1, 0); break;
		case EM_OsVersion::WS2012_R2:	_parse_func = std::bind(ParseTopLevelAPIwithRunqinTrickWS2012R2, std::placeholders::_1, 0); break;
		default:	break;
		}
	}
}

int EventRecordCallstack::parse() 
{
	if (Setting::GetInstance().local_detector_parse())
	{
		PhfDetector::GetInstance().TryDetectPhf();
	}
	_parse_func(this);
	return 0;
}

bool EventRecordCallstack::Output()
{
	if (callstack_ == "CryptImportKey" || callstack_ == "K32GetProcessImageFileName") 
	{
		// ransom need push send
		if (Filter::GetInstance().GetRansomDetector())
		{
            useless = true;
            if (InitCollector::GetCollector())
                InitCollector::GetCollector()->PushSendRecord(this);
            return true;
		}
	}

	if (!CallstackPruning::pruning(this))
	{
		return false;
	}

	this->QPCtimeToSystime();
	bool flag = true;
	//if (Setting::GetInstance().GetBool("local_detector_parse"))
	if (Setting::GetInstance().local_detector_parse())
	{
		if (PhfDetector::GetInstance().PushBack(this) == nullptr)
		{
			flag = false;
		}
		else
		{
			const std::string label_t = GetLabel();
			if (label_t == "RemoteDesktop" || label_t == "AudioRecord")
				//sometime have more than one label,we do not handle this situation  
			{
				int index = label_t == "RemoteDesktop" ? 0 : 1;
				if (InitCollectorOnlineParse::last_detect_time[index].count(get_thread_id_()))
				{
					//10s
					if (get_time_stamp_() - InitCollectorOnlineParse::last_detect_time[index][get_thread_id_()] < 10000000000)
					{
						return false;
					}
					else
					{
						InitCollectorOnlineParse::last_detect_time[index][get_thread_id_()] = get_time_stamp_();
					}
				}
				else
				{
					InitCollectorOnlineParse::last_detect_time[index][get_thread_id_()] = get_time_stamp_();
				}
			}
			if (InitCollector::GetCollector())
				InitCollector::GetCollector()->PushSendRecord(this);
		}
	}
	else
	{
		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(this);
	}

	return flag;
}

void EventRecordCallstack::InitApiConfiguration()
{
#ifndef USE_RAW_SIGNATURE

	std::fstream fp;
	String read_str;

	fp.open("api_configuration/api_filename_mapping", ios::in | ios::binary);
	while (getline(fp, read_str))
	{
		STRING_VECTOR mapping_info;
		StringUtil::split(ToolFunctions::DecryptStr(read_str), ':', mapping_info);
		api_filename_mapping.insert(std::make_pair(mapping_info[0], mapping_info[1]));
	}
	fp.close();

	fp.open("api_configuration/api_need_set", ios::in | ios::binary);
	while (getline(fp, read_str))
	{
		api_need_set.insert(ToolFunctions::DecryptStr(read_str));
	}
	fp.close();
	/*WJ 210828 test prepare API
	for (auto elem : api_need_set)
	{
		cout << elem << endl;
	}*/
#endif // !USE_RAW_SIGNATURE
}

void EventRecordCallstack::SetLabel(const String& label)
{
	if (label_ == "")
		label_ = label;
	else
		label_ += string(",") + label;
}

void EventRecordCallstack::SetCallstack(const String& callstack)
{
	callstack_ = callstack;
}

String EventRecordCallstack::GetLabel()
{
	return label_;
}

String EventRecordCallstack::GetOutputInfo()
{
	if (Setting::GetInstance().local_detector_parse())
	{
		return label_;
	}
	else
	{
		return callstack_;
	}
}

void EventRecordCallstack::ParseTopLevelAPIwithOptimize(EventRecordCallstack* ev)
{
	DWORD pid = ev->process_id_;
	auto &modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::exe_node_map.find(pid) == ObtainEntryAddress::exe_node_map.end())
	{		
		ev->useless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;
	bool flag = false;
	String& ev_callstack = ev->callstack_;
	const auto& address_stack = ev->entry_address_vector_;

	int_32 iter = ev->kernel_start + 1;
	int_32 vector_size = ev->vector_size;
	for (; iter < vector_size; iter++)
	{
		if (flag)   // may be can add cache later for optimize
		{
			// do this operation because we find sometimes callstack:
			/*{"processID":3432,"threadID":3676,"TimeStamp":8172785732,"CallStack":"18446735277688847513(NOMODULE-SYSTEMMODULE),
			1962159625(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962159551(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962660486(\\Windows\\System32\\wow64.dll:Wow64SystemServiceEx),
			1962657438(\\Windows\\System32\\wow64.dll:Wow64LdrpInitialize),
			2001945539(\\Windows\\System32\\ntdll.dll:RtlImageDirectoryEntryToData),
			2002360192(\\Windows\\System32\\ntdll.dll:longjmp),
			2002007838(\\Windows\\System32\\ntdll.dll:LdrInitializeThunk),
			1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			5360515(\\Rats\\Dark Comet 5.3\\Dark Comet\\DarkComet.exe:NOAPI),
			......
			1967421578(\\Windows\\SysWOW64\\user32.dll:DispatchMessageW)"}*/

			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}
			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (strstr(search_module->key_value.FileName.c_str(), api_filename_mapping[ev_callstack].c_str()) == nullptr &&
				api_ntdll_need_set_win7.find(ev_callstack) == api_ntdll_need_set_win7.end())			
			//if (search_module->key_value.FileName.find(api_filename_mapping[ev_callstack]) == string::npos &&
			//	api_ntdll_need_set_win7.find(ev_callstack) == api_ntdll_need_set_win7.end())
			{
				//ev->useless = true;   // remove by zxw on 20200804
				return;
			}
			else
			{
				if (search_module->key_value.rva_tree == NULL)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				// can not get funcation name
				if (!search_function)
				{
					//callstack_ = "1";
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// next is still API we need, such as 
				//1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
				//1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState), 

				// find such as this:
				//8791757691994(\\Windows\\System32\\gdi32.dll:SelectObject)
				//8791757692022(\\Windows\\System32\\gdi32.dll:CreateCompatibleDC)
				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;
					continue;
				}
				else
				{
					//callstack_ = "1";
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}

		}
		else
		{
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call
            if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				cout << "no cache1" << endl;
				continue;
			}
			// save address of system call we do not to parse 
			else if ((process_address_useless_cache[pid]).count(address_stack[iter]))
			{
				cout << "no cache2" << endl;
				// not one we need
				ev->useless = true;
				return;
			}
			// save address of system call we need 
			else if ((process_API_address_cache[pid]).count(address_stack[iter]))
			{  //address of API we need
				cout << "no cache3" << endl;
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];
				continue;
			}
			else if (APIaddress_keepon_cache[pid].count(address_stack[iter]))
			{
				cout << "no cache4" << endl;
				ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);
			if (search_module)
			{
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					return;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win7.find(search_function->key_value.FileName) != api_ntdll_need_set_win7.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later；
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design
							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
								cout << ev_callstack<<"-call"<<endl;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}
								if (process_address_cache.find(address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}
										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
                                            // remove by zxw on 20200623 do not add "zw" in cache
											//process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win7.find(search_function->key_value.FileName) != api_keepon_set_win7.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
							}
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->useless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)				
				{
					node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}
                }
                else if (strstr(search_module->key_value.FileName.c_str(), "kernel32.dll") != nullptr ||
                strstr(search_module->key_value.FileName.c_str(), "KernelBase.dll") != nullptr)
                {
                    node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
                    if (!search_function) {
                        process_address_useless_cache[pid].insert(address_stack[iter]);
                        ev->useless = true;
                        return;
                    }

                    if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end()) {
                        flag = true;
                        process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
                        ev_callstack = search_function->key_value.FileName;
                    }
                    else {
                       continue;
                    }
                }
				else
				{
					ev->useless = true;
					return;
				}
			}
			else
			{
				ev->useless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->useless = true;
	}
}

/*void EventRecordCallstack::ParseTopLevelAPIwithOptimizeWin10(EventRecordCallstack* ev)//real use in win10 OS
{
	//cout << "win10 1API collector statr" << endl;
	DWORD pid = ev->process_id_;
	// WJ add
	//for (auto elem : ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID]) { cout << "WJwin10-" << elem << endl; }
	//cout <<"WJ WIN10-"<< ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID] << endl;

	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	//cout <<"WJ win10 tree"<< modelTree << endl;
	//cout<< "WJWIN10"<< typeid(modelTree).name() << endl;   
	//the type of mode1tree is class btree * __ptr64
	if (!modelTree || ObtainEntryAddress::exe_node_map.find(pid) == ObtainEntryAddress::exe_node_map.end())
	{
		ev->useless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;
	//cout << exe_address_base_ <<"___"<< exe_address_end_ << endl; base<end
	bool flag = false;
	String& ev_callstack = ev->callstack_; //blank or ox address
	const auto& address_stack = ev->entry_address_vector_;

	int iter = ev->kernel_start + 1;//

	int vector_size = ev->vector_size;//
	//if (address_stack[iter - 1] > address_stack[iter])cout << "big knerel"<<endl;
	//else { cout << "small knerel" << endl; }

	//cout << iter << "--" << vector_size << endl;
	
	for (; iter < vector_size; iter++)
	{
		//if (address_stack[iter - 1] > address_stack[iter]) cout << "大" << endl;
		//cout << pid<<"__"<<address_stack[iter] <<"--"<<iter <<" every"<<endl;
		//cout << pid << "__" << exe_address_base_ <<"___"<< exe_address_end_ << endl; //base<end
		//if (ev_callstack != "")
			//cout << ev_callstack << endl;
		//cout << address_stack[iter] << "iter" << endl;
		if (flag)   // may be can add cache later for optimize
		{
			// do this operation because we find sometimes callstack:
			//{"processID":3432,"threadID":3676,"TimeStamp":8172785732,"CallStack":"18446735277688847513(NOMODULE-SYSTEMMODULE),
			//1962159625(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}
			//cout << "lrong" << endl;
			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			//cout << search_module->key_value.rva_tree << "modeltree-search"<<endl;
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (search_module->key_value.rva_tree != NULL)
			{
				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				//cout << search_function->key_value.FileName << endl; //real api name
				// can not get function name
				if (!search_function)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// next is still API we need, such as 
				//1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
				//1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState), 

				// find such as this:
				//8791757691994(\\Windows\\System32\\gdi32.dll:SelectObject)
				//8791757692022(\\Windows\\System32\\gdi32.dll:CreateCompatibleDC)
				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;// just one API name
					//cout << "start" << endl;
					//cout <<"WJ-win10"<< ev_callstack << endl;
					continue;
				}
				else
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}
			else
			{
				return;
			}
		}
		else
		{
			//cout << "addtest"<<address_stack[iter] << endl; //wj ex.  140720874950682
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call

			if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				continue;
			}
			// save address of system call we do not to parse 
			else if (process_address_useless_cache[pid].find(address_stack[iter]) != process_address_useless_cache[pid].end())
			{
				// not one we need
				ev->useless = true;
				return;
			}
			// save address of system call we need 
			else if (process_API_address_cache[pid].find(address_stack[iter]) != process_API_address_cache[pid].end())
			{  //address of API we need
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];//real API readable name
				//cout <<"WJ test 22"<< ev_callstack << endl;
				continue;
			}
			else if (APIaddress_keepon_cache[pid].find(address_stack[iter]) != APIaddress_keepon_cache[pid].end())
			{
				ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);//000002BC3E16A300
			//cout<<"WJ search" << search_module->key_value.FileName << endl;// example: \Windows\SysWOW64\win32u.dll
			//cout << "WJ size"<<process_address_cache.size<< endl;
			std::map < int, std::string > ::iterator it;
			std::map < int, std::string > ::iterator itEnd;

			if (search_module)// find callstack->detection-phf
			{//c_str()是Borland封装的String类中的一个函数，它返回当前字符串的首字符地址
			//换种说法，c_str()函数返回一个指向正规C字符串的指针常量，内容与本string串相同 bywj
			//const char * strstr ( const char * str1, const char * str2 );指向str2 中指定的整个字符序列在str1中第一次出现的指针，如果该序列不存在于str1 中，则为空指针。
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					continue;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win10.find(search_function->key_value.FileName) != api_ntdll_need_set_win10.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later；
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design

							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}

								if (process_address_cache.find(address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										//std::cout << search_next_module->key_value.FileName << std::endl;// should//
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}

										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
											process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win10.find(search_function->key_value.FileName) != api_keepon_set_win10.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
							}
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->useless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);//???
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())//???wj
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "kernel32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "KernelBase.dll") != nullptr)
				{
					node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function) {
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end()) {
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else {
						continue;
					}
				}
				else
				{
					ev->useless = true;
					return;
				}
			}
			else
			{
				ev->useless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->useless = true;
	}
}*/



// TOPNlevel by wangjian
void EventRecordCallstack::ParseTopLevelAPIwithOptimizeWin10(EventRecordCallstack* ev)//real use in win10 OS byWJ
{
	return;
	std::string callstack_;
	std::vector<std::string>& api_name_ = ev->topNAPI;
	DWORD pid = ev->process_id_;
	if (pid != 10876) { return; }
	//cout << pid << endl;
	//if (pid != 10384) { return; }
	/*
	if (Setting::GetInstance().cs_process_id()) {
		if (pid != Setting::GetInstance().cs_process_id()) {
			return;
		}
	}
	else {
		return;
	}
	*/

	int N = 5;
	//cout << "解析" << pid << endl;
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	//cout << modelTree->Size() << endl;
	int  iter = 0;
	int length = ev->vector_size;
	if (length == 0) {return;}
	int n = length - 1 > N - 1 ? N - 1 : length - 1;
	//cout << "解析进程: " << pid << " len="<<n<<endl;

	const auto& address_stack = ev->entry_address_vector_;
	String& ev_callstack = ev->callstack_;//blank or ox address

	if (iter == length) return;

	unsigned long long exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	unsigned long long exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;
	unsigned long long exe_address_base = ObtainEntryAddress::exe_node_map[pid].ImageEnd;

	for (; iter != length; iter++) {
		unsigned long long temp_iter = address_stack[iter];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_) {
			break;
		}
	}//for end
	//cout << iter << "===" << ev->kernel_start << endl;
	if (ev_callstack.empty() && length) {
		//while ignore && address_stack[iter] < 0xfffff00000000000
		while (--iter, iter >= 0 && n >= 0 && address_stack[iter] < 0xfffff00000000000) {
			unsigned long long temp_iter = address_stack[iter];			
			callstack_ = ConvertAddress2APIName(ev,temp_iter);
			//if (callstack_ != "NOAPI" && callstack_ != "NOMODULE" && callstack_ != ":NOAPI" && callstack_ != "NOMODULE-SYSTEMMODULE")
			//if(true)
			if(strstr(callstack_.c_str(), "NOOAPI") == nullptr && strstr(callstack_.c_str(), "NOMODULE") == nullptr && strstr(callstack_.c_str(), "NOAPI") == nullptr)
			{
				//cout << callstack_ << ":"<< modelTree->search(temp_iter)->key_value.FileName <<endl;
				ev_callstack.append(modelTree->search(temp_iter)->key_value.FileName +":" + callstack_+ "->");
				//n--;
			}			
			//api_name_.push_back(callstack_);
		}
	}
	//cout<<"RealCallStack: " <<ev_callstack<<endl;
	//cout << api_name_.size() << endl;
	//ev_callstack = callstack_;
	//cout<<"-----------------------end----------------------"<<endl;

}



void EventRecordCallstack::ParseTopLevelAPIwithOptimizeWS2012R2(EventRecordCallstack* ev)
{
	DWORD pid = ev->process_id_;
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::exe_node_map.find(pid) == ObtainEntryAddress::exe_node_map.end())
	{
		ev->useless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;
	bool flag = false;
	String& ev_callstack = ev->callstack_;
	const auto& address_stack = ev->entry_address_vector_;

	int_32 iter = ev->kernel_start + 1;
	int_32 vector_size = ev->vector_size;
	for (; iter < vector_size; iter++)
	{
		if (flag)   // may be can add cache later for optimize
		{
			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}

			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (search_module->key_value.rva_tree != NULL)
			{
				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				// can not get function name
				if (!search_function)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;
					continue;
				}
				else
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}
			else
			{
				return;
			}
		}
		else
		{
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call
			if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				continue;
			}
			// save address of system call we do not to parse 
			else if (process_address_useless_cache[pid].find(address_stack[iter]) != process_address_useless_cache[pid].end())
			{
				// not one we need
				ev->useless = true;
				return;
			}
			// save address of system call we need 
			else if (process_API_address_cache[pid].find(address_stack[iter]) != process_API_address_cache[pid].end())
			{  //address of API we need
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];
				continue;
			}
			else if (APIaddress_keepon_cache[pid].find(address_stack[iter]) != APIaddress_keepon_cache[pid].end())
			{
				ParseTopLevelAPIwithRunqinTrickWS2012R2(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);
			if (search_module)
			{
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					continue;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)				
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win10.find(search_function->key_value.FileName) != api_ntdll_need_set_win10.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later；
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design

							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}

								if (process_address_cache.find(address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										//std::cout << search_next_module->key_value.FileName << std::endl;
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}

										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
                                            // remove by zxw on 20200623 do not add "zw" in cache
											//process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win10.find(search_function->key_value.FileName) != api_keepon_set_win10.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrickWS2012R2(ev, iter + 1);
							}
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->useless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)			
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						if (search_function->key_value.FileName == "GetClassNameW")
						{
							ULONG64 offset = address_stack[iter] - search_module->key_value.ImageBase - search_function->key_value.ImageBase;
							if (offset >= 0x6c && offset <= 0x83)
							{
								ev_callstack = "GetKeyState";
								return;
							}
						}

						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->useless = true;
						return;
					}
				}
				else
				{
					ev->useless = true;
					return;
				}
			}
			else
			{
				ev->useless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->useless = true;
	}
}

void EventRecordCallstack::ParseTopLevelAPIwithRunqinTrick(EventRecordCallstack* ev, int start_index /*= 0*/)
{
	int iter = start_index;
	int length = ev->vector_size;
	if (iter == length) return;

	DWORD pid = ev->process_id_;
	if (ObtainEntryAddress::exe_node_map.find(pid) == ObtainEntryAddress::exe_node_map.end())
	{
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;

	String& ev_callstack = ev->callstack_;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	if (modelTree)
	{
		for (iter = start_index; iter < length; iter++)
		{
			ULONG64 temp_iter = address_stack[iter];
			//cout << exe_address_base_ << " " << exe_address_end_ << endl;//<
			if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
			{
				break;
			}
			if (temp_iter >= 0xfffff00000000000)
			{
				continue;
			}

			node* search_module = modelTree->search(temp_iter);
			if (!search_module)
			{
				break;
			}
			//cout << search_module->key_value.FileName << endl;
			if (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") != nullptr ||
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") != nullptr)
			{
				node* search_function = (*(search_module->key_value.rva_tree)).search(temp_iter - search_module->key_value.ImageBase);
				if (search_function)
				{
					ev_callstack = search_function->key_value.FileName;
					if (ev_callstack == "waveInOpen" || ev_callstack == "waveInAddBuffer")//audiorecord_signature_raw
					{
						return;
					}
				}
			}
		}
	}

	string temp_callstack_ = "";
	while (--iter, iter >= start_index)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < 0xfffff00000000000)
		{
			ev_callstack = std::move(ConvertAddress2APIName(ev, temp_iter));
			//cout << ev_callstack << " call" << endl;
			if (strstr(ev_callstack.c_str(), "NOOAPI") != nullptr ||
				strstr(ev_callstack.c_str(), "NOMODULE") != nullptr ||
				strstr(ev_callstack.c_str(), "NOAPI") != nullptr)			
			{
				continue;
			}
			else
			{
				break;
			}
		}
	}

	if (iter < 0) return;
}

void EventRecordCallstack::ParseTopLevelAPIwithRunqinTrickWS2012R2(EventRecordCallstack* ev, int_32 start_index /*= 0*/)
{
	int_32 iter = start_index;
	int_32 length = ev->vector_size;
	if (iter == length) return;

	DWORD pid = ev->process_id_;
	if (ObtainEntryAddress::exe_node_map.find(pid) == ObtainEntryAddress::exe_node_map.end())
	{
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;

	String& ev_callstack = ev->callstack_;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	for (iter = start_index; iter < length; iter++)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			break;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || strstr(search_module->key_value.FileName.c_str(), "mciwave.dll") != nullptr)
			{
				break;
			}
			if (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") != nullptr ||
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") != nullptr)			
			{
				node* search_function = (*(search_module->key_value.rva_tree)).search(temp_iter - search_module->key_value.ImageBase);
				if (search_function)
				{
					ev_callstack = search_function->key_value.FileName;
					if (ev_callstack == "waveInOpen" || ev_callstack == "waveInAddBuffer")
					{
						return;
					}
				}
			}
		}
	}

	string temp_callstack_ = "";
	while (--iter, iter >= start_index)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < 0xfffff00000000000)
		{
			ev_callstack = std::move(ConvertAddress2APIName(ev, temp_iter));
			if (strstr(ev_callstack.c_str(), "NOOAPI") != nullptr ||
				strstr(ev_callstack.c_str(), "NOMODULE") != nullptr ||
				strstr(ev_callstack.c_str(), "NOAPI") != nullptr)			
			{
				continue;
			}
			else
			{
				break;
			}
		}
	}

	if (iter < 0) return;
}

String EventRecordCallstack::ConvertAddress2APIName(EventRecordCallstack* ev, ULONG64 address)
{
	// convert address to api_name from here
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[ev->process_id_ % Max_Process_ID];
	if (!modelTree)
	{
		return EMPTY_STRING;
	}

	String ret;
	node* search_module = modelTree->search(address);
	if (search_module != NULL)
	{
		//string module_name_result = search_module->key_value.FileName;
		if (!Setting::GetInstance().local_detector_parse())//change to false by wj,reject the phf detection
		{
			ret = search_module->key_value.FileName; //cout << "ret" << ret << endl;
		}
		
		// the dll is not load and parse successfully
		if (search_module->key_value.rva_tree == NULL)
		{
			ret.append(":NOAPI");
			//temp.clear();
		}
		else
		{
			node * search_function = (*(search_module->key_value.rva_tree)).search((address)-search_module->key_value.ImageBase);
			if (search_function != NULL)
			{
				if (InitCollector::GetCollector()->GetMode() == ONLINE_PARSE_MODE)
				{
					//cout << "we get this" << endl; //all
					//ret.append(search_function->key_value.FileName);
					ret = search_function->key_value.FileName;

					//RUAN's computer,offset is GdipCreateSolidFill + 0x191db
					//To solve code suspend problem
					if (search_module->key_value.FileName.find("GdiPlus.dll") != String::npos)//查找失败则返回nops，否则返回第一个字符或者子串的位置（无符号整型类型）
					{
						//cout << "we get this" << endl; //all
						ULONG64 offset = address - search_module->key_value.ImageBase - search_function->key_value.ImageBase;
						if (offset > 0x10000 && search_function->key_value.ImageEnd == INT_MAX)
						{
							//cout << "we get this two" << endl; //not into
							ret = "GdipSaveImageToStream";
						}
					}
				}
				else
				{
					String api_name_result = search_function->key_value.FileName;
					ret.append(":").append(api_name_result); // all parse successfully
				}
				/* check api and return string shorter than 9 */
			}
			else
			{
				ret.append(":NOOAPI"); // can't match any rva
				//temp.clear();
			}
		}
	}
	// can't find a module match the address(moduleBase < address < moduleEnd)
	else
	{
		if (address >= 0xfffff00000000000)
		{
			ret.append("NOMODULE-SYSTEMMODULE");
		}
		else
		{
			ret.append("NOMODULE");
		}
	}

	return ret;
}

bool EventRecordCallstack::isKeeponParseAPI(EventRecordCallstack * ev, String apiname, int_32 index)
{
	int_32 length = ev->vector_size;
	if (index >= length) return false;

	DWORD pid = ev->process_id_;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::moduleAddressTree[pid % Max_Process_ID];
	ULONG64 exe_address_base_ = ObtainEntryAddress::exe_node_map[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::exe_node_map[pid].ImageEnd;
	if (strstr(apiname.c_str(), "ZwDeviceIoControlFile") != nullptr)
	{
		ULONG64 temp_iter = address_stack[index];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			return false;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || strstr(search_module->key_value.FileName.c_str(), "bcrypt.dll") == nullptr)
			{	// if next filename is not bcrypt.dll do not keep on parse
				return false;
			}
		}
	}
	else if (strstr(apiname.c_str(), "ZwWaitForSingleObject") != nullptr)
	{
		if (index + 3 >= length) return false;
		ULONG64 temp_iter = address_stack[index + 3];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			return false;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") == nullptr &&
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") == nullptr))
			{	// if next filename is not winmm.dll or winmmbase.dll do not keep on parse
				return false;
			}
		}
	}
	else
	{
		return true;
	}
	
	return true;
}

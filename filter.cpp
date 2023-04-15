#include "stdafx.h"
#include "filter.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <io.h>

#include "event_record_manager.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "setting.h"
#include "thread_task_manager.h"

#include <windows.h>
#include <winternl.h>

std::set<std::wstring> Filter::useless_API_list;
std::unordered_set<uint_64> Filter::event_process_white_list;
std::set<EventIdentifier> Filter::event_output_white_list;
std::set<DWORD> Filter::process_id_black_list;
std::set<DWORD> Filter::process_id_white_list;
std::set<std::string> Filter::api_name_white_list;
// add by zxw on 20200811
std::unordered_map<DWORD, std::unordered_set<DWORD>> Filter::parentid2childid_map_;
std::unordered_map<DWORD, std::unordered_set<DWORD>> Filter::pid2tid_map_;
std::unordered_set<DWORD> Filter::tid_pruner_black_list;
std::unordered_set<DWORD> Filter::pid_pruner_black_list;
std::unordered_set<DWORD> Filter::pid_pruner_white_list;

std::set<int> Filter::systemcall_list;
std::set<std::string> Filter::systemcall_name_list;
std::set<std::string> Filter::signature_systemcall_name_list;
std::set<EventIdentifier> Filter::event_list;
std::set<EventIdentifier> Filter::signature_event_list;
std::string Filter::signature_file_path = "C:\\Users\\APPshiel_DEV01\\Desktop\\multify\\Reconstruction_Collector\\12.22_back";

// add by zxw on 20191119 添加ransom目录白名单、检测进程黑名单
std::set<std::wstring> Filter::ransom_dir_white_list;
std::set<String> Filter::ransom_suffix_white_list;						// 添加ransom后缀白名单	
std::set<DWORD> Filter::ransom_process_id_black_list;
//std::unordered_map<DWORD, DWORD> Filter::processid_parentid_map;		// 父子进程map表
std::set<SCertificateResult> Filter::certificate_white_list;	// 添加企业证书白名单	

// add by zxw on 20191122 添加explorer pid特殊处理
DWORD Filter::_explorer_pid;

void Filter::InsetUselessAPIList(std::wstring temp) 
{ 
	useless_API_list.insert(temp); 
}

bool Filter::QueryUselessAPIList(std::wstring temp) 
{ 
	return useless_API_list.count(temp); 
}

void Filter::Init()
{
	insert_process_id_black_list(-1);
	insert_process_id_black_list(GetCurrentProcessId());

	DEFINE_DLL_FUNCTION(NtQueryInformationProcess, LONG(WINAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG), "ntdll.dll");
	if (NtQueryInformationProcess)
	{
		HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
		if (h_process)
		{
			PROCESS_BASIC_INFORMATION pbi;
			NTSTATUS ret = NtQueryInformationProcess(h_process, SystemBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
			if (NT_SUCCESS(ret))
			{
				LoggerRecord::WriteLog(L"Init process_id = " + std::to_wstring((ULONG_PTR)pbi.Reserved3), LogLevel::WARN);
				//insert_process_id_black_list((ULONG_PTR)pbi.Reserved3);
                // collector start by client scheduler
                _privilege_pid = (ULONG_PTR)pbi.Reserved3;
			}

			CloseHandle(h_process);
		}
	}

	//just consume event in white list
	insert_event_process_white_list(ETWStackWalk, 32);

	for (auto iter : EventRecordManager::GetInstance().event_strucp_map)
	{
		const EventIdentifier& event_identifier = iter.first;
		if (event_identifier.provider_id() == ETWPerfInfo &&
			InitCollector::GetCollector()->GetDetectorMode() == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK)
		{
			continue;
		}

		insert_event_process_white_list(event_identifier.provider_id(), event_identifier.opcode());
	}

#if defined(USE_LOCAL_TRUST_LIST)

	std::fstream super_white_list_file("super_white_list.ini", ios::in);
	String read_str;
	while (getline(super_white_list_file, read_str))
	{
		_super_white_list_config.insert(StringUtil::ToLowerCase(read_str));
		LoggerRecord::WriteLog(L"Filter::Init: add super white list config, name = " + ToolFunctions::StringToWString(read_str), LogLevel::WARN);
	}

    STRING_VECTOR suffix_white_list;
    suffix_white_list.push_back("txt");
    suffix_white_list.push_back("doc");
    suffix_white_list.push_back("docx");
    suffix_white_list.push_back("ppt");
    suffix_white_list.push_back("pptx");
    suffix_white_list.push_back("xls");
    suffix_white_list.push_back("xlsx");
    suffix_white_list.push_back("wps");
    suffix_white_list.push_back("pdf");
    suffix_white_list.push_back("zip");
    AddRansomSuffixWhiteList(suffix_white_list, 0);
    LoggerRecord::WriteLog(L"AddRansomSuffixWhiteList size = " + std::to_wstring(suffix_white_list.size()), LogLevel::INFO);

#endif

	_current_gear = (CollectorGear)Setting::GetInstance().collector_init_gear();
    // add by zxw on 20191216
    UpdateRansomDetector();
	// add by zxw on 20191120
	AddRansomWhiteDir();
    // add by zxw on 20200724
    char cur_dir[MAX_PATH] = { 0 };
    GetCurrentDirectoryA(MAX_PATH, cur_dir);
    _autorunsc64_path = cur_dir + std::string("\\") + AUTORUNSC64_PROCESS;
    _autorunsc64_path.erase(0, 2);  // erase drive
    LoggerRecord::WriteLog(L"Filter::Init _autorunsc64_path"+ToolFunctions::StringToWString(_autorunsc64_path), INFO);
}

void Filter::LogCacheSize() 
{
    if (Setting::GetInstance().enable_pruner_output())  
    {
        LoggerRecord::WriteLog(L"Filter::tid_pruner_black_list: " + std::to_wstring(tid_pruner_black_list.size()), INFO);
        LoggerRecord::WriteLog(L"Filter::pid_pruner_black_list: " + std::to_wstring(pid_pruner_black_list.size()), INFO);
        LoggerRecord::WriteLog(L"Filter::pid_pruner_white_list: " + std::to_wstring(pid_pruner_white_list.size()), INFO);

        LoggerRecord::WriteLog(L"Filter::parentid2childid_map_: " + std::to_wstring(parentid2childid_map_.size()), INFO);
        LoggerRecord::WriteLog(L"Filter::pid2tid_map_: " + std::to_wstring(pid2tid_map_.size()), INFO);
    }
}

bool Filter::FilterBeforeRecInstance(uint_32 provider_id, int_32 opcode, DWORD process_id)
{
	if (event_process_white_list.find((uint_64)provider_id * 100 + opcode) == event_process_white_list.end())	return false;
    // add by zxw on 20200509
    if (provider_id != ETWProcess)
    {
        if (IsSuperWhiteListProcess(process_id))	return false;
    }	
	if (_FilterByGear(process_id, provider_id))	return false;

	// Filter Win10 special event;
	switch (provider_id)
	{
	case ETWFileIo:
		if (opcode == EM_FileioEventOPC::FileIoRenamePath)	return false;
        // add by zxw 20191213 filter FileIoCleanup & FileioDirEnumerationEvent if not ransom
        if (!_current_ransom_detector)
        {
            if (opcode == EM_FileioEventOPC::FileIoCleanup || opcode == EM_FileioEventOPC::FileioDirEnumerationEvent)
            {
                return false;
            }
        }
        //
		break;

	case ETWProcess:
		if (opcode == EM_ProcessEventOPC::ProcessDCEnd)	return false;
		break;
    case ETWRegistry:
        if (opcode == EM_RegistryEventOPC::RegistryQuery || 
            opcode == EM_RegistryEventOPC::RegistrySetInformation||
            opcode == EM_RegistryEventOPC::RegistryQueryValue)
        {
            // add by zxw on 20200519
            if (!Setting::GetInstance().enable_debug_output())
                return false;
        }
        if (process_id == _explorer_pid || process_id == 4)
        {          
            return false;
        }
        break;
    // add by zxw on 20200811 if enable_pruner_output= true prun all TcpIpRecvIPV4
    case ETWTcpIp:
        if (Setting::GetInstance().enable_pruner_output() && opcode == EM_TcpIpEventOPC::TcpIpRecvIPV4)	return false;
        break;
        
	default:
		break;
	}

	return true;
}

bool Filter::FilterAfterRecInstance(EventRecord* rec)
{
    // add by zxw on 20200509
    auto provider_id = rec->get_event_identifier_().provider_id();
    if (provider_id != ETWProcess)
    {
        if (IsSuperWhiteListProcess(rec->get_process_id_()))	return false;
        // add by zxw on 20200820
        if (Setting::GetInstance().enable_pruner_output() && provider_id != ETWStackWalk) {
            if (pid_pruner_white_list.find(rec->get_process_id_()) != pid_pruner_white_list.end()) {
                if (tid_pruner_black_list.find(rec->get_thread_id_()) == tid_pruner_black_list.end())
                    return false;
            }
        }
    }
	
	if (_FilterByGear(rec->get_process_id_(), provider_id))	return false;

	return true;
}

bool Filter::IsSuperWhiteListProcess(DWORD pid)
{
	if (pid == ULONG_MAX)
	{
		return false;
	}
    // add by zxw on 20200724
    if (_autorunsc64_pid != 0 && pid == _autorunsc64_pid)
    {
        return true;
    }
    
	while (_super_white_list_config_remove_buffer.size_approx() > 0)
	{
		String file_name;
		if (_super_white_list_config_remove_buffer.try_dequeue(file_name))
		{
			_process_filter_data_lock.ReadLock();
			_OnRemoveSuperWhiteList(file_name);
			_process_filter_data_lock.ReadUnlock();
		}
	}

	while (_super_white_list_config_add_buffer.size_approx() > 0)
	{
		String file_name;
		if (_super_white_list_config_add_buffer.try_dequeue(file_name))
		{
			_process_filter_data_lock.ReadLock();
			_OnAddSuperWhiteList(file_name);
			_process_filter_data_lock.ReadUnlock();
		}
	}
	
	while (_super_white_list_wait_buffer.size_approx() > 0)
	{
		ProcessFilterData data;
		if (_super_white_list_wait_buffer.try_dequeue(data))
		{
			if (data.file_name != EMPTY_STRING && 
				_super_white_list_config.find(StringUtil::ToLowerCase(data.file_name)) != _super_white_list_config.end())
			{
				_super_white_list.insert(data.process_id);
				LoggerRecord::WriteLog(L"Filter::OnCertificateResult: add super white list process, pid = " + std::to_wstring(data.process_id), LogLevel::WARN);
			}
		}
	}
    // add by zxw on 20210511
    if (IsCertificateWhiteListProcess(pid))
    {
        return true;
    }
    //
	return _super_white_list.find(pid) != _super_white_list.end();
}

bool Filter::IsSuperWhiteListProcessEx(DWORD pid) {
    if (pid == ULONG_MAX) {
        return false;
    }
    // add by zxw on 20200724
    if (_autorunsc64_pid != 0 && pid == _autorunsc64_pid) {
        return true;
    }
    return _super_white_list.find(pid) != _super_white_list.end();
}

bool Filter::IsPrivilegeProcess(DWORD pid)
{
	if (pid != 0 && _privilege_pid == pid)
	{
		return true;
	}
	return false;	
}

bool Filter::SetLoclaIPbyEventRecord(EventRecordTcpip* rec)
{
	if (rec != nullptr)
	{
		auto event_identifier = rec->get_event_identifier_();
		if ((rec->get_process_id_() == _privilege_pid) && (event_identifier.provider_id() == ETWTcpIp))
		{
			EM_TcpIpEventOPC opcode = (EM_TcpIpEventOPC)event_identifier.opcode();
			if (opcode == EM_TcpIpEventOPC::TcpIpSendIPV4)
			{
				uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
				uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
				uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
				uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);
				auto ip_port = ToolFunctions::Net2Str(d_ip) + ":" + to_string(ntohs(d_port));
				if (Setting::GetInstance().kafka_address() == ip_port)
				{
					auto sip = ToolFunctions::Net2Str(s_ip);
					if (_local_ip != sip)
					{
						LoggerRecord::WriteLog(L"Update localIP old IP= " + 
							ToolFunctions::StringToWString(_local_ip) +
							L"new IP = " +
							ToolFunctions::StringToWString(sip), LogLevel::INFO);

						_local_ip = sip;
						return true;
					}							
				}				
			}
		}
	}
	return false;
}

std::string Filter::GetLocalIP()
{
	return _local_ip;
}

EventRecord* Filter::APIFilter(EventRecord* record) 
{
	if (record->get_event_identifier_().provider_id() == ETWStackWalk
		&& !api_name_white_list.count(record->get_callstack_())) {
		delete record;
		return NULL;
	}
	return record;
}

bool Filter::FilterAfterParseRecord(EventRecord* record) 
{
    // add by zxw on 20200511
    auto provider_id = record->get_event_identifier_().provider_id();
    if (provider_id != ETWProcess)
    {
        auto pid = record->get_process_id_();
        auto tid = record->get_thread_id_();
        if (process_id_white_list.size() != 0 && process_id_white_list.find(pid) == process_id_white_list.end())
        {
            return false;
        }

        if (process_id_black_list.count(pid))
        {
            return false;
        }

        // add by zxw on 20200811
        if (Setting::GetInstance().enable_pruner_output() && provider_id != ETWStackWalk) {
            if (pid_pruner_white_list.find(pid) != pid_pruner_white_list.end())
            {
                if (tid_pruner_black_list.find(tid) == tid_pruner_black_list.end())
                    return false;
            }
        }
    }
	
	// mod by zxw on 20191128 ransom模块需要先不处理，output模块再裁剪
    if (!Filter::GetInstance().GetRansomDetector())
	{
        if (record->isUseless())
        {
            return false;
        }
    }
    else
    {
        // 非FileIo事件过滤
        if (record->get_event_identifier_().provider_id() != ETWFileIo)
        {
			//cout << record->get_event_identifier_().provider_id() << endl;
            if (record->isUseless())
            {
                return false;
            }
        }
    }
	
	return true;
}

void Wchar_tToString(std::string& szDst, wchar_t *wchar)
{
	wchar_t * wText = wchar;
	char* psText;
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);
	psText = new char[dwNum];
	WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);
	szDst = psText;
	delete[]psText;
}

void Filter::set_signature_file_path(std::string path)
{
	signature_file_path = path;
}

void Filter::OnExeImageLoad(DWORD pid, const String& file_path)
{
	LoggerRecord::WriteLog(L"Filter::OnExeImageLoad: pid = " + std::to_wstring(pid) + L", file_path = " + ToolFunctions::StringToWString(file_path), INFO);

	ProcessFilterData* data = new ProcessFilterData();
	data->process_id = pid;
	data->file_path = file_path;
	STRING_VECTOR file_path_parts;
	StringUtil::split(file_path, '\\', file_path_parts);
	data->file_name = file_path_parts.empty() ? EMPTY_STRING : file_path_parts.back();
	data->certificate_result = EM_CertificateResult::CERTIFICATE_RESULT__UNDETERMINED;
	_process_filter_data_lock.WriteLock();
	_process_filter_data_map.insert(std::make_pair(pid, data));
	_process_filter_data_lock.WriteUnlock();
	// ADD BY ZXW 20191029 检测特权进程
	if (_privilege_pid == 0 && StringUtil::ToLowerCase(data->file_name) == PRIVILEGE_PROCESS)
	{
		_privilege_pid = pid;
		LoggerRecord::WriteLog(L"update _privilege_pid " + std::to_wstring(_privilege_pid), INFO);
	}
	// ADD BY ZXW ON 20191122 EXPLORER_PROCESS
	if (StringUtil::ToLowerCase(data->file_name) == EXPLORER_PROCESS)
	{
		_explorer_pid = pid;
		LoggerRecord::WriteLog(L"update _explorer_pid " + std::to_wstring(_explorer_pid), INFO);
	}
    // ADD BY ZXW 20200724 检测特权进程
    if (file_path == _autorunsc64_path) {
        _autorunsc64_pid = pid;
        LoggerRecord::WriteLog(L"update _autorunsc64_pid " + std::to_wstring(_autorunsc64_pid), INFO);
    }
    
	//
}

void Filter::OnExeCertificateResult(DWORD pid, EM_CertificateResult result)
{
	_process_filter_data_lock.WriteLock();

	auto iter_f = _process_filter_data_map.find(pid);
	if (iter_f != _process_filter_data_map.end())
	{
		ProcessFilterData* data = iter_f->second;
		if (data->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__UNDETERMINED)
		{
			data->certificate_result = result;

			if (result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL && data != nullptr)
			{
				_super_white_list_wait_buffer.enqueue(*data);
			}
		}        
	}
    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output())
    {
        if (result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL)             
        {
            // if pid is not exit and pid is not in blacklist add white list
            if (EventRecord::query_process_id2process_name_map_(pid) && pid_pruner_black_list.find(pid) == pid_pruner_black_list.end())
                insert_pid_pruner_white_list(pid);            
        }            
        else {
            if (EventRecord::query_process_id2process_name_map_(pid))
            {
                // 移除白名单
                erase_pid_pruner_white_list(pid);
                // 添加黑名单
                insert_pid_pruner_black_list(pid);
                // add child pid in black list
                auto iter = parentid2childid_map_.find(pid);
                if (iter != parentid2childid_map_.end()) {
                    for each (auto var in iter->second) {
                        if (EventRecord::query_process_id2process_name_map_(var))   
                        {
                            // 移除白名单
                            erase_pid_pruner_white_list(var);
                            // 添加黑名单
                            insert_pid_pruner_black_list(var);
                        }
                      
                    }
                }
                // add tid in black list
                auto iter1 = pid2tid_map_.find(pid);
                if (iter1 != pid2tid_map_.end()) {
                    for each (auto var in iter1->second) {
                        insert_tid_pruner_black_list(var);
                    }
                }
            }
               
        }
        pid2tid_map_.erase(pid);
        parentid2childid_map_.erase(pid);
    }
    //
	_process_filter_data_lock.WriteUnlock();
}

void Filter::OnProcessEnd(DWORD pid)
{
	_super_white_list.erase(pid);

	_process_filter_data_lock.WriteLock();
	auto iter_f = _process_filter_data_map.find(pid);
	if (iter_f != _process_filter_data_map.end())
	{
		SAFE_DELETE(iter_f->second);
		_process_filter_data_map.erase(iter_f);
	}

    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output()) {
        erase_pid_pruner_white_list(pid);
        erase_pid_pruner_black_list(pid);
        pid2tid_map_.erase(pid);
        parentid2childid_map_.erase(pid);
        for (auto iter = parentid2childid_map_.begin(); iter != parentid2childid_map_.end(); iter++)
        {          
            auto pidset = iter->second;
            if (pidset.find(pid) != pidset.end())
            {
                pidset.erase(pid);
            }            
        }
    }    

	_process_filter_data_lock.WriteUnlock();
}

void Filter::OnProcessStart(EventRecordProcess * rec) 
{
    if (Setting::GetInstance().enable_pruner_output()) {
        _process_filter_data_lock.WriteLock();

        auto pid = rec->GetDataParameter(parameter_index_enum::ProcessId);
        auto parentid = rec->GetDataParameter(parameter_index_enum::ParentId);
        if (pid_pruner_black_list.find(parentid) == pid_pruner_black_list.end())   
        {
            if (pid_pruner_white_list.find(parentid) == pid_pruner_white_list.end())
                parentid2childid_map_[parentid].insert(pid);
        }            
        else 
        {
            // 移除白名单
            erase_pid_pruner_white_list(pid);
            // 添加黑名单
            insert_pid_pruner_black_list(pid);
        }

        _process_filter_data_lock.WriteUnlock();
    }
}

void Filter::OnThreadEnd(DWORD tid, DWORD pid)
{
    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output()) 
    {
        _process_filter_data_lock.WriteLock();

        erase_tid_pruner_black_list(tid);

        auto iter = pid2tid_map_.find(pid);
        if (iter != pid2tid_map_.end())
            iter->second.erase(tid);

        _process_filter_data_lock.WriteUnlock();
    }
}

void Filter::OnThreadStart(EventRecordThread * rec) 
{
    auto ppid = rec->get_process_id_();
    auto ptid = rec->get_thread_id_();
    auto tid = rec->GetDataParameter(parameter_index_enum::TThreadId);
    auto pid = rec->GetDataParameter(parameter_index_enum::ProcessId);
    if (Setting::GetInstance().enable_pruner_output()) 
    {      
        _process_filter_data_lock.WriteLock(); 

        if (tid_pruner_black_list.size() > 0 && tid_pruner_black_list.find(ptid) != tid_pruner_black_list.end())       
        {
//             LoggerRecord::WriteLog(L"insert_tid_pruner_black_list ppid " + std::to_wstring(ppid)+
//                 L" ptid " + std::to_wstring(ptid)+
//                 L" tid " + std::to_wstring(tid)+
//                 L" pid " + std::to_wstring(pid), DEBUG);
            insert_tid_pruner_black_list(tid);
            _process_filter_data_lock.WriteUnlock();
            return;
        }

        if (pid_pruner_black_list.find(ppid) != pid_pruner_black_list.end())
        {
//             LoggerRecord::WriteLog(L"1111 insert_tid_pruner_black_list ppid " + std::to_wstring(ppid) +
//                 L" ptid " + std::to_wstring(ptid) +
//                 L" tid " + std::to_wstring(tid) +
//                 L" pid " + std::to_wstring(pid), DEBUG);
            insert_tid_pruner_black_list(tid);
            _process_filter_data_lock.WriteUnlock();
            return;
        }
        
        if (pid_pruner_white_list.find(ppid) == pid_pruner_white_list.end())
        {
            pid2tid_map_[ppid].insert(tid);
        }        

        _process_filter_data_lock.WriteUnlock();

//             
//         if (ppid != 4 && ppid != pid)
//         {
//             LoggerRecord::WriteLog(L"1111 insert_tid_pruner_black_list ppid " + std::to_wstring(ppid) +
//                 L" ptid " + std::to_wstring(ptid) +
//                 L" tid " + std::to_wstring(tid) +
//                 L" pid " + std::to_wstring(pid), INFO);
//             insert_tid_pruner_black_list(tid);
//         }
    }
}

void Filter::OnPhfDetectorResult(DWORD pid)
{
    _process_filter_data_lock.WriteLock();

    if (Setting::GetInstance().enable_pruner_output() && EventRecord::query_process_id2process_name_map_(pid))
    {       
        // 移除白名单
        erase_pid_pruner_white_list(pid);
        // 添加黑名单
        insert_pid_pruner_black_list(pid);
    }

    _process_filter_data_lock.WriteUnlock();
}

bool Filter::IsProcessCertificate(DWORD pid) const
{
	_process_filter_data_lock.ReadLock();

	auto iter_f = _process_filter_data_map.find(pid);
	bool result = iter_f != _process_filter_data_map.end() && iter_f->second->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL;

	_process_filter_data_lock.ReadUnlock();

	return result;
}

void Filter::InitSuperWhiteList(const STRING_VECTOR& list_init)
{
	for (const String& file_name : list_init)
	{
		_super_white_list_config_add_buffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::AddSuperWhiteList(const STRING_VECTOR& list_add)
{
	for (const String& file_name : list_add)
	{
		_super_white_list_config_add_buffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::RemoveSuperWhiteList(const STRING_VECTOR& list_remove)
{
	for (const String& file_name : list_remove)
	{
		_super_white_list_config_remove_buffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::ChangeSuperWhiteList(const String& file_name_s, const String& file_name_d)
{
	_super_white_list_config_add_buffer.enqueue(StringUtil::ToLowerCase(file_name_d));
	_super_white_list_config_remove_buffer.enqueue(StringUtil::ToLowerCase(file_name_s));
}

void Filter::AddRansomSuffixWhiteList(const STRING_VECTOR & list_add, int is_terminate)
{
	moodycamel::ConcurrentQueue<String>().swap(_ransom_suffix_white_list_add_buffer);
	for (const String& file_name : list_add)
	{
		_ransom_suffix_white_list_add_buffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
    // add by zxw on 20210513
    _ranssom_is_terminate = is_terminate;
}

void Filter::UpdateRansomDetector()
{
    // add on 20191216 m_collector_init_gear > CollectorGear::COLLECTOR_GEAR__2 or m_local_detector_mode != "callstack" close m_enable_ransom_detector
    if (Setting::GetInstance().local_detector_mode() != "callstack")
    {
        _current_ransom_detector = false;
        return;
    }
    /*
    // add on 20200102 if not safe mode close ransom
    if (Setting::GetInstance().enable_gear_adjustment() || Setting::GetInstance().enable_hardware_adjustment())
    {
        _current_ransom_detector = false;
        return;
    }
    //
    */
    if (_current_gear > CollectorGear::COLLECTOR_GEAR__2)
    {
        _current_ransom_detector = false;
    }
    else
    {
        _current_ransom_detector = Setting::GetInstance().enable_ransom_detector();    
    }       
}

void Filter::RuleMatchSwitch(std::string rule_match) 
{
    if (rule_match == "0") {
        ThreadTaskManager::GetInstance().StopTask(EM_ThreadTaskMode::RULE_MATCHER_TASK_MODE);
    }
    else {
        ThreadTaskManager::GetInstance().AddTask(EM_ThreadTaskMode::RULE_MATCHER_TASK_MODE);
    }
}

void Filter::AddCertificateWhiteListBuffer(const std::vector<SCertificateResult>& list_add)
{
    moodycamel::ConcurrentQueue<SCertificateResult>().swap(_certificate_white_list_add_buffer);
    for (auto certificate_data : list_add) {
        _certificate_white_list_add_buffer.enqueue(certificate_data);
    }
}

bool Filter::IsInCertificateWhiteList(std::string thumbPrint, std::string subjectname)
{
    // 添加
    if (_certificate_white_list_add_buffer.size_approx() > 0) {
        std::set<SCertificateResult>().swap(certificate_white_list);
        while (_certificate_white_list_add_buffer.size_approx() > 0) {
            SCertificateResult scert;
            if (_certificate_white_list_add_buffer.try_dequeue(scert)) {
                certificate_white_list.insert(scert);
            }
        }
    }
    // 查询
    auto it = certificate_white_list.begin();
    while (it != certificate_white_list.end())
    {
        if (it->thumbPrint.size() > 0)
        {
            if (it->thumbPrint == thumbPrint && it->subjectname == subjectname) 
            {
                return true;
            }
        }
        else {
            if (it->subjectname == subjectname) 
            {
                return true;
            }
        } 

        it++;
    }
    return false;
}

void Filter::AddSurpCertificateWhiteListBuffer(DWORD pid) 
{
    if (pid > 0 && pid != ULONG_MAX)
        _super_certificate_white_list_add_buffer.enqueue(pid);
}

bool Filter::IsCertificateWhiteListProcess(DWORD pid) 
{
    if (pid == ULONG_MAX) {
        return false;
    }
   
    if (_autorunsc64_pid != 0 && pid == _autorunsc64_pid) {
        return true;
    }
    
    while (_super_certificate_white_list_add_buffer.size_approx() > 0) 
    {
        DWORD process_id;
        if (_super_certificate_white_list_add_buffer.try_dequeue(process_id)) {
            if (EventRecord::query_process_id2process_name_map_(process_id))
            {
                _super_certificate_white_list.insert(process_id);
                LoggerRecord::WriteLog(L"Filter add certificate super white list process, pid = " + std::to_wstring(process_id), LogLevel::DEBUG);
            }
        }
    }

    return _super_certificate_white_list.find(pid) != _super_certificate_white_list.end();
}

String Filter::GetProcessFileName(DWORD pid) const
{
	String file_name = EMPTY_STRING;
	
	_process_filter_data_lock.ReadLock();
	auto iter = _process_filter_data_map.find(pid);
	if (iter != _process_filter_data_map.end())
	{
		file_name = iter->second->file_name;
	}
	_process_filter_data_lock.ReadUnlock();

	return file_name;
}

void Filter::SetCollectorGear(CollectorGear gear)
{
	if (!Setting::GetInstance().enable_gear_adjustment())	return;
    // add by zxw on 20200409 honey pot close change gear
    if (Setting::GetInstance().enable_honey_pot())	return;

	_current_gear = gear;
	if (_current_gear >= CollectorGear::COLLECTOR_GEAR__3)
	{
		ThreadTaskManager::GetInstance().StopTask(EM_ThreadTaskMode::GET_VISIBLE_WINDOW_TASK_MODE);
	}
	else
	{
		ThreadTaskManager::GetInstance().AddTask(EM_ThreadTaskMode::GET_VISIBLE_WINDOW_TASK_MODE);
	}
    // add by zxw on 20191216
    UpdateRansomDetector();
}

CollectorGear Filter::GetCollectorGear()
{
	return _current_gear;
}

void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname)
{

	intptr_t   hFile = 0;
	struct _finddata_t fileinfo;
	std::string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					getFiles(p.assign(path).append("\\").append(fileinfo.name), files, ownname); 
			}
			else
			{
				files.push_back(p.assign(path).append("\\").append(fileinfo.name));
				ownname.push_back(fileinfo.name);
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

//Filter::Filter(){
//	provider_modulo_mapping_hash[0xcd] = 0;//ALPC
//	provider_modulo_mapping_hash[0xd1] = 1;//Thread
//	provider_modulo_mapping_hash[0x39] = 2;//FileIO
//	provider_modulo_mapping_hash[0xd4] = 3;//DiskIO
//	provider_modulo_mapping_hash[0xb4] = 4;//PerfInfo
//	provider_modulo_mapping_hash[0xd3] = 5;//PageFault
//	provider_modulo_mapping_hash[0xc0] = 6;//Tcp
//	provider_modulo_mapping_hash[0xc5] = 7;//Udp
//	provider_modulo_mapping_hash[0xd0] = 8;//Process
//	provider_modulo_mapping_hash[0x2e] = 9;//Registry
//	provider_modulo_mapping_hash[0x92] = 10;//Splitlo
//	for (int i = 0; i != KProviderSize; i++){
//		for (int j = 0; j != KOpcodeSize; j++){
//			event_filter_list[i][j] = 0;
//		}
//	}
//}

bool Filter::isSystemCallNeeded(int Address)
{
	if (systemcall_list.count(Address)) return true;
	return false;
}

bool Filter::isEventNeeded(EventIdentifier ID)
{
	if (event_list.count(ID)) return true;
	return false;
}

bool Filter::AddSystemCall(int Address)
{
	systemcall_list.insert(Address);
	return 1;
}

bool Filter::AddEvent(EventIdentifier ID)
{
	event_list.insert(ID);
	return 1;
}

bool Filter::DelSystemCall(int Address)
{
	std::set<int>::iterator ix = systemcall_list.find(Address);
	if (ix == systemcall_list.end()) return 0;
	systemcall_list.erase(ix);
	return 1;
}

bool Filter::DelEvent(EventIdentifier ID)
{
	std::set<EventIdentifier>::iterator ix = event_list.find(ID);
	if (ix == event_list.end()) return 0;
	event_list.erase(ix);
	return 1;
}

String Filter::GetEventName(EventIdentifier ID) {
    std::set<EventIdentifier>::iterator ix = event_list.find(ID);
    if (ix == event_list.end()) return "";
    return ix->event_name();
}

size_t Filter::QuerySystemCallListSize()
{
	return systemcall_list.size();
}

size_t Filter::QueryEventListSize()
{
	return event_list.size();
}

//void Filter::CreatEnableFlag()
//{
//
//}

//int Filter::get_enableflag()
//{
//	if (!enableflag) CreatEnableFlag();
//	return enableflag;
//}

void inline Filter::InsertEventIdentifier(EventIdentifier event_indentifier)
{
	//if event_identifier not in the set && in the format,insert it
	std::set<EventIdentifier>::iterator ix = event_list.find(event_indentifier);
	if (ix!=event_list.end()&&signature_event_list.find(event_indentifier) == signature_event_list.end()) signature_event_list.insert(*ix);
}

bool Filter::_FilterByGear(DWORD process_id, uint_32 provider_id) const
{
	if (_current_gear >= CollectorGear::COLLECTOR_GEAR__2)
	{
		if ((provider_id == ETWStackWalk || provider_id == ETWPerfInfo) && (_current_gear >= CollectorGear::COLLECTOR_GEAR__3 || Filter::GetInstance().IsProcessCertificate(process_id)))
		{
			return true;
		}

		if (_current_gear >= COLLECTOR_GEAR__4 && provider_id == ETWFileIo)
		{
			return true;
		}

		if (_current_gear == COLLECTOR_GEAR__5 && provider_id != ETWThread && provider_id != ETWProcess)
		{
			return true;
		}
	}

	return false;
}

void Filter::_OnAddSuperWhiteList(const String& file_name)
{
	_super_white_list_config.insert(file_name);
	for (auto pair_t : _process_filter_data_map)
	{
		ProcessFilterData* data = pair_t.second;
		if (data->file_path.find(file_name) != String::npos &&
			data->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL)
		{
			_super_white_list.insert(data->process_id);
			LoggerRecord::WriteLog(L"Filter::_OnAddSuperWhiteList: process_id = " + std::to_wstring(data->process_id), LogLevel::WARN);
		}
	}
}

void Filter::_OnRemoveSuperWhiteList(const String& file_name)
{
	_super_white_list_config.erase(file_name);
	for (auto pair_t : _process_filter_data_map)
	{
		ProcessFilterData* data = pair_t.second;
		if (data->file_path.find(file_name) != String::npos)
		{
			_super_white_list.erase(data->process_id);
			LoggerRecord::WriteLog(L"Filter::_OnRemoveSuperWhiteList: process_id = " + std::to_wstring(data->process_id), LogLevel::WARN);
		}
	}
}

void Filter::AddRansomWhiteDir()
{
	TCHAR curdir[MAX_PATH]; 
	GetCurrentDirectory(MAX_PATH, curdir);
	// 添加当前目录作为白名单
	insert_ransom_dir_white_list(curdir);
	LoggerRecord::WriteLog(L"Filter::AddRansomWhiteDir: " + std::wstring(curdir), LogLevel::INFO);
	/*
	std::fstream fp;
	String read_str;
	fp.open("ransom_dir_white_list.ini", ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			insert_ransom_dir_white_list(ToolFunctions::StringToWString(read_str));
			LoggerRecord::WriteLog(L"Filter::AddRansomWhiteDir: " + ToolFunctions::StringToWString(read_str), LogLevel::INFO);
		}
		fp.close();
	}else
		LoggerRecord::WriteLog(L"Filter::AddRansomWhiteDir: open file failed,errcode = " + std::to_wstring(GetLastError()), LogLevel::WARN);
	*/
}

bool Filter::IsRansomBlackProcess(EventRecord* record)
{
    // cs
    //return true;
    if (!_current_ransom_detector)
    {
        return false;
    }

	if (_ransom_suffix_white_list_add_buffer.size_approx() > 0)
	{
		std::set<String>().swap(ransom_suffix_white_list);
		std::set<DWORD>().swap(ransom_process_id_black_list);
		while (_ransom_suffix_white_list_add_buffer.size_approx() > 0)
		{
			String suffix_name;
			if (_ransom_suffix_white_list_add_buffer.try_dequeue(suffix_name))
			{
				_ransom_suffix_data_lock.ReadLock();
				ransom_suffix_white_list.insert(suffix_name);
				_ransom_suffix_data_lock.ReadUnlock();
			}
		}
	}
	
	if (!record)
	{
		return false;
	}
	// 过滤需要的事件
	auto provider_id = record->get_event_identifier_().provider_id();
	auto opcode_id = record->get_event_identifier_().opcode();
	set< uint_32> opcode_output = { 1,2,3,64,67,68,71,70,72,65 };
	if (provider_id != ETWStackWalk && provider_id != ETWFileIo && provider_id != ETWProcess)
		return false;
	if (provider_id != ETWStackWalk && opcode_output.find(opcode_id) == opcode_output.end())
		return false;
	if (opcode_id == EM_ProcessEventOPC::ProcessEnd)
    {
        // 进程结束移除黑名单，可能后续子进程加入不了黑名单
        erase_ransom_process_id_black_list(record->GetDataParameter(parameter_index_enum::ProcessId));
        return true;	// 进程事件全发送至ransom
    }
	if (opcode_id == EM_ProcessEventOPC::ProcessStart || opcode_id == EM_ProcessEventOPC::ProcessDCStart)
	{
		auto process_id_ = record->GetDataParameter(parameter_index_enum::ProcessId);
		auto parentId = record->GetDataParameter(parameter_index_enum::ParentId);
		
		if (Filter::query_ransom_process_id_black_list(parentId))
		{
			Filter::insert_ransom_process_id_black_list(process_id_);
			LoggerRecord::WriteLog(L"AddRansomBlackProcess process_id_ " + std::to_wstring(process_id_), LogLevel::INFO);
		}
		return true;	// 进程事件全发送至ransom
	}	

	auto pid = record->get_process_id_();
	if (pid == _explorer_pid || pid == 4)
		return false;

	if (Filter::query_ransom_process_id_black_list(pid))
		return true;

	do 
	{
		auto openpath = record->GetStringParameter(parameter_index_enum::OpenPath);
		auto filename = record->GetStringParameter(parameter_index_enum::FileName);
		if (filename.length() > 0)
		{
			if (Filter::query_ransom_dir_white_list(filename))
			{	
				LoggerRecord::WriteLog(L"query_ransom_dir_white_list opcode_id: " + std::to_wstring(opcode_id) +
					L",useles: " + std::to_wstring(record->isUseless()) + 
					L",FileName: " + filename, LogLevel::INFO);
				break;
			}
          
			size_t end = filename.find_last_of('.');
			if (end != string::npos)
			{
				auto suffix = ToolFunctions::WStringToString(filename.substr(end + 1)) ;//获取文件后缀
				if (suffix != "" && Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				{
					LoggerRecord::WriteLog(L"query_ransom_suffix_white_list opcode_id: " + std::to_wstring(opcode_id) +
						L",useles: " + std::to_wstring(record->isUseless()) +
						L",FileName: " + filename, LogLevel::INFO);
					break;
				}
			}
			
		}

		if (openpath.length() > 0)
		{
			if (Filter::query_ransom_dir_white_list(openpath))
			{
				LoggerRecord::WriteLog(L"query_ransom_dir_white_list opcode_id: " + std::to_wstring(opcode_id) +
					L",useles: " + std::to_wstring(record->isUseless()) +
					L",openpath: " + openpath, LogLevel::INFO);
				break;
			}

			size_t end = openpath.find_last_of('.');
			if (end != string::npos)
			{
				auto suffix = ToolFunctions::WStringToString(openpath.substr(end + 1));//获取文件后缀				
				if (suffix != "" && Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				{
					LoggerRecord::WriteLog(L"query_ransom_suffix_white_list opcode_id: " + std::to_wstring(opcode_id) +
						L",useles: " + std::to_wstring(record->isUseless()) +
						L",openpath: " + openpath, LogLevel::INFO);
					break;
				}
			}
		}

		return false;
	} while (0);

	Filter::insert_ransom_process_id_black_list(pid);				// 添加进程进黑名单
	LoggerRecord::WriteLog(L"AddRansomBlackProcess parent process_id_ " + std::to_wstring(pid), LogLevel::INFO);
    /* 不添加父进程所有子进程进队列，后续看检测情况
	LoggerRecord::WriteLog(L"Filter:: processid_parentid_map size " + std::to_wstring(processid_parentid_map.size()), LogLevel::INFO);
	for each (auto var in processid_parentid_map)
	{		
		if (var.second == pid)
		{
			if (var.first == _explorer_pid || var.first == 4 || var.first <= 0)
				continue;
			Filter::insert_ransom_process_id_black_list(var.first);	// 添加进程子进程进黑名单
			LoggerRecord::WriteLog(L"AddRansomBlackProcess child process_id_ " + std::to_wstring(var.first), LogLevel::INFO);
		}		
	}
	*/
	return true;
}

void Filter::insert_systemcall_name_list(std::string temp)
{
	signature_systemcall_name_list.insert(temp);
}

void Filter::SignatureFileFilter()
{
	std::vector<std::string> files_path;
	std::vector<std::string> files_name;
	getFiles(signature_file_path, files_path, files_name);

	//necessary event
	EventIdentifier temp_event_identifier;
	//process start
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessStart);
	temp_event_identifier.provider_id(ETWProcess);
	InsertEventIdentifier(temp_event_identifier);
	//process end
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessEnd);
	InsertEventIdentifier(temp_event_identifier);
	//process dcstart
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessDCStart);
	InsertEventIdentifier(temp_event_identifier);
	//thread start
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadStart);
	temp_event_identifier.provider_id(ETWThread);
	InsertEventIdentifier(temp_event_identifier);
	//thread end
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadEnd);
	InsertEventIdentifier(temp_event_identifier);
	//thread dcstart
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadDCStart);
	InsertEventIdentifier(temp_event_identifier);
	//cswitch
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadContextSwitch);
	InsertEventIdentifier(temp_event_identifier);

	for (std::vector<std::string>::iterator ix = files_path.begin(); ix != files_path.end(); ix++)
	{
		std::fstream infile(*ix, std::ios::in);
		std::string line;
		while (getline(infile, line))
		{
			if (line.find("@") != -1)
			{
				std::istringstream signature_line(line);
				std::string temp;
				signature_line >> temp;
				temp.erase(temp.begin());
				if (temp == "PerfInfoSysClEnter")
				{
					std::string temp_systemcall;
					signature_line >> temp_systemcall >> temp_systemcall;
					temp_systemcall.erase(0, 11);
					size_t pos = temp_systemcall.find('\"');
					temp_systemcall.erase(pos, 2);
					if (signature_systemcall_name_list.find(temp_systemcall) == signature_systemcall_name_list.end()) signature_systemcall_name_list.insert(temp_systemcall);
					//for (std::set<std::string>::iterator ix = systemcall_name_list.begin(); ix != systemcall_name_list.end(); ix++){
					//	if ((*ix).find(temp_systemcall)!=-1 && (signature_systemcall_name_list.find(*ix) == signature_systemcall_name_list.end())){
					//		signature_systemcall_name_list.insert(*ix);
					//		break;
					//	}
					//}
				}
				for (std::set<EventIdentifier>::iterator ix = event_list.begin(); ix != event_list.end(); ix++)
				{
					if (ix->event_name().find(temp) != string::npos && (signature_event_list.find(*ix) == signature_event_list.end()))
					{
						signature_event_list.insert(*ix);
						break;
					}
				}
			}
		}
		infile.close();
		infile.clear();
	}

	bool registry_flag_ = false;
	bool fileio_flag_ = false;
	bool alpc_flag_ = false;

	for (std::set<EventIdentifier>::iterator ix = signature_event_list.begin(); ix != signature_event_list.end(); ix++) 
	{
		if (ix->provider_id() == ETWALPC) alpc_flag_ = true;
		if (ix->provider_id() == ETWFileIo) fileio_flag_ = true;
		if (ix->provider_id() == ETWRegistry) registry_flag_ = true;
	}

	if (alpc_flag_) 
	{
		temp_event_identifier.opcode(EM_AlpcEventOPC::AlpcSendEvent);
		temp_event_identifier.provider_id(ETWALPC);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_AlpcEventOPC::ApcReceiveEvent);
		InsertEventIdentifier(temp_event_identifier);
	}

	if (fileio_flag_) 
	{
		temp_event_identifier.opcode(EM_FileioEventOPC::FileioFileCreateEvent);
		temp_event_identifier.provider_id(ETWFileIo);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_FileioEventOPC::FileioCreateEvent);
		InsertEventIdentifier(temp_event_identifier);
	}

	if (registry_flag_) {
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryCreate);
		temp_event_identifier.provider_id(ETWRegistry);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryKCBCreate);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryOpen);
		InsertEventIdentifier(temp_event_identifier);
	}
	event_list.swap(signature_event_list);
}

void Filter::InitSystemcallEventList()
{
	std::fstream infile(addressmap_file, std::ios::in);
	std::string systemcall_name, systemcall_address;
	while (infile >> systemcall_name >> systemcall_address)
	{
		if (signature_systemcall_name_list.find(systemcall_name) != signature_systemcall_name_list.end())
		{
			systemcall_list.insert(atoi(systemcall_address.c_str()));
		}
	}
}

void Filter::set_systemcall_list(std::string infile_name)
{
	std::fstream infile(infile_name, std::ios::in);
	std::string systemcalll_name;
	while (infile >> systemcalll_name){
		systemcall_name_list.insert(systemcalll_name);
	}
}

bool Filter::QuerySystemcallName(std::string& systemcall_name)
{
//	std::string temp_systemcall_name;
//	Wchar_tToString(temp_systemcall_name, systemcall_name);
	if (signature_systemcall_name_list.size() == 0) return true;
	if (signature_systemcall_name_list.count(systemcall_name)) return true;
	return false;
}


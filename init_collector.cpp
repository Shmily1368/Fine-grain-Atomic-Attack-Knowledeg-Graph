#include "stdafx.h"
#include "output_kafka.h"
#include "output_json.h"
#include "output_ransom.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "event_record_subclass.h"
#include "get_signature_info.h"
#include "event_record_callstack.h"
#include "ntkernel_provider_guid.h"
#include <windows.h> 
#include <wbemidl.h> 
#include "output.h"
#include <comdef.h>  
#include <Shlwapi.h> 
#include <tchar.h>
#include "obtain_entry_address.h"
//#include "avro_snappy.h"
#include <json_include\rapidjson\istreamwrapper.h>
#include <json_include\rapidjson\document.h>
#include <thread>
#include <Windows.h>
#include <windowsx.h>
#include <fstream>
#include <boost/algorithm/string.hpp>

#include "setting.h"
#include "time_util.h"
#include "thread_task_manager.h"
#include "output.h"
#include "filter.h"
#include "named_pipe_client.h"

#pragma comment(lib, "wbemuuid.lib")  
#pragma comment(lib, "Shlwapi.lib")  

using namespace std;
using namespace rapidjson;

uint_64 InitCollector::PARSE_EVENT_COUNT = 0;
bool InitCollector::one_hour_cache_clean_flag = false;

InitCollector* InitCollector::_instance = nullptr;

InitCollector::InitCollector(EM_InitCollectorMode mode) 
	: _mode(mode)
	, m_insert_child_process(false)
	, m_sig_verification(false)
{
	if (Setting::GetInstance().local_detector_mode() == "callstack")
	{
		_detector_mode = LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK;
	}
	else
	{
		_detector_mode = LocalDetectorMode::LOCAL_DETECTOR_MODE__SYSCALL;
	}
}

InitCollector::~InitCollector()
{

}

void InitCollector::Clean()
{
	for (auto& output : _output_list)
	{
		output->Clean();
	}
}

void InitCollector::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return;
	// add by zxw on 20210511
    //UpdateUuidEventRecord(rec);
	bool delete_flag = true;
	for (auto& output : _output_list)
	{
		delete_flag &= output->OutputEventRecord(rec);
	}

	if (delete_flag)	EventRecordManager::GetInstance().RecycleEventRecord(rec);
}

void InitCollector::PushSendRecord(EventRecord* rec)
{
    // add by zxw on 20200109
    auto data_size = _wait_send_data_queue.size_approx();
    if (data_size > 100000)
    {
        _swap_flag = true;
    }
    else if (data_size == 0)
    {
        if (_swap_flag)
        {
            _swap_data_lock.WriteLock();            
            EventRecordQueue().swap(_wait_send_data_queue);
            _swap_flag = false;
            _swap_data_lock.WriteUnlock();
        }
    }
    //

	_wait_send_data_queue.enqueue(rec);
}

EventRecord* InitCollector::PopSendRecord()
{
	if (_wait_send_data_queue.size_approx() == 0)	return nullptr;

	EventRecord* rec = nullptr;
	if (!_wait_send_data_queue.try_dequeue(rec))	return nullptr;

	return rec;
}

size_t InitCollector::WaitSendDataSize()
{
	return _wait_send_data_queue.size_approx();
}

void InitCollector::SetProcessLastEvent(DWORD pid, uint_32 provider_id, uint_32 opcode)
{
	_process_last_event[pid] = (uint_64)provider_id * 100 + opcode;
}

void InitCollector::GetProcessLastEvent(DWORD pid, uint_32& provider_id, uint_32& opcode)
{
	auto iter_f = _process_last_event.find(pid);
	if (iter_f != _process_last_event.end())
	{
		provider_id = iter_f->second / 100;
		opcode = iter_f->second % 100;
	}
	else
	{
		provider_id = 0;
		opcode = 0;
	}
}

void InitCollector::InitOutput()
{
	const String& output_mode_str = Setting::GetInstance().output_mode();
	if (output_mode_str == EMPTY_STRING)	return;

	STRING_VECTOR output_vector;
	StringUtil::split(output_mode_str, '|', output_vector);
	for (auto& output_mode : output_vector)
	{
		if (output_mode == "Kafka")
		{
			_output_list.push_back(new OutputKafka());
			continue;
		}
		if (output_mode == "Json")
		{
			_output_list.push_back(new OutputJson());
			continue;
		}
	}
	// add by zxw on 20191128
	if (Setting::GetInstance().enable_ransom_detector())
	{
		_output_list.push_back(new OutputRansom());
	}
	//Init output thread 
	ThreadTaskManager::GetInstance().AddTask(OUTPUT_RECORD_TASK_MODE);
}

void InitCollector::InitDefaultValue()
{
	for (int i = 0; i != Max_Process_ID; i++) 
	{
		ObtainEntryAddress::moduleAddressTree[i] = NULL;
	}

	PhfDetector::GetInstance().Init();
}

void InitCollector::InitCallStackEnableEvent()
{
	wcout << "InitCallStackEnableEvent" << endl;
	LoggerRecord::WriteLog(L"InitCallStackEnableEvent", LogLevel::INFO);
	vector<CLASSIC_EVENT_ID> enable_stack_events;
// 	enable_stack_events.push_back({ ProcessGuid, 1,{ 0 } });
// 	enable_stack_events.push_back({ ProcessGuid, 2,{ 0 } });
// 	enable_stack_events.push_back({ ProcessGuid, 4,{ 0 } });
// 	enable_stack_events.push_back({ FileIoGuid, 64,{ 0 } });
// 	enable_stack_events.push_back({ FileIoGuid, 67,{ 0 } });
// 	enable_stack_events.push_back({ FileIoGuid, 68,{ 0 } });
// 	enable_stack_events.push_back({ FileIoGuid, 72,{ 0 } });
// 	enable_stack_events.push_back({ FileIoGuid, 74,{ 0 } });
	enable_stack_events.push_back({ PerfInfoGuid, 51,{ 0 } });
// 	enable_stack_events.push_back({ ALPCGuid, 33,{ 0 } });
// 	enable_stack_events.push_back({ ALPCGuid, 34,{ 0 } });
// 	enable_stack_events.push_back({ ThreadGuid, 2,{ 0 } });
// 	enable_stack_events.push_back({ ThreadGuid, 4,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 10,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 11,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 13,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 16,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 17,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 18,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 20,{ 0 } });
// 	enable_stack_events.push_back({ RegistryGuid, 22,{ 0 } });
	_etw_configuration.SetEnableStackEvents(enable_stack_events);

	EventRecordCallstack::InitApiConfiguration();
	EventRecordCallstack::Init();
}

void InitCollector::InitKeyAndMouseHook() 
{
	ThreadTaskManager::GetInstance().AddTask(HOOK_KEY_MOUSE_TASK_MODE);
} 

void InitCollector::InitThreadTask()
{

}

void InitCollector::GetSystemContext() 
{
	LoggerRecord::WriteLog(L"GetSystemContext", INFO);
// 	SystemContext sys_context;
// 
// 	//later you may can do key handle fix in here too
// 	sys_context.GetFileContext(EventRecordFileio::file_context);
// 
// 	std::wofstream f;
// 	f.open(L"Fileobject.txt");
// 	f.imbue(locale(locale(), "", LC_CTYPE));
// 	//
// 	//do drive translate 
// 	for (auto iter = EventRecordFileio::file_context.begin(); iter != EventRecordFileio::file_context.end(); iter++) 
// 	{
// 		if (iter->second.find(L"HarddiskVolume") != wstring::npos)
// 		{
// 			std::wstring converted_path;
// 			ObtainEntryAddress::drivemap.ConvertDeviceFormat2DriveFormat(iter->second, converted_path, true);
// 			iter->second = converted_path;
// 		}
// 		f << iter->first << L" ";
// 		f << iter->second << std::endl;
// 	}
// 
// 	f.close(); 
// 
// 	std::cout << "GetSystemFileContext" << std::endl;
// 	LoggerRecord::WriteLog(L"GetSystemFileContext", LogLevel::INFO);
	//getchar();
}

void InitCollector::InitEventStruct()
{
	LoggerRecord::WriteLog(L"Init EventRecordManager", INFO);

	EventRecordManager::GetInstance();
	ObtainEntryAddress::drivemap.getDeviceDriveMap();//need excute after set_event_strucp_map;
}

void InitCollector::InitDLLModuleTree()
{
	for (auto iter = signature_dll_file_path_.begin(); iter != signature_dll_file_path_.end(); iter++) 
	{
		wstring module_name = ToolFunctions::StringToWString(*iter);
		if ((ToolFunctions::isEndWith(module_name.c_str(), L".dll")) || (ToolFunctions::isEndWith((module_name).c_str(), L".DLL"))) 
		{
			LoggerRecord::WriteLog(L"Load module:" + module_name, INFO);
			ObtainEntryAddress::getModuleRvaFromFileName(module_name);
		}
	}
}

void InitCollector::ParseAPISignatureFile(std::string file_name)
{
	LoggerRecord::WriteLog(L"ParseAPISignatureFile", INFO);
	ifstream ifs(file_name);
	IStreamWrapper isw(ifs);
	Document newDoc;
	newDoc.ParseStream(isw);
	if (newDoc.HasParseError()) 
	{
#ifdef OUTPUT_COMMAND_LINE
		printf("Json Parse error:%d", newDoc.GetParseError()); 
#endif // OUTPUT_COMMAND_LINE;
		return;
	}
	if (newDoc.IsArray() && !newDoc.Empty()) 
	{
		for (rapidjson::SizeType i = 0; i < newDoc.Size(); i++) 
		{
			rapidjson::Value& temp_object = newDoc[i];
			if (temp_object.HasMember("sig")) 
			{
				rapidjson::Value signatures_dll_api;    
				signatures_dll_api = temp_object["sig"];


				if (signatures_dll_api.IsArray() && !signatures_dll_api.Empty())
				{
					for (rapidjson::SizeType j = 0; j < signatures_dll_api.Size(); j++) 
					{
						string temp = signatures_dll_api[j].GetString();
						Filter::GetInstance().insert_api_name_white_list(temp);
					}
				}
				else 
				{

				}
			}
			else 
			{

			}
		}
	}
	ifs.close();
	ifs.clear();
}

void InitCollector::UpdateUuidEventRecord(EventRecord * rec) 
{
    if (!rec)
        return;

    if (rec->isUseless())
        return ;

    std::wstring strUuid;

    auto provider_id = rec->get_event_identifier_().provider_id();
    auto opcode_id = rec->get_event_identifier_().opcode();
    //auto process_id = rec->GetDataParameter(parameter_index_enum::ProcessId);
    auto process_id = rec->get_process_id_();
    if (provider_id == ETWProcess && (opcode_id == EM_ProcessEventOPC::ProcessDCStart || opcode_id == EM_ProcessEventOPC::ProcessStart))
    {
        process_id = rec->GetDataParameter(parameter_index_enum::ProcessId);
    }
   
    do 
    {
        if (provider_id == ETWProcess && (opcode_id == EM_ProcessEventOPC::ProcessDCStart || opcode_id == EM_ProcessEventOPC::ProcessStart))
        {
            if (GetUuidbyProcessId(process_id, strUuid)) {
                insert_process_id_uuid_map(process_id, strUuid);
            }
            else {
                LoggerRecord::WriteLog(L"InitCollector::UpdateUuidEventRecord failed, pid " + to_wstring(process_id), LogLevel::DEBUG);
            }
            break;
        }
        else {           
            query_process_id_uuid_map(process_id, strUuid);
        }        

        // processend erase cache
        if (provider_id == ETWProcess && opcode_id == EM_ProcessEventOPC::ProcessEnd) {
            erase_process_id_uuid_map(process_id);
            break;
        }
    } while (0);
     
    // add uuid to event
    rec->SetParameter(parameter_index_enum::PUUID, strUuid);
}

bool InitCollector::GetUuidbyProcessId(DWORD process_id, std::wstring & strUuid) 
{
    HANDLE device = 0;
    SKU_INFO sku;
    BOOL bool_ret = FALSE;

    device = CreateFileA("\\\\.\\MagicProcesser", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!device || device == INVALID_HANDLE_VALUE) {
		LoggerRecord::WriteLog(L"InitCollector::GetUuid, createfile failed", LogLevel::ERR);
        return bool_ret;
    }

    memset(&sku, 0, sizeof(sku));
    sku.pid = process_id;

    DWORD nBytesReturn;
    bool_ret = ::DeviceIoControl(device,
        CODEMSG(GET_PROCESS_SKU),
        &sku,
        sizeof(sku),
        &sku,
        sizeof(sku),
        &nBytesReturn,
        NULL);
    if (bool_ret)
    {
        strUuid = ToolFunctions::StringToWString(sku.psz_process_unique_identifier);
    }
   
    CloseHandle(device);

    return bool_ret;
}

void InitCollector::insert_process_id_uuid_map(DWORD process_id, std::wstring strUUID) 
{
    _process_uuid_map[process_id] = strUUID;
}

// erase_process_id_uuid_map
void InitCollector::erase_process_id_uuid_map(DWORD process_id) 
{
    if (_process_uuid_map.find(process_id) != _process_uuid_map.end()) {
        _process_uuid_map.erase(process_id);
    }
}

// query_process_id_uuid_map
bool InitCollector::query_process_id_uuid_map(DWORD process_id, std::wstring & strUuid)
{
    bool ret = false;
    if (process_id <= 0)
    {
        return ret;
    }
    auto iter = _process_uuid_map.find(process_id);
    if (iter != _process_uuid_map.end()) {
        strUuid = iter->second;
        ret = true;
    }
    else {
        if (GetUuidbyProcessId(process_id, strUuid))
        {
            // before process start or after process end event
            //insert_process_id_uuid_map(process_id, strUuid);
            LoggerRecord::WriteLog(L"query_process_id_uuid_map strUuid " + strUuid+
                L",pid " + to_wstring(process_id), LogLevel::DEBUG);
            ret = true;
        }
    }
    return ret;
}

void InitCollector::InitVerification()
{
	if (Setting::GetInstance().verification() == "open")
	{
		m_sig_verification = true;
	}

	HRESULT hRet = S_OK;

	// 初始化COM组件  
	hRet = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hRet))
    {
#ifdef OUTPUT_COMMAND_LINE	
		cout << "初始化COM库组件失败。错误码：" << hRet << endl;
#endif // OUTPUT_COMMAND_LINE;
		exit(1);
	}

	IWbemLocator *pIWbemLocator = NULL;

	hRet = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pIWbemLocator);
	if (FAILED(hRet))
	{
#ifdef OUTPUT_COMMAND_LINE	
		cout << "创建IWbemLocator对象失败！错误码：" << hRet << endl;
#endif // OUTPUT_COMMAND_LINE;
		CoUninitialize();
		exit(1);
	}

	IWbemServices *pIWbemServices = NULL;

	bstr_t strNetwoekResource("ROOT\\CIMV2");

	hRet = pIWbemLocator->ConnectServer(strNetwoekResource, NULL, NULL, NULL, 0, NULL, NULL, &pIWbemServices);
	if (FAILED(hRet))
	{
#ifdef OUTPUT_COMMAND_LINE	
		cout << "" << hRet << endl;
#endif // OUTPUT_COMMAND_LINE;
		pIWbemLocator->Release();
		CoUninitialize();
		exit(1);
	}
#ifdef OUTPUT_COMMAND_LINE	
	cout << "Connected to WMI \n" << endl;
#endif // OUTPUT_COMMAND_LINE;

	hRet = CoSetProxyBlanket(pIWbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hRet))
	{
#ifdef OUTPUT_COMMAND_LINE
		cout << "CoSetProxyBlanket FAILED" << endl;
#endif // OUTPUT_COMMAND_LINE;	
		pIWbemServices->Release();
		pIWbemLocator->Release();
		CoUninitialize();
		exit(1);
	}

	bstr_t strQueryLanguage("WQL");
	bstr_t strQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

	IEnumWbemClassObject *pIEnumWbemClassObject = NULL;

	hRet = pIWbemServices->ExecNotificationQuery(strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pIEnumWbemClassObject);

	if (!SUCCEEDED(hRet)) {
#ifdef OUTPUT_COMMAND_LINE      
		cout << "创建pIWbemServices对象失败！错误码：" << hRet << endl;
#endif // OUTPUT_COMMAND_LINE;
		CoUninitialize();
		exit(1);
	}
}
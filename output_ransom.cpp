#include "stdafx.h"
#include "tool_functions.h"
#include "output_ransom.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "init_collector.h"
#include "time_util.h"
#include "event_record_manager.h"
#include "parameter_index.h"
#include "filter.h"

OutputRansom::OutputRansom()
{
	// 启动ransom模块线程
	_ransomthread = std::thread(&OutputRansom::_ExcuteRansomDetector, this);
	_ransomthread.detach();
	initTime = time(NULL);
    _user_path = ToolFunctions::GetUserPath();
	LoggerRecord::WriteLog(L"InitOutputRansom user_path " + ToolFunctions::StringToWString(_user_path), INFO);
}

OutputRansom::~OutputRansom()
{

}

bool OutputRansom::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return false;
	// 10min清理map
	auto times = time(NULL);
	if (time(NULL) - initTime > clean_time_threshold)
	{
		initTime = time(NULL);
		_CleanUselessCache();
	}

	if (Filter::GetInstance().IsRansomBlackProcess(rec))
		_RansomParse(rec);

	return true;
}

void OutputRansom::_ExcuteRansomDetector()
{
	RansomDetector::GetInstance().Init();
}

void OutputRansom::_PushRansomRecord(EventRecord * record)
{
	if (!record)
		return;

	auto provider_id = record->get_event_identifier_().provider_id();
	auto opcode_id = record->get_event_identifier_().opcode();
	set< uint_32> opcode_output = { 1,2,3,64,67,68,71,70,72,65 };
	if (provider_id != ETWStackWalk && provider_id != ETWFileIo && provider_id != ETWProcess)
		return;
	if (provider_id != ETWStackWalk && opcode_output.find(opcode_id) == opcode_output.end())
		return;

	// 推送ransom模块
	event ev(*record);
	RansomDetector::GetInstance().PushRansomRecord(ev);
	output_event_sum++;
	if (output_event_sum % 20000 == 0) {
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_PushRansomRecord sum: " << output_event_sum << 
			" fileioread_cache_map:" << _fileioread_cache_map.size()<<
			" fileiowrite_cache_map:"<< _fileiowrite_cache_map .size()<< endl;
 #endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"_PushRansomRecord counts: " + std::to_wstring(output_event_sum) +
			L" fileioread_cache_map size: " + std::to_wstring(_fileioread_cache_map.size()) +
			L" fileiowrite_cache_map size: " + std::to_wstring(_fileiowrite_cache_map.size()), INFO);
	}
}

void OutputRansom::_RansomParse(EventRecord* rec)
{
	auto event_providerid = rec->get_event_identifier_().provider_id();
	auto event_opcode = rec->get_event_identifier_().opcode();
	if (event_providerid == ETWFileIo)
	{
        // add by zxw on 20201112       
        if (event_opcode = EM_FileioEventOPC::FileioCreateEvent)
        {
            auto open_path = rec->GetStringParameter(parameter_index_enum::OpenPath);
            if (open_path.size() != 0 && !ToolFunctions::JudgePath(_user_path, ToolFunctions::WStringToString(open_path))) {
                return;
            }
        }
        else {
            auto file_name = rec->GetStringParameter(parameter_index_enum::FileName);
            if (file_name.size() != 0 && !ToolFunctions::JudgePath(_user_path, ToolFunctions::WStringToString(file_name))) {
                return;
            }
        }        
        //

		switch (event_opcode)
		{
		case EM_FileioEventOPC::FileIoCleanup:
		{         
			_RansomFileIoCleanup(rec);
			break;
		}
		case EM_FileioEventOPC::FileIoRead:
		{
			_RansomFileIoRead(rec);
			break;
		}
		case EM_FileioEventOPC::FileIoWirte:
		{          
			_RansomFileIoWirte(rec);
			break;
		}		
		default:
		{            
			_PushRansomRecord(rec);
			break;
		}
		}
	}
	else if (event_providerid == ETWProcess)
	{
		// 清理缓存
		_CleanProcessCache(rec->get_process_id_());

		switch (event_opcode)
		{
		case EM_ProcessEventOPC::ProcessStart:
		case EM_ProcessEventOPC::ProcessEnd:
		case EM_ProcessEventOPC::ProcessDCStart:
		{
			_PushRansomRecord(rec);
			break;
		}
		default:
			break;
		}
	}
	else if (event_providerid == ETWStackWalk)
	{
		auto callstack_ = rec->get_callstack_();
		if (callstack_ == "CryptImportKey" || callstack_ == "K32GetProcessImageFileName")
		{
			_PushRansomRecord(rec);
		}		
	}
}

void OutputRansom::_RansomFileIoRead(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (process_id == 0 || fileobj == 0)
		return;
	event ev(*rec);
	ev.set_time_stamp(time(NULL));
	auto iter = _fileioread_cache_map.find(process_id);
	if (iter != _fileioread_cache_map.end())
	{
		auto& cache_set = iter->second;
		auto cashe_iter = cache_set.find(fileobj);
		if (cashe_iter != cache_set.end())
		{
			cashe_iter->second = ev;
		}else
			cache_set.insert(make_pair(fileobj, ev));		
	}
	else
	{	
		_fileioread_cache_map[process_id].insert({fileobj, ev});
	}
}

void OutputRansom::_RansomFileIoWirte(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (process_id == 0 || fileobj == 0)
		return;
	event ev(*rec);
	ev.set_time_stamp(time(NULL));
	auto iter = _fileiowrite_cache_map.find(process_id);
	if (iter != _fileiowrite_cache_map.end())
	{
		auto& cache_set = iter->second;
		auto cashe_iter = cache_set.find(fileobj);
		if (cashe_iter != cache_set.end())
		{
			auto& record = cashe_iter->second;
			// 累加IoSize
			if (record.arguments.Offset != rec->GetDataParameter(parameter_index_enum::Offset))
			{
				record.arguments.IoSize += rec->GetDataParameter(parameter_index_enum::IoSize);
				record.set_time_stamp(time(NULL));
			}
		}
		else
			cache_set.insert(make_pair(fileobj, ev));
	}
	else
	{
		_fileiowrite_cache_map[process_id].insert({ fileobj, ev });		
	}
}

void OutputRansom::_RansomFileIoCleanup(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (fileobj == 0)
		return;

	auto iterr = _fileioread_cache_map.find(process_id);
	if (iterr != _fileioread_cache_map.end())
	{
		auto& cache_set = iterr->second;
		auto cache_iterr = cache_set.find(fileobj);
		if (cache_iterr != cache_set.end())
		{
			// 推送本地ransom
			RansomDetector::GetInstance().PushRansomRecord(cache_iterr->second);
			cache_set.erase(cache_iterr);
		}		
	}

	auto iterw = _fileiowrite_cache_map.find(process_id);
	if (iterw != _fileiowrite_cache_map.end())
	{
		auto& cache_set = iterw->second;
		auto cache_iterr = cache_set.find(fileobj);
		if (cache_iterr != cache_set.end())
		{
			// 推送本地ransom
			RansomDetector::GetInstance().PushRansomRecord(cache_iterr->second);
			cache_set.erase(cache_iterr);
		}
	}
	// cleanup事件推送ransom
	_PushRansomRecord(rec);
}

void OutputRansom::_RansomCleanMap()
{
	if (_fileioread_cache_map.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map size: " << _fileioread_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"_RansomCleanMap fileioread_cache_map size: " + std::to_wstring(_fileioread_cache_map.size()), INFO);

		std::unordered_map<DWORD, std::unordered_map<ULONG64, event>>().swap(_fileioread_cache_map);
	}

	if (_fileiowrite_cache_map.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map size: " << _fileiowrite_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"_RansomCleanMap fileiowrite_cache_map size: " + std::to_wstring(_fileiowrite_cache_map.size()), INFO);

		std::unordered_map<DWORD, std::unordered_map<ULONG64, event>>().swap(_fileiowrite_cache_map);
	}
}

void OutputRansom::_CleanUselessCache()
{
	if (_fileioread_cache_map.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map size: " << _fileioread_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"_RansomCleanMap fileioread_cache_map size: " + std::to_wstring(_fileioread_cache_map.size()), INFO);
		for (auto iter = _fileioread_cache_map.begin(); iter != _fileioread_cache_map.end();)
		{
			auto& cash_set = iter->second;
			for (auto iterr = cash_set.begin(); iterr != cash_set.end();)
			{
				if (time(NULL) - iterr->second.get_time_stamp() > clean_time_threshold)
				{
					iterr = cash_set.erase(iterr);
				}
				else
					iterr++;
			}
			//
			if (cash_set.size() > 0)
			{				
				LoggerRecord::WriteLog(L"_RansomCleanMap _fileioread_cache_map fileobject:" + std::to_wstring(iter->first) +
					L" size: " + std::to_wstring(cash_set.size()), INFO);
				iter++;
			}
			else
				iter = _fileioread_cache_map.erase(iter);
		}
		LoggerRecord::WriteLog(L"_RansomCleanMap fileioread_cache_map over size: " + std::to_wstring(_fileioread_cache_map.size()), INFO);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map over size: " << _fileioread_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
	}

	if (_fileiowrite_cache_map.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map size: " << _fileiowrite_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"_RansomCleanMap fileiowrite_cache_map size: " + std::to_wstring(_fileiowrite_cache_map.size()), INFO);

		for (auto iter = _fileiowrite_cache_map.begin(); iter != _fileiowrite_cache_map.end();)
		{
			auto& cash_set = iter->second;
			for (auto iterw = cash_set.begin(); iterw != cash_set.end();)
			{
				if (time(NULL) - iterw->second.get_time_stamp() > clean_time_threshold)
				{
					iterw = cash_set.erase(iterw);
				}
				else
					iterw++;
			}
			//
			if (cash_set.size() > 0)
			{
				LoggerRecord::WriteLog(L"_RansomCleanMap _fileiowrite_cache_map fileobject:" + std::to_wstring(iter->first) +
					L" size: " + std::to_wstring(cash_set.size()), INFO);
				iter++;
			}
			else
				iter = _fileiowrite_cache_map.erase(iter);
		}
		LoggerRecord::WriteLog(L"_RansomCleanMap fileiowrite_cache_map over size: " + std::to_wstring(_fileiowrite_cache_map.size()), INFO);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map over size: " << _fileiowrite_cache_map.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
	}
}

void OutputRansom::_CleanProcessCache(DWORD process_id)
{
	_fileioread_cache_map.erase(process_id);
	_fileiowrite_cache_map.erase(process_id);
}

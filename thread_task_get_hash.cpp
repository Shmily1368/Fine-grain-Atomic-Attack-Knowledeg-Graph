#include "stdafx.h"
#include "thread_task_get_hash.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "concurrent_queue.h"
#include "tool_functions.h"
#include "cal_MD5.h"

GetHashThreadTask::GetHashThreadTask()
	: BaseThreadTask(GEE_HASH_TASK_MODE)
{
	
}

GetHashThreadTask::~GetHashThreadTask()
{

}

void GetHashThreadTask::_Excute()
{
	Sleep(MS_ONE_SECOND * 5); // wait 5s to make cpu express better;
    time_t init_time,now_time;
    time(&init_time);
	while (!_stop_flag) 
	{
		if (!_hash_data_queue.empty())
		{
			EventRecord* event_record = nullptr;
			bool flag = _hash_data_queue.front_pop(event_record);
			if (!flag) continue;

            GetHashfromEvent(event_record);
			
			if (_hash_data_queue.size() < 500)
			{
				Sleep(100);
			}
		}
		else 
		{
			_signal.Wait();
		}
        
        time(&now_time);
        if (now_time - init_time > 60*60)
        {
            init_time = now_time;
            CleanFileHashMap();
        }
	}
}

void GetHashThreadTask::GetHashfromEvent(EventRecord * ev) 
{
    if (!ev)
    {
        return;
    }
    SFileHash fileHash;
    auto fileName = ev->GetStringParameter(parameter_index_enum::FileName);
    if (fileName.size() > 0)
    {
        // if file_name is equal last
        if (GetFileHash(fileName, fileHash.file_md5, fileHash.file_size)) {
            EventRecord* event_record = EventRecordManager::GetInstance().ParseHashInfoEvent(ev, fileHash.file_md5, fileHash.file_size);
            if (event_record)
                InitCollector::GetCollector()->PushSendRecord(event_record);
            return;
        }

        std::string filePath = ToolFunctions::UTF8_to_String(ToolFunctions::WStringToString(fileName));
        auto fileSize = ToolFunctions::get_file_ize(filePath.c_str());
        if (fileSize <= 0 || fileSize > 1024 * 1024 * 50) {    // 文件大于50M不计算MD5 
            LoggerRecord::WriteLog(L"GetHashThreadTask::GetHashfromEvent fileSize is 0 or over 50M, fileSize： " + to_wstring(fileSize), LogLevel::DEBUG);
            return;
        }
      
        std::string tmp_md5 = CalMD5::Calculate((wchar_t*)fileName.c_str());
        if (tmp_md5.size() == 0) {
            LoggerRecord::WriteLog(L"GetHashThreadTask::GetHashfromEvent Calculate md5 failed, filePath " + fileName, LogLevel::DEBUG);
            return;
        }

        fileHash.file_md5 = ToolFunctions::StringToWString(tmp_md5);
        fileHash.file_size = fileSize;
        file_hash_map_[fileName] = fileHash;

        EventRecord* event_record = EventRecordManager::GetInstance().ParseHashInfoEvent(ev, fileHash.file_md5, fileHash.file_size);
        if (event_record)
            InitCollector::GetCollector()->PushSendRecord(event_record);
    }
}

bool GetHashThreadTask::GetFileHash(std::wstring file_name, std::wstring & file_md5, long & file_size)
{
    auto iter = file_hash_map_.find(file_name);
    if (iter != file_hash_map_.end())
    {
        auto sfilehash = iter->second;
        file_md5 = sfilehash.file_md5;
        file_size = sfilehash.file_size;
        return true;
    }
    return false;
}

void GetHashThreadTask::CleanFileHashMap() 
{
    LoggerRecord::WriteLog(L"GetHashThreadTask::CleanFileHashMap file_hash_map_ size before clean = " + std::to_wstring(file_hash_map_.size()), LogLevel::DEBUG);
    std::unordered_map<std::wstring, SFileHash>().swap(file_hash_map_);
}

void GetHashThreadTask::Log()
{
	int size = _hash_data_queue.size();
#ifdef OUTPUT_COMMAND_LINE       
	cout <<"CertificateImageThreadTask::Log:certificate_data_queue size is " << size << endl;
#endif // OUTPUT_COMMAND_LINE;
	LoggerRecord::WriteLog(L"GetHashThreadTask::Log:hase_data_queue size is" + std::to_wstring(size), LogLevel::INFO);
}

void GetHashThreadTask::Init()
{
	LoggerRecord::WriteLog(L"GetHashThreadTask", LogLevel::INFO);
}

void GetHashThreadTask::Stop()
{
	_stop_flag = true;
	_signal.NotifyOne();
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void GetHashThreadTask::AddData(EventRecord* record)
{
	EventRecordImage* image_rec = dynamic_cast<EventRecordImage*>(record);
	if (!image_rec)
	{
		SAFE_DELETE(record);
		return;
	}

	_hash_data_queue.push(record);
	_signal.NotifyOne();
}

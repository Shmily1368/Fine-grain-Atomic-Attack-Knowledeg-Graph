#include "stdafx.h"
#include "thread_task_cerficate_image.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "concurrent_queue.h"

CertificateImageThreadTask::CertificateImageThreadTask()
	: BaseThreadTask(CERTIFICATE_IMAGE_TASK_MODE)
{
	
}

CertificateImageThreadTask::~CertificateImageThreadTask()
{

}

void CertificateImageThreadTask::_Excute()
{
	//_certificate_dataqueue will change in class outside,so dont use Iterator to avoid crash; to fix chips;
	Sleep(MS_ONE_SECOND * 12); // wait 12s to make cpu express better;

	while (!_stop_flag) 
	{
		if (!_certificate_data_queue.empty())
		{
			EventRecord* event_record = nullptr;
			bool flag = _certificate_data_queue.front_pop(event_record);
			if (!flag) continue;

			EventRecordImage* image_record = dynamic_cast<EventRecordImage*>(event_record);
			if (image_record)
			{
				image_record->certificate();
				InitCollector::GetCollector()->PushSendRecord(image_record);
			}
			else
			{
				LoggerRecord::WriteLog(L"CertificateImageThreadTask::_Excute: wrong type record", LogLevel::ERR);
				SAFE_DELETE(event_record);
			}

			{
				std::wstring& file_name = image_record->GetStringParameter(parameter_index_enum::FileName);

				AutoLock lock(_processing_files_lock);
				_processing_file_names.erase(file_name);
				auto iter_f = _processing_file_lists.find(file_name);
				if (iter_f != _processing_file_lists.end())
				{
					const auto& file_list = iter_f->second;
					for (EventRecordImage* image_rec : file_list)
					{
						image_rec->certificate();
						InitCollector::GetCollector()->PushSendRecord(image_rec);
					}

					_processing_file_lists.erase(iter_f);
				}
			}
            // remove by zxw on 20202-1229
            /*
			if (_certificate_data_queue.size() < 500)
			{
				Sleep(100);
			}
            */
            Sleep(1);
		}
		else 
		{
			_signal.Wait();
		}
	}
}

void CertificateImageThreadTask::Log()
{
	int size = _certificate_data_queue.size();
#ifdef OUTPUT_COMMAND_LINE       
	cout <<"CertificateImageThreadTask::Log:certificate_data_queue size is " << size << endl;
#endif // OUTPUT_COMMAND_LINE;
	LoggerRecord::WriteLog(L"CertificateImageThreadTask::Log:certificate_data_queue size is" + std::to_wstring(size), LogLevel::INFO);
}

void CertificateImageThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitImageCerificate", LogLevel::INFO);
}

void CertificateImageThreadTask::Stop()
{
	_stop_flag = true;
	_signal.NotifyOne();
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void CertificateImageThreadTask::AddData(EventRecord* record)
{
	EventRecordImage* image_rec = dynamic_cast<EventRecordImage*>(record);
	if (!image_rec)
	{
		SAFE_DELETE(record);
		return;
	}

	AutoLock lock(_processing_files_lock);
	const std::wstring& file_name = record->GetStringParameter(parameter_index_enum::FileName);
	if (_processing_file_names.find(file_name) != _processing_file_names.end())
	{
		_processing_file_lists[file_name].push_back(image_rec);
		return;
	}

	_processing_file_names.insert(file_name);
	_certificate_data_queue.push(record);
	_signal.NotifyOne();
}

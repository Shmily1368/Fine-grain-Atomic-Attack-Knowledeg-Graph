#include "stdafx.h"
#include "thread_task_parse_event.h"
#include "init_collector.h"
#include "filter.h"

ParseEventThreadTask::ParseEventThreadTask()
	: BaseThreadTask(PARSE_EVENT_TASK_MODE)
{
	
}

ParseEventThreadTask::~ParseEventThreadTask()
{

}

void ParseEventThreadTask::Init()
{
	LoggerRecord::WriteLog(L"Init ParseEventThreadTask", LogLevel::INFO);
#ifdef OUTPUT_COMMAND_LINE       
	std::cout << "Init ParseEventThreadTask" << std::endl;
#endif // OUTPUT_COMMAND_LINE;
}

void ParseEventThreadTask::Log()
{

}

void ParseEventThreadTask::_Excute()
{
	if ((EM_InitCollectorMode)InitCollector::GetCollector()->GetMode() != EM_InitCollectorMode::ONLINE_PARSE_MODE)	return;

	EventRecord* rec = nullptr;
	while (!_stop_flag)
	{
		rec = InitCollector::GetCollector()->PopSendRecord();
		if (rec != nullptr)
		{
			rec->parse();

			//get process_id to filter
			//mainly filter PID in black list, because fileiofilecreate and fileiocreate is need to match rename event and macro ,we do not filter it here
			if (!Filter::GetInstance().FilterAfterParseRecord(rec))
			{
				EventRecordManager::GetInstance().RecycleEventRecord(rec);
				continue;
			}

			rec->SetProcessTcpPreEventRecord(rec);
			if (!rec->Output())
			{
				EventRecordManager::GetInstance().RecycleEventRecord(rec);
			}
		}
		else
		{
			Sleep(10);
		}
	}
}

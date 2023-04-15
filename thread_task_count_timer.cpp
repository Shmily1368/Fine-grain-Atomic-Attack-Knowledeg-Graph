#include "stdafx.h"
#include "thread_task_count_timer.h"
#include "event_record_subclass.h"
#include "global_enum_def.h"
#include "phf_detector.h"
#include "output.h"
#include "init_collector.h"

TimerCountThreadTask::TimerCountThreadTask()
	: BaseThreadTask(TIMER_TASK_MODE)
{
	
}

TimerCountThreadTask::~TimerCountThreadTask()
{

}

void TimerCountThreadTask::_Excute()
{
	int second_count = 1;
	while (!_stop_flag) 
	{
        // mod by zxw on 20200821 change to 10min clear map
		//if (second_count % 3600 == 0)//every 1 hour clear map
        if (second_count % 600 == 0)//every 10 min clear map
		{
			InitCollector::one_hour_cache_clean_flag = true;

			second_count = 0;
		}

		if (second_count % 6 == 0)//6 second
		{
			PhfDetector::GetInstance().ActiveDetectPhfFlag();
			Output::schedule_monitor_flag = true;
		}

		second_count++;
		Sleep(MS_ONE_SECOND);
	}
}

void TimerCountThreadTask::Log()
{

}

void TimerCountThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitTimer", INFO);
}


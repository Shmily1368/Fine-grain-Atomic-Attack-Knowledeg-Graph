#include "stdafx.h"
#include "thread_task_rule_matcher.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "concurrent_queue.h"
#include "rule_matcher.h"

RuleMatcherThreadTask::RuleMatcherThreadTask()
	: BaseThreadTask(RULE_MATCHER_TASK_MODE)
{
	
}

RuleMatcherThreadTask::~RuleMatcherThreadTask()
{

}

void RuleMatcherThreadTask::_Excute()
{
	while (!_stop_flag) 
	{
		if (!_certificate_data_queue.empty())
		{
			EventRecord* event_record = nullptr;
			bool flag = _certificate_data_queue.front_pop(event_record);
			if (!flag) continue;
            SRule srule;
            if (rule_matcher::GetInstance().event_rule_matcher(event_record, srule))
            {
                LoggerRecord::WriteLog(L"RuleMatcherThreadTask send rule " + to_wstring(srule.rule_id), LogLevel::INFO);
                // 上报事件
                EventRecord* rec = EventRecordManager::GetInstance().ParseRuleIdentifierEvent(event_record, srule);
                if (rec && InitCollector::GetCollector())
                    InitCollector::GetCollector()->PushSendRecord(rec);
            }

            SAFE_DELETE(event_record);
		}
		else 
		{
			_signal.Wait();
		}
	}
}

void RuleMatcherThreadTask::Log()
{
	int size = _certificate_data_queue.size();

	LoggerRecord::WriteLog(L"RuleMatcherThreadTask::Log:certificate_data_queue size is" + std::to_wstring(size), LogLevel::INFO);
}

void RuleMatcherThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitRuleMatcher", LogLevel::INFO);
    //rule_matcher::GetInstance().add_rule_map_by_file("rulematcher");    
}

void RuleMatcherThreadTask::Stop()
{
	_stop_flag = true;
	_signal.NotifyOne();
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void RuleMatcherThreadTask::AddData(EventRecord* record)
{
	_certificate_data_queue.push(record);
	_signal.NotifyOne();
}

/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(�汾��);
	Description:	��ʼ���ɼ��������߽������࣬������offline��Ϊ������ԭ������online̫�غ�;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019.01.07    |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/
#pragma once
#include "init_collector.h"
#include "record_queue_per_process.h"

class InitCollectorOfflineParse : public InitCollector
{
public:
	InitCollectorOfflineParse() : InitCollector(EM_InitCollectorMode::OFFLINE_PARSE_MODE) { }

	void InitCallStackRvaAndDriveMap();

	virtual void Init() override;
	virtual void Excute() override;
	virtual void Clean() override;
	virtual void InitFilter();
	static VOID WINAPI ConsumeEvent(PEVENT_RECORD p_event);
	static void CacheClean();
	static bool ParseOPCode(EventRecord* _event_record);
	static void ParseProviderId(EventRecord* _event_record);
	static void ParseETWFileIoEvent(EventRecord* _event_record);
	static void ParseETWImageEvent(EventRecord* _event_record);
	static void ParseETWStackWalkEvent(EventRecord* _event_record);
	static void ParseETWThreadEvent(EventRecord* _event_record);
	static void ParseDefaultEvent(EventRecord* _event_record);

	void CleanQueue();

private:
	static RecordQueuePerProcess call_stack_queue;
	static RecordQueuePerProcess event_queue;
	static unsigned long long call_stack_count;
	static unsigned long long event_count;
};
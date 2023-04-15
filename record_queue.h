#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-4-13
// Updated 2018-5-7

#include <Windows.h>

#include <queue>
#include <deque>
#include <unordered_map>

#include "event_record.h"
#include "event_record_callstack.h"
#include "etw_configuration.h"

class RecordQueue
{
public:
	RecordQueue();
	~RecordQueue();

	bool Empty() { return record_queue_.empty(); }
	void Clear();
	size_t Size() { return record_queue_.size(); }
	// void* TryPop();
	EventRecord* Pop();
	void PushBack(EventRecord* event_record);

	// event_record_queue.Alignment(call_stack_queue)
	ULONG64 Alignment(RecordQueue& callstack_record_queue);
	bool CheckAlignment(RecordQueue& callstack_record_queue);

	std::pair<void*, void*> output(RecordQueue& callstack_record_queue);

	void ClearDeque() { record_queue_.shrink_to_fit(); }

protected:


public:
	std::deque<EventRecord*> record_queue_;

	// if event have callstack return true
	inline bool IsEventwithCallStack(EventRecord* event) 
	{
		return ETWConfiguration::enable_stack_events_set_.find(event->get_event_identifier_().provider_id() + event->get_event_identifier_().opcode()) != ETWConfiguration::enable_stack_events_set_.end();
	}
	//std::deque<ULONG64> timestamp_queue_;
	//std::deque<void*>::iterator currrent_iter_;
};


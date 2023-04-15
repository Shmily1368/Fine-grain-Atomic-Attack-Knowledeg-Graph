#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-5-7
// Updated 2018-5-7

#include <unordered_map>

#include "record_queue.h"

class RecordQueuePerProcess
{
public:
	RecordQueuePerProcess();
	~RecordQueuePerProcess();

	void PushBack(EventRecord* event_record);

	ULONG64 Alignment(RecordQueuePerProcess& callstack_record_queue);

	std::pair<void*, void*> output(RecordQueuePerProcess& callstack_record_queue);

	void ClearDeque();
	void Clear(RecordQueuePerProcess& callstack_record_queue);

public:
	std::unordered_map<DWORD, RecordQueue> record_queue_per_process_;
	std::unordered_map<DWORD, bool> record_queue_empty;
};


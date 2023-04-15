#include "stdafx.h"
#include "record_queue_per_process.h"
#include "event_record.h"

RecordQueuePerProcess::RecordQueuePerProcess()
{
}


RecordQueuePerProcess::~RecordQueuePerProcess()
{
}

void RecordQueuePerProcess::PushBack(EventRecord* event_record) {
	if (record_queue_per_process_.count(event_record->get_thread_id_()) == 0) {
		record_queue_per_process_[event_record->get_thread_id_()] = RecordQueue();
		//record_queue_empty[event_record->get_thread_id_()] = false;
	}
	record_queue_per_process_[event_record->get_thread_id_()].PushBack(event_record);
}

ULONG64 RecordQueuePerProcess::Alignment(RecordQueuePerProcess& callstack_record_queue) {
	for (auto iter = record_queue_per_process_.begin(); iter != record_queue_per_process_.end(); iter++) {
		//if (callstack_record_queue.record_queue_per_process_[iter->first].Size() && iter->second.Size())
			//iter->second.Alignment(callstack_record_queue.record_queue_per_process_[iter->first]);
		record_queue_empty[iter->first] = false;
	}

	return 0;
}

std::pair<void*, void*> RecordQueuePerProcess::output(RecordQueuePerProcess& callstack_record_queue) {
	std::pair<void*, void*> temp;
	for (auto iter = record_queue_per_process_.begin(); iter != record_queue_per_process_.end(); iter++) {
		if (record_queue_empty[iter->first] == false) {
			temp = iter->second.output(callstack_record_queue.record_queue_per_process_[iter->first]);
			if (temp.first == NULL && temp.second == NULL) {
				record_queue_empty[iter->first] = true;
				continue;
			}
			return temp;
		}
	}
	return std::pair<void*, void*>(NULL,NULL);
}

void RecordQueuePerProcess::ClearDeque() {
	size_t size = 0;
	for (auto iter = record_queue_per_process_.begin(); iter != record_queue_per_process_.end(); iter++) {
		size += iter->second.Size();
		iter->second.ClearDeque();
		//iter->second.Clear();
	}
	LoggerRecord::WriteLog(std::to_wstring(size), INFO);
}

void RecordQueuePerProcess::Clear(RecordQueuePerProcess& event_queue)
{
	for (auto iter = record_queue_per_process_.begin(); iter != record_queue_per_process_.end(); iter++) {
		if (event_queue.record_queue_per_process_.count(iter->first) == 0) {
			iter->second.Clear();
			continue;
		}
		if (iter->second.Size() > 100 && (event_queue.record_queue_per_process_[iter->first].Size() == 0)) {
			iter->second.Clear();
			continue;
		}
	}
}

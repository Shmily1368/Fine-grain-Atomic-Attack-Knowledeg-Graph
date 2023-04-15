#include "stdafx.h"
#include "record_queue.h"
#include "event_record.h"
#include "etw_configuration.h"

RecordQueue::RecordQueue()
{
}

RecordQueue::~RecordQueue()
{
}

EventRecord* RecordQueue::Pop()
{
	if (record_queue_.size() == 0) return NULL;
	EventRecord* temp = record_queue_[0];
	record_queue_.pop_front();
	return temp;
}

void RecordQueue::PushBack(EventRecord* event_record)
{
	record_queue_.push_back(event_record);
}

ULONG64 RecordQueue::Alignment(RecordQueue& another_record_queue)
{
	int i = 0;
	std::deque<EventRecord*>* temp_callstack = &(another_record_queue.record_queue_);
	int record_queque_size_ = (int)record_queue_.size();
	if (record_queque_size_ != 0 && another_record_queue.Size() != 0)
	while ((record_queque_size_ != i ) &&  (*temp_callstack)[0]->time_stamp_ != record_queue_[i]->time_stamp_) 
	{
		if (another_record_queue.record_queue_[0]->time_stamp_ > record_queue_[i]->time_stamp_) 
		{
			i++;
		}
		else 
		{
			//delete another_record_queue.Pop();
			//if (another_record_queue.Empty()) break;
			break;

		}
	}

	if (record_queue_.empty() || another_record_queue.record_queue_.empty() || record_queque_size_ == i ) 
	{
		return 0; // align failed
	}
	
	//std::cout << record_queue_[0]->time_stamp_ << "\t" << another_record_queue.record_queue_[0]->time_stamp_ << std::endl;
	return record_queue_[0]->time_stamp_;
}

bool RecordQueue::CheckAlignment(RecordQueue& callstack_record_queue) {
	if (record_queue_.empty() || callstack_record_queue.record_queue_.empty()) {
#ifdef OUTPUT_COMMAND_LINE	
		std::cout << "empty" << std::endl;
#endif // OUTPUT_COMMAND_LINE;
		return false;
	}
	if (record_queue_[0]->time_stamp_ == callstack_record_queue.record_queue_[0]->time_stamp_) {
		//std::cout << "Alignment!" << std::endl;
		return true;
	}
	else
		return false;
}

// return <NULL,NULL> when output finished!
std::pair<void*, void*> RecordQueue::output(RecordQueue& callstack_record_queue)
{
	if (record_queue_.empty() && callstack_record_queue.Empty()) {
		return std::pair<void*, void*>(NULL, NULL);
	}
	if (record_queue_.empty() && !callstack_record_queue.Empty()) {
		return std::pair<void*, void*>(NULL, callstack_record_queue.Pop());
	}

	if (callstack_record_queue.Empty() && !record_queue_.empty()) return std::pair<void*, void*>(Pop(), NULL);
	
	if (record_queue_[0]->time_stamp_ == callstack_record_queue.record_queue_[0]->time_stamp_) {
		record_queue_[0]->process_id_ = callstack_record_queue.record_queue_[0]->process_id_;
		return std::pair<void*, void*>(Pop(), callstack_record_queue.Pop());
	}
	if (record_queue_[0]->time_stamp_ < callstack_record_queue.record_queue_[0]->time_stamp_) {
		return std::pair<void*, void*>(Pop(), NULL);
	}
	else if (!record_queue_.empty()) {
		while(!callstack_record_queue.Empty() && callstack_record_queue.record_queue_[0]->time_stamp_ < record_queue_[0]->time_stamp_) {
			//delete callstack_record_queue.Pop();
			return std::pair<void*, void*>(NULL, callstack_record_queue.Pop());
		}
		if(callstack_record_queue.Empty())
			return std::pair<void*, void*>(NULL, NULL);
		if (record_queue_[0]->time_stamp_ == callstack_record_queue.record_queue_[0]->time_stamp_) {
			record_queue_[0]->process_id_ = callstack_record_queue.record_queue_[0]->process_id_;
			return std::pair<void*, void*>(Pop(), callstack_record_queue.Pop());
		}
		if (record_queue_[0]->time_stamp_ < callstack_record_queue.record_queue_[0]->time_stamp_) {
			return std::pair<void*, void*>(Pop(), NULL);
		}
	}
	return std::pair<void*, void*>(NULL, NULL);
	//if ((!callstack_record_queue.record_queue_.empty()) && IsEventwithCallStack(record_queue_[0])) {

	//	return std::pair<void*, void*>(Pop(),callstack_record_queue.Pop());
	//}
	//else {
	//	return std::pair<void*, void*>(Pop(),NULL);
	//}
}

void RecordQueue::Clear()
{
	EventRecord* temp;
	while (temp = Pop()) {
		delete temp;
	}
	record_queue_.shrink_to_fit();
}

#include "stdafx.h"
#include "task_queue_service.h"

TaskQueueService::TaskQueueService()
{

}

TaskQueueService::~TaskQueueService()
{

}

void TaskQueueService::Start()
{
	_stop_flag = false;
	_worker = std::thread(std::bind(&TaskQueueService::_Excute, this));
}

void TaskQueueService::Stop()
{
	_stop_flag = true;
	_signal.NotifyOne();
	if (_worker.joinable())
	{
		_worker.join();
	}
}

void TaskQueueService::AddTask(std::function<void()> task, std::function<void()> callback /*= nullptr*/)
{
	TaskQueueItem item;
	item.task = task;
	item.callback = callback;
	_task_queue.enqueue(item);
	_signal.NotifyOne();
}

void TaskQueueService::_Excute()
{
	TaskQueueItem item;
	while (!_stop_flag)
	{
		if (_task_queue.try_dequeue(item))
		{
			if (item.task)	item.task();
			if (item.callback)	item.callback();
		}
		else
		{
			_signal.Wait();
		}
	}
}

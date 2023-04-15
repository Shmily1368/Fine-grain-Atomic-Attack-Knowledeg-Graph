#pragma once
#include <functional>
#include "concurrentqueue.h"

struct TaskQueueItem
{
	std::function<void()> task;
	std::function<void()> callback;
};

class TaskQueueService
{
	SINGLETON_DEFINITION(TaskQueueService);
	DISABLE_COPY(TaskQueueService);

public:
	TaskQueueService();
	~TaskQueueService();

	void Start();
	void Stop();

	void AddTask(std::function<void()> task, std::function<void()> callback = nullptr);

private:
	void _Excute();

private:
	Semaphore _signal;
	moodycamel::ConcurrentQueue<TaskQueueItem> _task_queue;

	bool _stop_flag;
	std::thread _worker;
};

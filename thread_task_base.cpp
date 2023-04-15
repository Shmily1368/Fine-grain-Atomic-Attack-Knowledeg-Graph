#include "stdafx.h"
#include "thread_task_base.h"

BaseThreadTask::BaseThreadTask(EM_ThreadTaskMode mode)
	: _mode(mode)
	, _stop_flag(false)
{

}

BaseThreadTask::~BaseThreadTask(void)
{

}

void BaseThreadTask::Start()
{
	_thread = std::thread(&BaseThreadTask::_Excute, this);
	_stop_flag = false;
	//_thread.detach();
}

void BaseThreadTask::Stop()
{
	_stop_flag = true;
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void BaseThreadTask::AddData(EventRecord* record)
{
	//std<< "BaseThreadTask::AddData:warning!!Maybe ";
	delete record;
}

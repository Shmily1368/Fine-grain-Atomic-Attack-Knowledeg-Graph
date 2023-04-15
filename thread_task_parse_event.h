#pragma once
#include "thread_task_base.h"

class ParseEventThreadTask : public BaseThreadTask
{
public:
	ParseEventThreadTask();
	virtual ~ParseEventThreadTask();

	virtual void Init() override;
	virtual void Log() override;

protected:
	virtual void _Excute() override;
};

/********************************************************************
	Created:		2019-01-09
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to certificate image;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018=01-09 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
  2018-04-04 |	1.0.0	 |	xuduo		  | Optimize declaration
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"
#include "event_record.h"
#include "concurrent_queue.h"

class EventRecord;
class EventRecordImage;
class CertificateImageThreadTask : public BaseThreadTask
{
private:
	SpinLock _processing_files_lock;
	std::set<std::wstring> _processing_file_names;
	std::map<std::wstring, std::list<EventRecordImage*>> _processing_file_lists;

	Semaphore _signal;
	concurrent_queue<EventRecord*> _certificate_data_queue;

private:
	virtual void _Excute() override;

public:
	CertificateImageThreadTask();
	~CertificateImageThreadTask();
	virtual void Log() override;
	virtual void Init() override;
	virtual void Stop() override;
	virtual void AddData(EventRecord* record) override;
};
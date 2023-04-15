/********************************************************************
	Created:		2020-10-26
	Author:			zxw;
	Version:		1.0.0(version);
	Description:	thread task to get MD5;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2020-10-2 |	1.0.0	 |	zxw		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"
#include "event_record.h"
#include "concurrent_queue.h"
#include "publicstruct.h"

class EventRecord;
class EventRecordImage;
class GetHashThreadTask : public BaseThreadTask
{
private:
	Semaphore _signal;
    concurrent_queue<EventRecord*> _hash_data_queue;
    std::unordered_map<std::wstring, SFileHash> file_hash_map_;
private:
	virtual void _Excute() override;

    void GetHashfromEvent(EventRecord* ev);
    bool GetFileHash(std::wstring file_name, std::wstring& file_md5, long& file_size);
    void CleanFileHashMap();
public:
    GetHashThreadTask();
	~GetHashThreadTask();
	virtual void Log() override;
	virtual void Init() override;
	virtual void Stop() override;
	virtual void AddData(EventRecord* record) override;
};
#pragma once

#include "event_record.h"
#include "etwdata.pb.h"

using namespace ETWproto;
using namespace std;

class Output
{
public:
	Output();
	virtual ~Output();
	virtual bool OutputEventRecord(EventRecord* rec) = 0;
	virtual void DataCompress(EventRecords* rec, String* data_str) = 0;
	virtual void Clean() = 0;

	static bool schedule_monitor_flag;
};


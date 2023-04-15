#pragma once

#include "kafka_producer.h"
#include "event_record.h"
#include "etwdata.pb.h"
#include "output.h"
#include <time.h>
//#include "activemq.h"

using namespace ETWproto;

class OutputKafka : public Output
{
public:
	OutputKafka();
	bool OutputEventRecord(EventRecord* rec) override;
	void DataCompress(EventRecords* rec, String* data_str) override;
	virtual void Clean() override {};

	void OutputProtubufKafka(EventRecord*);
	void EventRecord2ProtoBuf(EventRecord* rec);
    bool OutputEventRecordCallStack(EventRecord* rec);
	//void PushEventRecord(EventRecord* rec);
	std::string outputCompress;
	//static output_Activemq;
	static const int repeat_times = 10000;
	static const int cache_threshold = 100;  //when cache count > cache_threshold,output it 
	static const int time_checkinterval = 60000;  //ms,every interval check 
	static std::unordered_map <DWORD, EventRecord *> cache_callstack;   // cache callstack between event 
	static std::unordered_map < DWORD, int> cache_count;  // count callstack length for too long length may cause memory explode
	static std::unordered_map <DWORD, time_t> last_time;  //count lastest API time, if after long time no new API generate,send data(avoid local memory increasing)
	ProducerKafka kafka_producer;

	static time_t compress_start;
	static time_t compress_current;
	//static time_t output_start;
	//static time_t output_current;
	//static bool output_flag;
	static bool compress_flag;
	time_t last_send;

	void InitKafka();

private:
	ETWproto::EventRecords* output_record;
	const ULONG64 time_threshold = time_checkinterval * (ULONG64)1000000;//ns
	const time_t compress_time_threshold = 1;
	const time_t output_time_threshold = 10;

	long long fail_count;
};



#include "stdafx.h"
#include "output_kafka.h"
#include "etwdata.pb.h"
#include <snappy/snappy.h>
#include <time.h>
#include "event_record.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "tool_functions.h"
#include "init_collector.h"
#include "setting.h"

#define STACK_TIMEINTERVAL 3000000000  

unsigned long long currentprocessevent = 0;
unsigned long long cycleprocessevent = 0;
unsigned long long sendkafkacounts = 0;
std::unordered_map <DWORD, EventRecord *> OutputKafka::cache_callstack;
std::unordered_map <DWORD, int> OutputKafka::cache_count;
std::unordered_map <DWORD, time_t> OutputKafka::last_time;
time_t OutputKafka::compress_start;
time_t OutputKafka::compress_current;
//time_t OutputKafka::output_start;
//time_t OutputKafka::output_current;
//bool OutputKafka::output_flag = false;
bool OutputKafka::compress_flag = false;

OutputKafka::OutputKafka()
{
	output_record = new ETWproto::EventRecords;
    output_record->mutable_data()->Reserve(6 * repeat_times);  
    output_record->mutable_opcode()->Reserve(repeat_times);
    output_record->mutable_processid()->Reserve(repeat_times);
    output_record->mutable_providerid()->Reserve(repeat_times);
    output_record->mutable_threadid()->Reserve(repeat_times);
    output_record->mutable_timestamp()->Reserve(repeat_times);
    output_record->mutable_callstack()->Reserve(repeat_times);

	time(&last_send);

	fail_count = 0;
	InitKafka();
}

void OutputKafka::InitKafka()
{
	LoggerRecord::WriteLog(L"InitKafka", INFO);

	kafka_producer.init_kafka();
	//StartTimer();  //start timer,used to clear cache map,since change policy in 12.8, no longer need anymore 
}

void OutputKafka::DataCompress(EventRecords* rec, String* data_str)
{
	int size = rec->ByteSize();
	snappy::Compress(rec->SerializeAsString().data(), size, data_str);
}

void OutputKafka::EventRecord2ProtoBuf(EventRecord* rec)
{
	//output_record->add_eventname(rec->event_name_);
	output_record->add_opcode(rec->event_identifier_.opcode());
	output_record->add_processid(rec->process_id_);
	output_record->add_threadid(rec->thread_id_);
	output_record->add_timestamp(rec->time_stamp_);
	output_record->add_providerid(rec->event_identifier_.provider_id());
	if (rec->event_identifier_.provider_id() == ETWStackWalk)
	{
		String temp = ((EventRecordCallstack*)rec)->GetOutputInfo();
		output_record->add_callstack(temp);
		//return;
	}
	// mod by zxw on 20191206 裁剪FileIoRead、FileIoWrite参数,前四个参数为ransom模块需要，不发送Kafka
	auto event_opcode = rec->get_event_identifier_().opcode();
	int ix = 0;
	if (rec->event_identifier_.provider_id() == ETWFileIo && (event_opcode == EM_FileioEventOPC::FileIoWirte || event_opcode == EM_FileioEventOPC::FileIoRead))
	{
		if (rec->parameter_list_.size() > 4)
			ix = 4;
	}
	for (ix; ix != rec->parameter_list_.size(); ix++)
	//for (int ix = 0; ix != rec->parameter_list_.size(); ix++)
	{	
		if (rec->parameter_list_[ix].s != L"") 
		{
			ETWproto::datad* new_arg = output_record->add_data();
			String parm;
			parm = ToolFunctions::WStringToString(rec->parameter_list_[ix].s);
			new_arg->add_s(parm);
		}
		//else if (!InitCollector::GetFlag() & ETW_Collector_Online_FullCallStack_Parse_Mode){
		else
		{
            const char* parm_name;
            parm_name = json_parameter_name_list[EventRecordManager::GetInstance().event_strucp_map[rec->event_identifier_][ix].name];
            String parameter_name(parm_name);
            if (g_parameter_string.find(parameter_name) != g_parameter_string.end())
            {                
                ETWproto::datad* new_arg = output_record->add_data();
                String parm = "";                
                new_arg->add_s(parm);
            }
            else {
                ETWproto::datad* new_arg = output_record->add_data();
                new_arg->add_d(rec->parameter_list_[ix].d);
            }		
		}
	}
}

void OutputKafka::OutputProtubufKafka(EventRecord* record) 
{
	if (schedule_monitor_flag)
	{
		if (fail_count != 0)
		{
			LoggerRecord::WriteLog(L"OutputKafka::OutputProtubufKafka fail_count is " + std::to_wstring(fail_count), LogLevel::ERR);
		}
		
		schedule_monitor_flag = false;
	}

// 	if (output_flag == false)
// 	{
// 		output_start = time(NULL);
// 		output_flag = true;
// 	}
//	output_current = time(NULL);

	++currentprocessevent;
	++cycleprocessevent;
    try
    {   
	    EventRecord2ProtoBuf(record);
	    time_t now;
	    time(&now);

	    if ((cycleprocessevent % repeat_times == 0) || difftime(now, last_send) >= 10) 
	    {
		    //clock_t st, ed;
		    //st = clock();
		    int size = output_record->ByteSize();
		    snappy::Compress(output_record->SerializeAsString().data(), size, &outputCompress);
		    //ed = clock();
            if (kafka_producer.push_data_to_kafka(outputCompress.data(), outputCompress.size()) == -1) {
                fail_count++;
            }
            // add by zxw on 20200519
            output_record->Clear();
            sendkafkacounts++;
            if (sendkafkacounts > 100)
            {
                sendkafkacounts = 0;
                if (output_record)
                    delete output_record;
                output_record = new ETWproto::EventRecords;
                output_record->mutable_data()->Reserve(6 * repeat_times);
                //output_record->mutable_eventname()->Reserve(repeat_times);
                output_record->mutable_opcode()->Reserve(repeat_times);
                output_record->mutable_processid()->Reserve(repeat_times);
                output_record->mutable_providerid()->Reserve(repeat_times);
                output_record->mutable_threadid()->Reserve(repeat_times);
                output_record->mutable_timestamp()->Reserve(repeat_times);
                output_record->mutable_callstack()->Reserve(repeat_times);
            }       
		
		    //ParseData::Activemq.output(outputCompress);
    #ifdef OUTPUT_COMMAND_LINE       
		    std::cout << std::endl;
		    std::cout << ToolFunctions::getTime() << std::endl;
		    //std::cout << std::dec << currentprocessevent << " time: " << ed - st << std::endl;
		    std::cout << "all process:" << currentprocessevent << ":" <<
			    cycleprocessevent << std::endl;
		    std::cout << std::endl;
		    //std::cout << record->process_id_ << ' ' << record->thread_id_ << std::endl;
    #endif // OUTPUT_COMMAND_LINE;
		    time(&last_send);
		    cycleprocessevent = 0;
	    }
    }
    catch (...) {
        LoggerRecord::WriteLog(L"OutputKafka::OutputProtubufKafka catch execption " + std::to_wstring(GetLastError()), LogLevel::ERR);
    }
}

bool OutputKafka::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return false;
	// add by zxw on 20191128 裁剪无用的事件
	if (rec->isUseless())
		return true;

	bool delete_flag = true;

    if (Setting::GetInstance().local_detector_parse())
	{
        OutputProtubufKafka(rec);        
    }
    else {
        delete_flag = OutputEventRecordCallStack(rec);
    }
	
	return delete_flag;
}

bool OutputKafka::OutputEventRecordCallStack(EventRecord * rec) 
{
    bool delete_flag = true;

    if (compress_flag == false) {
        compress_start = time(NULL);
        compress_flag = true;
    }
    compress_current = time(NULL);
    if (compress_current - compress_start >= compress_time_threshold) {
        for (auto iter = last_time.begin(); iter != last_time.end();) {
            DWORD thread_id_temp = iter->first;
            if (compress_current - iter->second > compress_time_threshold) {
                EventRecord * item_temp = cache_callstack[thread_id_temp];
                OutputProtubufKafka(item_temp);
                cache_callstack.erase(thread_id_temp);
                iter = last_time.erase(iter);
                cache_count[thread_id_temp] = 0;
                EventRecordManager::GetInstance().RecycleEventRecord(item_temp);
            }
            else {
                iter++;
            }
        }
        compress_flag = false;
    }


    if (rec->get_event_identifier_().provider_id() == ETWStackWalk) {
        DWORD thread_id = rec->thread_id_;

        //merge duplicate data in the same thread_id
        if (cache_callstack.find(thread_id) != cache_callstack.end()) {
            EventRecord* item = cache_callstack[thread_id];
            item->callstack_ += std::string(",") + rec->callstack_;
            last_time[thread_id] = compress_current;
            if (++cache_count[thread_id] >= cache_threshold) {
                // if thread callstack amount < 100,may will cause API missing; add timer to solve problem 
                OutputProtubufKafka(item);
                cache_callstack.erase(thread_id);
                cache_count[thread_id] = 0;
                last_time.erase(thread_id);
                EventRecordManager::GetInstance().RecycleEventRecord(item);
            }
        }
        else {
            cache_callstack[thread_id] = rec;
            cache_count[thread_id] = 1;
            last_time[thread_id] = compress_current;
            delete_flag = false;
        }
    }
    else {
        OutputProtubufKafka(rec);
    }

    return delete_flag;
}
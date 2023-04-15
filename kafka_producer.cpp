#include "stdafx.h"
#include <ctype.h>    
#include <signal.h>    
#include <string>    
#include <stdlib.h>    
#include <time.h>    
#include <errno.h>    

#include "rdkafka.h" 
#include "kafka_producer.h"
#include "setting.h"
#include "tool_functions.h"

#pragma warning( disable: 4996 )

const int PRODUCER_INIT_FAILED = -1;
const int PRODUCER_INIT_SUCCESS = 0;
const int PUSH_DATA_FAILED = -1;
const int PUSH_DATA_SUCCESS = 0;

static void push_data_cb(rd_kafka_t* rk, const rd_kafka_message_t* rk_msg, void* opaque)
{
	if (rk_msg->err)
	{
		LoggerRecord::WriteLog(L"push_data_cb: failed, " + ToolFunctions::StringToWString(rd_kafka_err2str(rk_msg->err)), LogLevel::ERR);
	}
}


ProducerKafka::ProducerKafka()
{
	ip_port = "127.0.0.1:9092";
	topic = "MARPLE";
	partition_ = 0;
}

static void logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
	time_t st;
	struct tm*  current_time;
	time(&st);
	current_time = localtime(&st);
	fprintf(stderr, "%d %d %d %d %d %d\n",current_time->tm_year,current_time->tm_mon,current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec);
	fprintf(stderr, "RDKAFKA-%i-%s: %s: %s\n",
		level, fac, rk ? rd_kafka_name(rk) : NULL, buf);
	fprintf(stderr,"");
}


int ProducerKafka::init_kafka()
{
// 	ip_port = Setting::GetInstance().GetString("kafka_address");
// 	topic = Setting::GetInstance().GetString("kafka_data_tunnel_topic");
// 	partition_ = Setting::GetInstance().GetInt("kafka_partition");
	ip_port = Setting::GetInstance().kafka_address();
   
	topic = Setting::GetInstance().kafka_topic();
	partition_ = Setting::GetInstance().kafka_partition();

	char tmp[16] = { 0 };
	char errstr[512] = { 0 };

	//partition_ = partition;

	/* Kafka configuration */
	conf_ = rd_kafka_conf_new();
    LoggerRecord::WriteLog(L"ProducerKafka::init_kafka rd_kafka_conf_new " + ToolFunctions::StringToWString(ip_port), DEBUG);
	//set logger :register log function    
	rd_kafka_conf_set_log_cb(conf_, logger);

	/* Quick termination */
	//snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(conf_, "internal.termination.signal", tmp, NULL, 0);
	rd_kafka_conf_set(conf_, "message.max.bytes", "10000000" , NULL, 0); //单条消息的最大长度
	rd_kafka_conf_set(conf_, "log.segment.bytes", "1GB", NULL, 0); //kafka数据文件的大小;
	rd_kafka_conf_set(conf_, "replica.fetch.max.bytes", "10MB", NULL, 0); //每个分区指令的内存空间;

    // add by zxw on 20200908
    rd_kafka_conf_set(conf_, "security.protocol", "sasl_plaintext", errstr, sizeof(errstr));
    rd_kafka_conf_set(conf_, "sasl.mechanisms", "PLAIN", errstr, sizeof(errstr));
//     rd_kafka_conf_set(conf_, "sasl.username", "client", errstr, sizeof(errstr));
//     rd_kafka_conf_set(conf_, "sasl.password", "lwcenfzjoeozdfyl", errstr, sizeof(errstr));
    rd_kafka_conf_set(conf_, "sasl.username", Setting::GetInstance().kafka_user_name().c_str(), errstr, sizeof(errstr));
    rd_kafka_conf_set(conf_, "sasl.password", Setting::GetInstance().kafka_password().c_str(), errstr, sizeof(errstr));

	rd_kafka_conf_set_dr_msg_cb(conf_, push_data_cb);
	//log.retention.bytes && log.retention.minutes 大小和时间满足一个就会丢弃数据;
	//log.retention.minutes default == 168h && log.retention.bytes default == -1

	/*topic configuration*/
	topic_conf_ = rd_kafka_topic_conf_new();
    LoggerRecord::WriteLog(L"ProducerKafka::init_kafka rd_kafka_topic_conf_new", DEBUG);
	if (!(handler_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf_, errstr, sizeof(errstr))))
	{
        LoggerRecord::WriteLog(L"ProducerKafka::init_kafka Failed to create new producer ERR: " + to_wstring(GetLastError()), ERR);
		fprintf(stderr, "*****Failed to create new producer: %s*******\n", errstr);
		return PRODUCER_INIT_FAILED;
	}
    LoggerRecord::WriteLog(L"ProducerKafka::init_kafka rd_kafka_new", DEBUG);
	rd_kafka_set_log_level(handler_, 0);

	/* Add brokers */
	if (rd_kafka_brokers_add(handler_, ip_port.c_str()) == 0)
	{
        LoggerRecord::WriteLog(L"ProducerKafka::init_kafka no valid brokers specified ERR: " + to_wstring(GetLastError()), ERR);
		fprintf(stderr, "****** No valid brokers specified********\n");
		return PRODUCER_INIT_FAILED;
	}
    LoggerRecord::WriteLog(L"ProducerKafka::init_kafka rd_kafka_brokers_add", DEBUG);

	/* Create topic */
	topic_ = rd_kafka_topic_new(handler_, topic.c_str(), topic_conf_);

    LoggerRecord::WriteLog(L"ProducerKafka::init_kafka succeed", INFO);
	return PRODUCER_INIT_SUCCESS;
}

void ProducerKafka::destroy()
{
	/* Destroy topic */
	rd_kafka_topic_destroy(topic_);

	/* Destroy the handle */
	rd_kafka_destroy(handler_);
}

int ProducerKafka::push_data_to_kafka(const char* buffer, const size_t buf_len)
{
	int ret;
	char errstr[512] = { 0 };

	if (NULL == buffer)
		return 0;

	ret = rd_kafka_produce(topic_, partition_, RD_KAFKA_MSG_F_COPY,
		(void*)buffer, buf_len, NULL, 0, NULL);

	if (ret == -1)
	{
		fprintf(stderr, "****Failed to produce to topic %s partition %i: %s*****\n",
			rd_kafka_topic_name(topic_), partition_,
			rd_kafka_err2str(rd_kafka_errno2err(errno)));

		rd_kafka_poll(handler_, 0);
		return PUSH_DATA_FAILED;
	}

	fprintf(stderr, "***Sent %d bytes to topic:%s partition:%i*****\n",
		(int)buf_len, rd_kafka_topic_name(topic_), partition_);

	rd_kafka_poll(handler_, 0);

	return PUSH_DATA_SUCCESS;
}

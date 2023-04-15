#pragma once
#include "rdkafka.h"
#include <string>
class ProducerKafka
{
public:
	ProducerKafka();
	~ProducerKafka(){ destroy(); };

	int init_kafka();
	int push_data_to_kafka(const char* buf, const size_t buf_len);
	void destroy();
	//void ProducerKafkaInit();

private:
	int partition_ = 0;
	std::string ip_port;
	std::string topic;
	//rd    
	rd_kafka_t* handler_;
	rd_kafka_conf_t *conf_;

	//topic    
	rd_kafka_topic_t *topic_;
	rd_kafka_topic_conf_t *topic_conf_;
};


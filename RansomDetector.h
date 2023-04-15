#pragma once
#include <Windows.h>
#include "event.h"

#define ITEMREPOSITORYSIZE   100000

struct ItemRepository   //may need change to queue later 
{
	event event_buffer[ITEMREPOSITORYSIZE]; // 产品缓冲区, 配合 read_position 和 write_position 模型环形队列.
	size_t read_position;
	size_t write_position;
	std::mutex event_mtx;                    // 互斥量,保护产品缓冲区
	std::condition_variable repo_not_full;   // 条件变量, 指示产品缓冲区不为满.
	std::condition_variable repo_not_empty;  // 条件变量, 指示产品缓冲区不为空.
};  // 产品库全局变量, 生产者和消费者操作该变量.


typedef struct ItemRepository ItemRepository;


class RansomDetector
{
	SINGLETON_DEFINITION(RansomDetector);
	DISABLE_COPY(RansomDetector);

public:
	RansomDetector();
	~RansomDetector();

	int Init(void);
	void PushRansomRecord(String &input);   //May Suspend
	// add by zxw on 20191114
	void PushRansomRecord(event item);
	//String ParseApi(ULONG64 address);

private:
	//bool _LoadSymbol(const String& system_file_path, const String& symbol_file_name, DWORD image_base);
	ItemRepository gItemRepository;
	void ConsumerTask();
	void ConsumeItem(ItemRepository *ir);
	int _push_count;
	std::mutex unit_lock;
	std::mutex out_lock;
	//void ProducerTask();
	//std::unordered_map<DWORD, String> _address_api_map;
};
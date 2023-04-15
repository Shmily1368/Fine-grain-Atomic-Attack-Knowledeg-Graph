#pragma once

#include "process_info.h"
#include "json_include/rapidjson/document.h"
#include "concurrentqueue.h"

#include <thread>

//#define  PIPE_Name 

class NamedPipeClient
{
	SINGLETON_DEFINITION(NamedPipeClient);

public:
	NamedPipeClient();
	~NamedPipeClient();

	//create
	void InitPipe();
	//read
	bool ReadPipe(char** buf);
	//write
	void WritePipe(const ProcessInfoItem& item);
	void WritePipe(const rapidjson::Document& json);

	std::string TransClassToString(const ProcessInfoItem& item);

private:
	void _ConnectPipe();
	void _ClosePipe();
	void _PushData(const String& data);
	void _WriteDataToPipe();

private:
	Mutex _lock;
	moodycamel::ConcurrentQueue<String> _data_queue;
    bool _swap_flag = false;
	bool _stop_flag;
	std::thread _worker;

	HANDLE named_pipe_write;
	HANDLE named_pipe_read;
	//std::string  send_content;
	std::wstring pipe_name_write;
	std::wstring pipe_name_read;
};

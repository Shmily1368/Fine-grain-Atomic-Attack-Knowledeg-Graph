#include "stdafx.h"
#include <fstream>
#include "named_pipe_client.h"
#include "tool_functions.h"
#include "json_include/rapidjson/writer.h"
#include "json_include/rapidjson/stringbuffer.h"
#include <sstream>
#include <atlbase.h>
#include <atlconv.h>
#include "setting.h"

#define PIPE_HEAD_LEN			       8

NamedPipeClient::NamedPipeClient()
{
	pipe_name_write = L"\\\\.\\pipe\\PidInfoPipe";
	pipe_name_read = L"\\\\.\\pipe\\HealthCheckPipe";
}

NamedPipeClient::~NamedPipeClient()
{
	_ClosePipe();

	_stop_flag = true;
	if (_worker.joinable())
	{
		_worker.join();
	}
}

void NamedPipeClient::InitPipe()
{
	_ConnectPipe();

	_stop_flag = false;
	_worker = std::thread(std::bind(&NamedPipeClient::_WriteDataToPipe, this));
}

bool NamedPipeClient::ReadPipe(char** buf)
{
	DWORD peek_size = 0;
	if (!PeekNamedPipe(named_pipe_read, NULL, 0, NULL, &peek_size, NULL) || peek_size == 0)
	{
		return false;
	}

	char* read_len = new char[PIPE_HEAD_LEN];
	DWORD dw_read;

	memset(read_len, '\0', PIPE_HEAD_LEN);
	if (!ReadFile(named_pipe_read, read_len, PIPE_HEAD_LEN, &dw_read, NULL) || dw_read != PIPE_HEAD_LEN)
	{
		delete[] read_len;
		return false;
	}

	std::string buf_len_str(read_len, PIPE_HEAD_LEN);
	delete[] read_len;
	int buf_len = atoi(buf_len_str.c_str());
    // mod by zxw on 20201023
	char* read_buf = new char[buf_len+1];
    if (!read_buf) {
        LoggerRecord::WriteLog(L"NamedPipeClient::ReadPipe: new read_buf failed, errcode = " + std::to_wstring(GetLastError()), LogLevel::ERR);
        return false;
    }
       
	memset(read_buf, '\0', buf_len+1);
	if (!ReadFile(named_pipe_read, read_buf, buf_len, &dw_read, NULL))
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "NamePipeServer::NamedPipeReadInServer: error in get written buf" << endl << endl;
#endif // OUTPUT_COMMAND_LINE;
		delete[] read_buf;
		return false;
	}

	*buf = read_buf;
	return true;
}

void NamedPipeClient::WritePipe(const ProcessInfoItem& item)
{
    // add by zxw on 20210111 注释pipe通信
    return;
	AutoLock lock(_lock);

	//class  to json 
	std::string json_str = TransClassToString(item);
	size_t length = strlen(json_str.c_str()) + 1;
	std::string length_str = std::to_string(length);
	while (length_str.length() < PIPE_HEAD_LEN)
	{
		length_str = std::string("0") + length_str;
	}

	json_str = length_str + json_str;
	_PushData(json_str);
}

void NamedPipeClient::WritePipe(const rapidjson::Document& json)
{
    // add by zxw on 20210111 去除pipe通信发送
    return;
	if (!named_pipe_write)	return;
	AutoLock lock(_lock);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	json.Accept(writer);
	std::string json_str = buffer.GetString();

	size_t length = strlen(json_str.c_str()) + 1;
	std::string length_str = std::to_string(length);
	while (length_str.length() < PIPE_HEAD_LEN)
	{
		length_str = std::string("0") + length_str;
	}

	json_str = length_str + json_str;
	_PushData(json_str);
}

std::string NamedPipeClient::TransClassToString(const ProcessInfoItem& item)
{
	rapidjson::Document record_document;
	rapidjson::Document::AllocatorType& doc_allocator = record_document.GetAllocator();
	rapidjson::Value rec_doc_root(rapidjson::kObjectType);
	rec_doc_root.AddMember("processID", long(item.process_id_), doc_allocator);

	rapidjson::Value uint;
	uint.SetUint64(item.timestamp_);
	rec_doc_root.AddMember("TimeStamp", uint, doc_allocator);

	rec_doc_root.AddMember("parentID", long(item.parent_id_), doc_allocator);

	string parm;
	parm = ToolFunctions::WStringToString(item.file_name_);
	rapidjson::Value str_val1;
	str_val1.SetString(parm.c_str(), (rapidjson::SizeType)parm.length(), doc_allocator);
	rec_doc_root.AddMember("fileName", str_val1, doc_allocator);

	parm = ToolFunctions::WStringToString(item.file_path_);
	rapidjson::Value str_val2;
	str_val2.SetString(parm.c_str(), (rapidjson::SizeType)parm.length(), doc_allocator);
	rec_doc_root.AddMember("filePath", str_val2, doc_allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	rec_doc_root.Accept(writer);
	std::string rec_json = buffer.GetString();

	return rec_json;
}

void NamedPipeClient::_ConnectPipe()
{
	while (!WaitNamedPipe(pipe_name_write.c_str(), NMPWAIT_WAIT_FOREVER))
	{
		Sleep(100);
	}

	named_pipe_write = CreateFile(pipe_name_write.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == named_pipe_write)
	{
		LoggerRecord::WriteLog(L"NamedPipeClient::InitPipe: open pipe failed, err code = " + std::to_wstring(GetLastError()), LogLevel::ERR);
		return;
	}

	while (!WaitNamedPipe(pipe_name_read.c_str(), NMPWAIT_WAIT_FOREVER))
	{
		Sleep(100);
	}

	named_pipe_read = CreateFile(pipe_name_read.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == named_pipe_read)
	{
		LoggerRecord::WriteLog(L"NamedPipeClient::InitPipe: open pipe failed, err code = " + std::to_wstring(GetLastError()), LogLevel::ERR);
		return;
	}
}

void NamedPipeClient::_ClosePipe()
{
	CloseHandle(named_pipe_write);
	CloseHandle(named_pipe_read);
}

void NamedPipeClient::_PushData(const String& data)
{
    auto data_size = _data_queue.size_approx();
    if (data_size >= 200)
        _swap_flag = true;
    if (Setting::GetInstance().enable_honey_pot())
    {
        if (data_size >= 1000) {           
            LoggerRecord::WriteLog(L"NamedPipeClient::_PushData: data queue full", ERR);
            return;
        }
    }
    else {
        if (data_size >= 200) {
            LoggerRecord::WriteLog(L"NamedPipeClient::_PushData: data queue full", ERR);
            return;
        }
    }	

    if (_swap_flag && data_size == 0)
    {
        _swap_flag = false;
        moodycamel::ConcurrentQueue<String>().swap(_data_queue);
    }

	//LoggerRecord::WriteLog(L"NamedPipeClient::_PushData: size = " + std::to_wstring(_data_queue.size_approx()), LogLevel::ERR);
	_data_queue.enqueue(data);
}

void NamedPipeClient::_WriteDataToPipe()
{
	bool reconnect_flag = false;
	while (!_stop_flag)
	{
		if (reconnect_flag)
		{
			_ClosePipe();
			_ConnectPipe();
		}

		String data;
		if (_data_queue.try_dequeue(data))
		{
			int_64 begin_t = ToolFunctions::GetUnixTimestamp64();
			DWORD dw_write = 0;
			if (!WriteFile(named_pipe_write, data.c_str(), (DWORD)(data.size() + 1), &dw_write, NULL))
			{
				LoggerRecord::WriteLog(L"NamePipeServer::_WriteDataToPipe: write failed, err code = " + std::to_wstring(GetLastError()), LogLevel::ERR);
				reconnect_flag = true;
				continue;
			}
			int_64 cost_t = ToolFunctions::GetUnixTimestamp64() - begin_t;
			if (cost_t >= 500)
			{
				LoggerRecord::WriteLog(L"NamePipeServer::_WriteDataToPipe: write pipe cost time = " + std::to_wstring(cost_t), LogLevel::ERR);
			}
		}
		else
		{
			Sleep(200);
		}
	}
}


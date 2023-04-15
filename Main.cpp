/********************************************************************
	Created:		2019-01-03
	Author:			chips;
	Version:		1.0.1(版本号);
	Description:	初始化项目;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/04/09 |	0.1.0	 |	zhenyuan	  | Create file
----------------------------------------------------------------------------
  2019/01/03 |	1.0.0	 |	chips		  | initLoggerRecord && initSetting && initCollector
----------------------------------------------------------------------------
*********************************************************************/
#pragma comment( lib, "Dbghelp.lib" )

#include "stdafx.h"
#include "setting.h"
#include "tool_functions.h"
#include "init_collector.h"
#include "init_collector_factory.h"
#include "obtain_entry_address.h"
#include "etw_configuration.h"
#include "task_queue_service.h"

#include <Windows.h>
#include <DbgHelp.h>
#include <chrono>
#include <iomanip>

using namespace std;

void DumpMiniDump(HANDLE dump_handle, PEXCEPTION_POINTERS exception_p)
{
    if (exception_p == NULL) //如果没有传入异常, 比如是在程序里面调用的, 生成一个异常
    {
        // Generate exception to get proper context in dump
        __try {
            OutputDebugString(_T("raising exception\r\n"));
            RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
        }
        __except (DumpMiniDump(dump_handle, GetExceptionInformation()),
            EXCEPTION_CONTINUE_EXECUTION) {
        }
    }
    else {
        // Dump信息  
        MINIDUMP_EXCEPTION_INFORMATION dump_info;
        dump_info.ExceptionPointers = exception_p;
        dump_info.ThreadId = GetCurrentThreadId();
        dump_info.ClientPointers = TRUE;

        // 写入Dump文件内容  
        MINIDUMP_TYPE dump_type = MiniDumpNormal;
        if (Setting::GetInstance().enable_maximum_dump()) {
            dump_type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithThreadInfo);
        }
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dump_handle, dump_type, &dump_info, NULL, NULL);
    }
}
void CreateDumpFile(LPCWSTR dump_file_path, EXCEPTION_POINTERS* exception_p)
{
	// 创建Dump文件  
	HANDLE dump_handle = CreateFile(dump_file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dump_handle == INVALID_HANDLE_VALUE) return ;

    DumpMiniDump(dump_handle, exception_p);

	CloseHandle(dump_handle);
}

LONG CrashHandler(EXCEPTION_POINTERS *pException) 
{
	// add by zxw on 20191107 添加空指针保护
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->StopETWSession();

	WCHAR current_path[MAX_PATH] = { 0 };
	GetCurrentDirectory(sizeof(current_path), current_path);
	std::wstring dump_file_path = std::wstring(current_path) + _T("\\collector_") + ToolFunctions::GetPresentTime() + _T(".dmp");
	CreateDumpFile(dump_file_path.data(), pException);

	return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char *argv[]) 
{
    auto modulePath = ToolFunctions::GetModuleDirectory();
    if (SetCurrentDirectory(modulePath.c_str()))
    {
        std::wcout << ToolFunctions::GetPresentTime() << L": SetCurrentDirectory " << modulePath << std::endl;
    }
    
	//init log
	std::wcout << ToolFunctions::GetPresentTime() << L": init logger" << std::endl;   
	LoggerRecord::InitLoggerRecord();

	//init setting;
	std::wcout << ToolFunctions::GetPresentTime() << L": init setting" << std::endl;
	Setting::GetInstance().Init(argc, argv);

	//init task queue service;
	std::wcout << ToolFunctions::GetPresentTime() << L": init task queue service" << std::endl;
	TaskQueueService::GetInstance().Start();

	//add error handle for debug, will delete it when release;
	std::wcout << ToolFunctions::GetPresentTime() << L": init crash handler" << std::endl;
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)CrashHandler);

	//init collector
	std::wcout << ToolFunctions::GetPresentTime() << L": init collector" << std::endl;
	InitCollectorFactory factory;
	factory.Create();

	if (InitCollector::GetCollector())
	{
		//collector action
		InitCollector::GetCollector()->Init();
        // add by zxw on 20200724 start one sec later waite init over
        Sleep(1000);
		InitCollector::GetCollector()->Excute();
		InitCollector::GetCollector()->Clean();
	}
	else 
	{
		//LoggerRecord::WriteLog(L"init fail, setting mode is " + Setting::GetInstance().GetChar("mode"), INFO);
		LoggerRecord::WriteLog(L"init fail, setting mode = " + Setting::GetInstance().collector_mode(), LogLevel::ERR);
	}

	factory.Recycle();

	TaskQueueService::GetInstance().Stop();
	
	return 0;
}

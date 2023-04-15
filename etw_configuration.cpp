#include "stdafx.h"
#include "etw_configuration.h"

#include <windows.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <time.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <in6addr.h>
#include <conio.h>
#include <strsafe.h>

#include <fstream>
#include <sstream>
#include <stdio.h>

#include "setting.h"
#include "tool_functions.h"

using namespace std;

std::set<int> ETWConfiguration::enable_stack_events_set_;
bool g_exit = false; //whether exit for offline collect Mode

ETWConfiguration::ETWConfiguration()
{
	Preemption();

	_low_mode = false;

	do 
	{
		if (!Setting::GetInstance().enable_hardware_adjustment())	break;

		String cpu_name;
		if (!ToolFunctions::GetCpuName(cpu_name) || cpu_name.find("Intel") == String::npos)
		{
			break;
		}

		STRING_VECTOR cpu_info;
		StringUtil::split(cpu_name, ' ', cpu_info);
		if (cpu_info.size() < 3)
		{
			break;
		}

		String cpu_model = StringUtil::ToLowerCase(cpu_info[2]);
		if (!StringUtil::IsStartWith(cpu_model, "i", true))
		{
			break;
		}

		if (cpu_model.find("m") != String::npos)
		{
			_low_mode = true;
			break;
		}

		if (StringUtil::IsStartWith(cpu_model, "i3", true))
		{
			_low_mode = true;
			break;
		}

		if (StringUtil::IsStartWith(cpu_model, "i5", true) && (cpu_model.find("u") != String::npos || cpu_model.find("u") != String::npos))
		{
			_low_mode = true;
			break;
		}

	} while (0);

	LoggerRecord::WriteLog(L"ETWConfiguration::ETWConfiguration: low_mode = " + std::to_wstring(_low_mode), LogLevel::WARN);

    // mod by zxw on20200415 honey pot open registry
    if (Setting::GetInstance().enable_honey_pot())
    {
        enable_flag_ = 0
            | EVENT_TRACE_FLAG_CSWITCH          // context switches
            | EVENT_TRACE_FLAG_IMAGE_LOAD		// image load
            | EVENT_TRACE_FLAG_FILE_IO_INIT
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_DISK_FILE_IO     // requires disk IO
            | EVENT_TRACE_FLAG_DISK_IO
            //| EVENT_TRACE_FLAG_FILE_IO          // file IO
            | EVENT_TRACE_FLAG_PROCESS			// process start & end
            | EVENT_TRACE_FLAG_THREAD			// thread start & end

            //local detector lcs dont need
            | EVENT_TRACE_FLAG_REGISTRY         // registry calls
            //| EVENT_TRACE_FLAG_ALPC             // ALPC traces
            //| EVENT_TRACE_FLAG_DISK_IO          // physical disk IO
            //| EVENT_TRACE_FLAG_DISK_IO_INIT     // physical disk IO initiation
            ;
    }
    else
    {
        enable_flag_ = 0
            | EVENT_TRACE_FLAG_CSWITCH          // context switches
            | EVENT_TRACE_FLAG_IMAGE_LOAD		// image load
            | EVENT_TRACE_FLAG_FILE_IO_INIT
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_DISK_FILE_IO     // requires disk IO
            | EVENT_TRACE_FLAG_DISK_IO
            //| EVENT_TRACE_FLAG_FILE_IO          // file IO
            | EVENT_TRACE_FLAG_PROCESS			// process start & end
            | EVENT_TRACE_FLAG_THREAD			// thread start & end

            //local detector lcs dont need
            | EVENT_TRACE_FLAG_REGISTRY         // registry calls
            //| EVENT_TRACE_FLAG_ALPC             // ALPC traces
            //| EVENT_TRACE_FLAG_DISK_IO          // physical disk IO
            //| EVENT_TRACE_FLAG_DISK_IO_INIT     // physical disk IO initiation
            ;
    }

	if (!_low_mode)	enable_flag_ |= EVENT_TRACE_FLAG_SYSTEMCALL;       // system calls

	//string temp = Setting::GetInstance().GetString("offline_log_file");
	logfile_path_ = ToolFunctions::StringToWString(Setting::GetInstance().offline_log_file());
}

ETWConfiguration::~ETWConfiguration()
{
	Preemption();
}


bool ctrlHandler(DWORD dCtrlType)
{
	switch (dCtrlType)
	{
	case CTRL_C_EVENT:
		g_exit = true;
		return false;

	default:
		return false;
	}
}

void ETWConfiguration::SetTraceProperties(EVENT_TRACE_PROPERTIES * pSessionProperties, ULONG BufferSize, bool is_real_time)
{
    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
                                                 //	pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
    pSessionProperties->EnableFlags = enable_flag_;

    if (is_real_time)
    {
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->LogFileNameOffset = 0;
    }
    else
    {
        pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
        StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), (logfile_path_.length() + 1) * 2, logfile_path_.c_str());
    }
    pSessionProperties->MaximumBuffers = 200;
    pSessionProperties->BufferSize = 1024;

}

int ETWConfiguration::ConfigureEtwSession(bool is_real_time, void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE SessionHandle = 0;
	EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
	ULONG BufferSize = 0;

	// Allocate memory for the session properties. The memory must
	// be large enough to include the log file name and session name,
	// which get appended to the end of the session properties structure.

	BufferSize = sizeof(EVENT_TRACE_PROPERTIES)
		+ sizeof(KERNEL_LOGGER_NAME);

	if (!is_real_time) 
	{
		BufferSize += (ULONG)((logfile_path_.length() + 1) * 2);
	}

	pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
	if (NULL == pSessionProperties)
	{
		wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
		return -1;
	}

	// Set the session properties. You only append the log file name
	// to the properties structure; the StartTrace function appends
	// the session name for you.
    SetTraceProperties(pSessionProperties, BufferSize, is_real_time);
	// Create the trace session.

	status = StartTrace((PTRACEHANDLE)&SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties);

	if (ERROR_SUCCESS != status)
	{
		if (ERROR_ALREADY_EXISTS == status)
		{
            status = ::ControlTrace((TRACEHANDLE)NULL, KERNEL_LOGGER_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(status))
            {
                SetTraceProperties(pSessionProperties, BufferSize, is_real_time);
                status = ::StartTrace((PTRACEHANDLE)&SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties);
                if (ERROR_SUCCESS != status)
                {
                    LoggerRecord::WriteLog(L"ETWConfiguration::ConfigureEtwSession StartTrace failed, err = " + std::to_wstring(status), LogLevel::ERR);
                    return -1;
                }
            }
            else
            {
                LoggerRecord::WriteLog(L"ETWConfiguration::ConfigureEtwSession ControlTrace failed, err = " + std::to_wstring(status), LogLevel::ERR);
                return -1;
            }
		}
		else
		{
            LoggerRecord::WriteLog(L"ETWConfiguration::ConfigureEtwSession StartTrace failed, status err = " + std::to_wstring(status), LogLevel::ERR);
            wprintf(L"EnableTrace() failed with %lu\n", status);
            return -1;
		}
	}


	SessionHandle_ = SessionHandle;
	pSessionProperties_ = pSessionProperties;

	if (enable_stack_events_.size() != 0) 
	{
		SetupEventStackwalk();
	}

	if (is_real_time) 
	{
		SetupEventConsumer(consum_event_realtime);
	}
	else 
	{
		//add by jiehao.meng 2018/10/24 ctrl+c to exit; for offline collect mode 
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctrlHandler, true);
		while (!g_exit)
		{
			Sleep(10);
		}
	}

	return 0;

}

ULONG ETWConfiguration::StopEtwSession()
{
	if (SessionHandle_ != 0 && pSessionProperties_ != NULL)
	{
		return StopTrace(SessionHandle_, KERNEL_LOGGER_NAME, pSessionProperties_);
	}
	
	return ERROR_SUCCESS;
}

void ETWConfiguration::SetupEventConsumer(void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	EVENT_TRACE_LOGFILE event_logfile;
	TRACE_LOGFILE_HEADER* event_logfile_header;
	TRACEHANDLE event_logfile_handle;
	BOOL event_usermode = FALSE;


	event_logfile_header = &event_logfile.LogfileHeader;
	ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
	event_logfile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;

	// consum_event() is the callback function. should be writed in this class.
	// If everything go well, the program will be block here.
	event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event_realtime);

	event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
	event_logfile_handle = OpenTrace(&event_logfile);
	if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle)
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
	}

	event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
	if (event_logfile_header->PointerSize != sizeof(PVOID))
	{
		event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
			2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
	}
    // add by zxw on 20201229
    auto eventmonitor_worker = std::thread(std::bind(&ETWConfiguration::_EventMonitorExec, this));
    eventmonitor_worker.detach();
    //
	TDHSTATUS temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);
	if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", temp_status);
		goto cleanup;
	}

cleanup:
	if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle)
	{
		temp_status = CloseTrace(event_logfile_handle);
	}
}

inline void ETWConfiguration::SetupEventStackwalk()
{
	TRACE_INFO_CLASS information_class = TraceStackTracingInfo;
	TraceSetInformation(SessionHandle_, information_class, &enable_stack_events_[0], (ULONG)(enable_stack_events_.size() * sizeof(CLASSIC_EVENT_ID)));
	return;
}

void ETWConfiguration::SetEnableStackEvents(std::vector<CLASSIC_EVENT_ID> enable_stack_events)
{
	if (_low_mode)	return;

	enable_stack_events_ = enable_stack_events;
	for (auto iter = enable_stack_events.begin(); iter != enable_stack_events.end(); iter++)
	{
		enable_stack_events_set_.insert(iter->EventGuid.Data1 + iter->Type);
	}
}

void ETWConfiguration::_EventMonitorExec() 
{
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
    ULONG BufferSize = 0;

    BufferSize = sizeof(EVENT_TRACE_PROPERTIES)
        + sizeof(KERNEL_LOGGER_NAME);

    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
    if (NULL == pSessionProperties) {
        LoggerRecord::WriteLog(L"Unable to allocate bytes for properties structure. size:" + std::to_wstring(BufferSize), LogLevel::ERR);    
        return;
    }
    SetTraceProperties(pSessionProperties, BufferSize, true);
    while (true) {
        Sleep(10000);
        auto status = ::ControlTrace((TRACEHANDLE)NULL, KERNEL_LOGGER_NAME, pSessionProperties, EVENT_TRACE_CONTROL_QUERY);
        if (ERROR_SUCCESS == status) {
            if (pSessionProperties->EnableFlags != enable_flag_)
            {
                LoggerRecord::WriteLog(L"EnableFlags is changed:" + std::to_wstring(pSessionProperties->EnableFlags), LogLevel::WARN);
                StopEtwSession();
                break;
            }
        }
        Sleep(10000);
    }   
}

void ETWConfiguration::ConsumeLogFile(void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	TDHSTATUS status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	TRACEHANDLE g_hTrace;
	BOOL g_bUserMode = FALSE;

	// Identify the log file from which you want to consume events
	// and the callbacks used to process the events and buffers.
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));

	//consume data from logfile
	trace.LogFileName = (LPWSTR)logfile_path_.c_str();
	wcout << (LPWSTR)logfile_path_.c_str() << endl;
	trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event_realtime);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;


	g_hTrace = OpenTrace(&trace);
	if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)//打开失败一般为打不开这个.bin文件，没有test.bin或者没有管理员权限
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

	wprintf(L"Number of events lost:  %lu\n", pHeader->EventsLost);

	// Use pHeader to access all fields prior to LoggerName.
	// Adjust pHeader based on the pointer size to access
	// all fields after LogFileName. This is required only if
	// you are consuming events on an architecture that is 
	// different from architecture used to write the events.

	if (pHeader->PointerSize != sizeof(PVOID))
	{
		pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
			2 * (pHeader->PointerSize - sizeof(PVOID)));
	}
	wprintf(L"Number of buffers lost: %lu\n\n", pHeader->BuffersLost);

	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}

cleanup:
	//	wprintf(L"The process is ended with %lu\n", status);
	if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
	{
		status = CloseTrace(g_hTrace);
	}
	//	getchar();
}


#include "stdafx.h"
#include "sysmon_trace_session.h"
#include "event_record_manager.h"
#include "init_collector.h"
#include "public_xml_interface.h"
#include "tool_functions.h"
#include "sysmon_pruning.h"

#pragma comment(lib, "wevtapi.lib")
// static ULONG64 matchfalg = PROCESS_CREATE_THREAD |
// PROCESS_QUERY_LIMITED_INFORMATION |
// PROCESS_QUERY_INFORMATION |
// PROCESS_VM_OPERATION |
// PROCESS_VM_WRITE |
// PROCESS_VM_READ;

SysmonTraceSession::SysmonTraceSession() {

}


SysmonTraceSession::~SysmonTraceSession() {

}

void SysmonTraceSession::Init()
{
   
}

bool SysmonTraceSession::StartSession() {
	DWORD status = ERROR_SUCCESS;
	LPWSTR pwsPath = (LPWSTR)L"Microsoft-Windows-Sysmon/Operational";
    LPWSTR pwsQuery = L"*";
	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
		(EVT_SUBSCRIBE_CALLBACK)_ConsumeEvent, EvtSubscribeToFutureEvents);
	if (NULL == hSubscription)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			LoggerRecord::WriteLog(L"SysmonTraceSession::StartSession Channel" + wstring(pwsPath) + L" was not found.", LogLevel::ERR);
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call EvtGetExtendedStatus to get information as to why the query is not valid.
			LoggerRecord::WriteLog(L"SysmonTraceSession::StartSession the query \"" + wstring(pwsQuery)+ L"\" is not valid.", LogLevel::ERR);
		else
			LoggerRecord::WriteLog(L"SysmonTraceSession::StartSession EvtSubscribe failed with " + std::to_wstring(status), LogLevel::ERR);
	}
	
    if (hSubscription) {
        _session_worker = std::thread(std::bind(&SysmonTraceSession::_SessionExec, this));
        _session_worker.detach();
    }		
	else
		StopSession();	

	return true;
}


void SysmonTraceSession::StopSession() {
    _end_flag = true;
	if (hSubscription)
		EvtClose(hSubscription);
}

void SysmonTraceSession::_SessionExec() {
	while (!_end_flag) {
		Sleep(1000);
	}
}

// Render the event as an XML string and print it.
DWORD PrintSysmonEvent(EVT_HANDLE hEvent)
{
	std::unordered_map<String, String> mdata;
	String strData = "";

	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				LoggerRecord::WriteLog(L"Malloc failed in parse event.", LogLevel::ERR);
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			LoggerRecord::WriteLog(L"EvtRender failed with" + to_wstring(status), LogLevel::ERR);
			goto cleanup;
		}
	}

	//wprintf(L"%s\n\n", pRenderedContent);
	//LoggerRecord::WriteLog(L"EvtRender Sysmon" + wstring(pRenderedContent), LogLevel::INFO);
	if (public_xml_interface::GetInstance().ParseSysmon(ToolFunctions::WStringToString(pRenderedContent), mdata))
	{
        SysmonTraceSession::GetInstance().MakeSysmonEvent(mdata);
	}	

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

VOID WINAPI SysmonTraceSession::_ConsumeEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			// Handle if this is an issue for your application.
			LoggerRecord::WriteLog(L"The subscription callback was notified that event records are missing.", LogLevel::ERR);
		}
		else
		{
			LoggerRecord::WriteLog(L"The subscription callback received the following Win32 error:"+ std::to_wstring((DWORD)hEvent), LogLevel::ERR);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = PrintSysmonEvent(hEvent)))
		{
			goto cleanup;
		}
		break;

	default:
		LoggerRecord::WriteLog(L"SubscriptionCallback: Unknown action.", LogLevel::ERR);
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	//return status; // The service ignores the returned status.
}

bool SysmonTraceSession::MakeSysmonEvent(std::unordered_map<String, String> mdata) 
{   
    try {
        if (mdata.size() <= 0) {
            return false;
        }
        auto EventID = atol(mdata["EventID"].c_str());      

        do {
            if (EventID == SYSMON_Drive_Loaded)
            {
                SDriverLoaded sdl;
                sdl.Signed = mdata["Signed"] == "true" ? 1 : 0;
                sdl.Signature = mdata["Signature"];
                sdl.SignatureStatus = mdata["SignatureStatus"];
                sdl.ImageLoaded = mdata["ImageLoaded"];
                auto iter = mdata.find("Hashes");
                if (iter != mdata.end() && iter->second.size() > 32)
                {
                    sdl.Hashes = iter->second.substr(4, 32);
                }

                EventRecord* event_record = EventRecordManager::GetInstance().ParseSysmonDriverLoadedEvent(sdl);
                if (event_record)
                    InitCollector::GetCollector()->PushSendRecord(event_record);
            
            }else if (EventID == SYSMON_Process_Access)
            {
                SProcessAccess spa;
                spa.SourceProcessId = atol(mdata["SourceProcessId"].c_str());
                spa.SourceThreadId = atol(mdata["SourceThreadId"].c_str());
                spa.SourceImage = mdata["SourceImage"];
                spa.TargetProcessId = atol(mdata["TargetProcessId"].c_str());
                spa.TargetImage = mdata["TargetImage"];
                spa.GrantedAccess = strtoull(mdata["GrantedAccess"].c_str(), nullptr, 16);
               
                // ¼ì²â¹ýÂË 0x143A                
                //if (spa.GrantedAccess & matchfalg) 
                {
                    // prun repeating event
                    if (!SysmonPruning::pruningProcessAccess(spa.SourceProcessId, spa.TargetProcessId)) {
                        return false;
                    }

                    EventRecord* event_record = EventRecordManager::GetInstance().ParseSysmonProcessAccessEvent(spa);
                    if (event_record)
                        InitCollector::GetCollector()->PushSendRecord(event_record);
                }
            }
                     
        } while (0);
      
    }
    catch (...) {
        LoggerRecord::WriteLog(L"MakeSecurityAudit catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return "";
    }

    return true;
}

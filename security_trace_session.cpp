#include "stdafx.h"
#include "security_trace_session.h"
//#include "event_record.h"
#include "event_record_manager.h"
#include "init_collector.h"
#include "public_xml_interface.h"
#include "tool_functions.h"
#include "security_audit.h"

#pragma comment(lib, "wevtapi.lib")

extern std::wstring wstrQuery;

SecurityTraceSession::SecurityTraceSession() {

}


SecurityTraceSession::~SecurityTraceSession() {

}

void SecurityTraceSession::Init()
{
    security_audit::GetInstance().Init();
}

bool SecurityTraceSession::StartSession() {
	DWORD status = ERROR_SUCCESS;
	LPWSTR pwsPath = (LPWSTR)L"Security";
	//LPWSTR pwsQuery = (LPWSTR)L"*";
    //XPath Query: *[System[(Level <= 3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]
    //LPWSTR pwsQuery = (LPWSTR)L"*[System[(EventID=1102 or EventID=4624)]]";
    LPWSTR pwsQuery = (LPWSTR)wstrQuery.data();
	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
		(EVT_SUBSCRIBE_CALLBACK)_ConsumeEvent, EvtSubscribeToFutureEvents);
	if (NULL == hSubscription)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			LoggerRecord::WriteLog(L"Channel" + wstring(pwsPath) + L" was not found.", LogLevel::ERR);
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call EvtGetExtendedStatus to get information as to why the query is not valid.
			LoggerRecord::WriteLog(L"The query \"" + wstring(pwsQuery)+ L"\" is not valid.", LogLevel::ERR);
		else
			LoggerRecord::WriteLog(L"EvtSubscribe failed with " + std::to_wstring(status), LogLevel::ERR);
	}
	
    if (hSubscription) {
        _session_worker = std::thread(std::bind(&SecurityTraceSession::_SessionExec, this));
        _session_worker.detach();
    }
		
	else
		StopSession();	

	return true;
}


void SecurityTraceSession::StopSession() {
    _end_flag = true;
	if (hSubscription)
		EvtClose(hSubscription);
}

void SecurityTraceSession::_SessionExec() {
	while (!_end_flag) {
		Sleep(1000);
	}
}

// Render the event as an XML string and print it.
DWORD PrintEvent(EVT_HANDLE hEvent)
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
	//LoggerRecord::WriteLog(L"EvtRender Security" + wstring(pRenderedContent), LogLevel::INFO);
	
	public_xml_interface::GetInstance().ParseSecurityAudit(ToolFunctions::WStringToString(pRenderedContent), mdata);
    long pid, tid;
	strData = security_audit::GetInstance().MakeSecurityAudit(mdata, pid, tid);
	if (strData.length() > 0)
	{
		EventRecord* event_record = EventRecordManager::GetInstance().ParseSecurityEventRecord(ToolFunctions::StringToWString(strData), pid, tid);
		InitCollector::GetCollector()->PushSendRecord(event_record);
	}

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

VOID WINAPI SecurityTraceSession::_ConsumeEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
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
		if (ERROR_SUCCESS != (status = PrintEvent(hEvent)))
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
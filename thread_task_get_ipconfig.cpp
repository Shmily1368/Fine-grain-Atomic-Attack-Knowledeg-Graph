#include "stdafx.h"
#include "thread_task_get_ipconfig.h"
#include "init_collector.h"
#include "global_enum_def.h"

#pragma comment(lib, "ws2_32.lib")  

void GetIpConfigThreadTask::_Excute()
{
	while (!_stop_flag) 
	{
		Sleep(5000);

		string ip;
		char hostname[MAX_PATH] = { 0 };
		gethostname(hostname, MAX_PATH);
		struct hostent FAR* lpHostEnt = gethostbyname(hostname);
		if (lpHostEnt == NULL)
			continue;


		char **pptr = lpHostEnt->h_addr_list;
		while (*(lpHostEnt->h_addr_list) != NULL) //ipv4 address
		{
			ip += inet_ntoa(*(struct in_addr *) *lpHostEnt->h_addr_list);
			ip += " ";
			//printf("ipv4 addr = %s\n\n", ip);
			lpHostEnt->h_addr_list++;
		}

		if (ip != ip_backup) 
		{
			EventRecord* event_record = EventRecordManager::GetInstance().ParseIpconfigEvent(ip);
			InitCollector::GetCollector()->PushSendRecord(event_record);
			ip_backup = ip;
		}
	}
}

GetIpConfigThreadTask::GetIpConfigThreadTask()
	: BaseThreadTask(GET_IPCONFIG_TASK_MODE)
{
	
}

GetIpConfigThreadTask::~GetIpConfigThreadTask()
{

}

void GetIpConfigThreadTask::Log()
{

}

void GetIpConfigThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitGetIpConfigThreadTask", INFO);
}

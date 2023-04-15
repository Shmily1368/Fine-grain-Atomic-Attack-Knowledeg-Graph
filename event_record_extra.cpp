#include "stdafx.h"
#include "event_record_extra.h"
#include "event_identifier.h"
#include "event_record_pruner.h"
#include "init_collector.h"
#include <evntcons.h>

EventRecordDNS::EventRecordDNS(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordDNS);

	event_identifier_ = EventIdentifier(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Id);
	switch (event_identifier_.opcode())
	{
	case EM_DNSDataEventOPC::DNSQueryRequest:
	case EM_DNSDataEventOPC::DNSQueryResult:
		ParameterValue param_val;
		param_val.s = (wchar_t*)raw_rec->UserData;
		parameter_list_.push_back(std::move(param_val));
	}

// 	std::wstring query_name = (wchar_t*)user_data;
// 	user_data += (query_name.size() + 1) * 2;
// 
// 	UINT32 query_type = *(UINT32*)user_data;
// 	UINT32 network_index = *(UINT32*)(user_data + 4);
// 	UINT32 interface_index = *(UINT32*)(user_data + 8);
// 	UINT32 status = *(UINT32*)(user_data + 12);
// 
// 	std::wstring results = (wchar_t*)(user_data + 16);
}

EventRecordDNS::~EventRecordDNS()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordDNS);
}

int_32 EventRecordDNS::parse()
{
	return 0;
}


////////////////////EventRecordPowerShell////////////////////////

EventRecordPowerShell::EventRecordPowerShell(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordPowerShell);

	event_identifier_ = EventIdentifier(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Id);
	switch (event_identifier_.opcode())
	{
		case EM_PowerShellEventOPC::PowerShellScript:
			ParameterValue param_val;
			param_val.s = (wchar_t*)(raw_rec->UserData) + 4;
			parameter_list_.push_back(std::move(param_val));
	}
}

EventRecordPowerShell::~EventRecordPowerShell()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordPowerShell);
}

int_32 EventRecordPowerShell::parse()
{
	return 0;
}

bool EventRecordPowerShell::Output() 
{
    bool flag = true;    
   
    if (EventRecordPruner::GetInstance().PrunPowerShell(this)) {
      
        QPCtimeToSystime();
       
        if (InitCollector::GetCollector())
            InitCollector::GetCollector()->PushSendRecord(this);

        return true;
    }

    return false;
}


////////////////////EventRecordSecurity////////////////////////
EventRecordSecurity::EventRecordSecurity() {
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordSecurity);

}


EventRecordSecurity::~EventRecordSecurity() {
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordSecurity);
}

int_32 EventRecordSecurity::parse()
{
	return 0;
}
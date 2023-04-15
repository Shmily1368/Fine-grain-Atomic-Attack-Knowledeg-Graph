#pragma once
#include "event_record.h"

#include <windows.h>
#include <evntrace.h>

class EventRecordDNS : public EventRecord
{
public:
	EventRecordDNS(PEVENT_RECORD raw_rec);
	~EventRecordDNS();

	virtual int_32 parse() override;
};


////////////////////EventRecordPowerShell////////////////////////

class EventRecordPowerShell : public EventRecord
{
public:
	EventRecordPowerShell(PEVENT_RECORD raw_rec);
	~EventRecordPowerShell();

	virtual int_32 parse() override;
    bool Output() override;
};

class EventRecordSecurity : public EventRecord
{
public:
	EventRecordSecurity();
	~EventRecordSecurity();

	virtual int_32 parse() override;
};
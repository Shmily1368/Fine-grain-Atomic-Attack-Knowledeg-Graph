#pragma once

#include <wbemidl.h>
#include <wmistr.h>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>

#include "event_identifier.h"
#include "event_parameter.h"
#include "event_record.h"
#include "event_record_callstack.h"
#include "object_pool.h"
#include "publicstruct.h"
#include"powershell_detector/powershellStruct.h"

const int_32 KProviderMappingSize = 19;
const int_32 KOpcodeNum = 256;
const int_32 KProviderModuloNum = 256;

class EventRecordManager
{
	SINGLETON_DEFINITION(EventRecordManager);
	DISABLE_COPY(EventRecordManager);

public:
	EventRecordManager();
	~EventRecordManager();
	std::map<EventIdentifier, std::vector<EventParameter>> event_strucp_map;
	int parameter_position[KProviderMappingSize][KOpcodeNum][KParametesStringListSize];
	int get_parameter_posistion(EventIdentifier&, parameter_index_enum);
	int query_parameter_posistion(EventIdentifier&, parameter_index_enum);
	void SetWIN7EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	void SetWIN10EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	EventRecord* ParseEventRecord(PEVENT_RECORD raw_rec);
	void RecycleEventRecord(EventRecord* rec);

	EventRecord* ParseVisibleWindowStruct(DWORD processid, DWORD threadid, long long handle , long long left, long long top, long long right, long long bottom, DWORD visible, DWORD toolbar); 
	EventRecord* ParseMouseEvent(DWORD processid, long long buttontype);
	EventRecord* ParseKeyboardEvent(DWORD processid, std::wstring value);
	//EventRecord* ParseRemoveableDeviceEvent(std::wstring value);
    EventRecord* ParseRemoveableDeviceEvent(DWORD serialNum, std::wstring rootPath, std::wstring volumeName, std::wstring fileSystem);
	EventRecord* ParseRansomDetectorEvent(DWORD processid, DWORD parentid,std::wstring processname, std::wstring parentname, std::wstring details);
	EventRecord* ParseIpconfigEvent(std::string ip);
	EventRecord* ParseExtraEventRecord(PEVENT_RECORD raw_rec);
	EventRecord* ParseSecurityEventRecord(std::wstring raw_rec, long pid, long tid);
    EventRecord* ParseZoneIdentifierEvent(ULONG64 time_stamp, DWORD processid, DWORD zoneId, wstring referrerUrl, std::wstring hostUrl, std::wstring fileName);
    EventRecord* ParseRuleIdentifierEvent(EventRecord * ev, SRule srule);
    EventRecord* ParseSysmonDriverLoadedEvent(SDriverLoaded sdl);
    EventRecord* ParseSysmonProcessAccessEvent(SProcessAccess spa);
    EventRecord* ParseHashInfoEvent(EventRecord * ev, std::wstring md5, long fileSize);
	EventRecord* ParsePowershellCheckEvent(powershell_Result ret);

    

private:
	void _InitEventStructMap(const String& file_name);
	bool _ConvertSidtoUname(PVOID sid, std::wstring& uname);
private:
	int provider_modulo_mapping_hash[KProviderModuloNum];
	ParameterIndex base_parameter_index;
	// add by zxw on 20191204
	std::unordered_map<std::wstring, std::wstring> _sid_uname_map;
};


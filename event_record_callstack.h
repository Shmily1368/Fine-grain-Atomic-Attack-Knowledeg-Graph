#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-4-17
// Updated 2018-4-28

#include "event_record.h"

#include <Windows.h>
#include <evntrace.h>

using DWORD_USET_UMAP = std::unordered_map<DWORD, std::unordered_set<ULONG64>>;
using DWORD_UMAP_UMAP = std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>>;

class EventRecordCallstack : public EventRecord
{
public:
	static void Init();

	EventRecordCallstack(PEVENT_RECORD raw_rec);
	EventRecordCallstack(int pid, int tid, ULONG64 timestamp);
	~EventRecordCallstack();

	int parse() override;
	bool Output() override;

	// provide top level api's address for callstack pruning.
	ULONG64 getTopAddress() {
		if (!vector_size) return 0;
		else return entry_address_vector_[0]; 
	}
	static ULONG64 parse_api_level_number;
	static void InitApiConfiguration();

	static DWORD_USET_UMAP process_address_cache;  // address enter and continue address
	static DWORD_UMAP_UMAP process_API_address_cache;  // API we need 
	static DWORD_USET_UMAP process_address_useless_cache;  // useless
	static DWORD_USET_UMAP APIaddress_keepon_cache;   // address of API keepon

	void SetLabel(const String& label);
	void SetCallstack(const String& callstack);
	String GetLabel();
	String GetOutputInfo();

private:
	static std::function<void(EventRecordCallstack*)> _parse_func;

	static void ParseTopLevelAPIwithOptimize(EventRecordCallstack* ev);
	static void ParseTopLevelAPIwithOptimizeWin10(EventRecordCallstack* ev);
	static void ParseTopLevelAPIwithOptimizeWS2012R2(EventRecordCallstack* ev);
	static void ParseTopLevelAPIwithRunqinTrick(EventRecordCallstack* ev, int start_index = 0);
	static void ParseTopLevelAPIwithRunqinTrickWS2012R2(EventRecordCallstack* ev, int_32 start_index = 0);

	static String ConvertAddress2APIName(EventRecordCallstack* ev, ULONG64 address);

	static bool isKeeponParseAPI(EventRecordCallstack* ev, String apiname, int_32 index);

private:
	ULONG64 entry_address_vector_[256];
	int_32 vector_size = 0;
	int_32 kernel_start = 0;
	String label_;
};


/* Events with call stack ==================================

{ ProcessGuid, 1,{ 0 } }, // start
{ ProcessGuid, 4,{ 0 } }, // DC end
{ ProcessGuid, 2,{ 0 } }, // end

{ FileIoGuid, 64,{ 0 } }, // fileiocreate
{ FileIoGuid, 72,{ 0 } }, // DirEnum
{ FileIoGuid, 67,{ 0 } }, // read
{ FileIoGuid, 68,{ 0 } }, // write
{ FileIoGuid, 74,{ 0 } }, // queryinfo

{ PerfInfoGuid, 51,{ 0 } }, // system cal

{ ALPCGuid, 33,{ 0 } }, // send
{ ALPCGuid, 34,{ 0 } }, // receive

{ ThreadGuid, 2,{ 0 } }, // end
{ ThreadGuid, 4,{ 0 } }, // DC end

{ RegistryGuid, 22,{ 0 } }, // KCBCreate
{ RegistryGuid, 16,{ 0 } }, // Query value
{ RegistryGuid, 13,{ 0 } }, // Query
{ RegistryGuid, 17,{ 0 } }, // Enumerate key
{ RegistryGuid, 18,{ 0 } }, // Enumerate value
{ RegistryGuid, 10,{ 0 } }, // create
{ RegistryGuid, 11,{ 0 } }, // Open
{ RegistryGuid, 20,{ 0 } }, //setinformation */
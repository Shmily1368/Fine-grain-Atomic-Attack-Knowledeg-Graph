#pragma once

// Writed by Chunlin(chunlinxiong@foxmail.com)
// Created 2018-04-02
// Updated 2018-04-03

#include "event_record.h"
#include "map_auto_cleanup.h"
#include "macro_detector.h"
#include "get_systemcontext.h"
#include <list>
#include <functional> 
#include <windows.h>
#include "cert_analyzer.h"

class EventRecordPerfInfo : public EventRecord
{
public:
	EventRecordPerfInfo(PEVENT_RECORD raw_rec);
	~EventRecordPerfInfo();

	void InitParse() override;
	int parse() override;
	virtual bool Output() override;
};

class EventRecordUnknown : public EventRecord
{
public:
	EventRecordUnknown();
	~EventRecordUnknown();

	int parse() 
	{
		useless = true;
		return 0; 
	}
};

class EventRecordAlpc : public EventRecord
{
public:
	EventRecordAlpc(PEVENT_RECORD raw_rec);
	EventRecordAlpc(DWORD input_thread_id, DWORD input_process_id, ULONG64 time_stamp);
	~EventRecordAlpc();

	int parse() override;
	struct AlpcMessage {
		int message_id;
		int process_id;
		int thread_id;
		AlpcMessage() {
			process_id = 0;
			message_id = 0;
			thread_id = 0;
		}
	};
	EventRecord* get_correspond_send();

private:
	static std::list<AlpcMessage> send_message_list_;

	class messageid_to_find :public std::unary_function<AlpcMessage, bool>
	{
	private:
		int name;
	public:
		explicit messageid_to_find(int iname) :name(iname) {}
		bool operator()(const AlpcMessage& alpc_message)
		{
			return (alpc_message.message_id == name);
		}
	};
};

class EventRecordThread : public EventRecord
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	EventRecordThread(PEVENT_RECORD raw_rec);
	~EventRecordThread();

protected:
	DWORD _owner_pid;
};

class EventRecordDiskio : public EventRecord
{
public:
	EventRecordDiskio(PEVENT_RECORD raw_rec);
	~EventRecordDiskio();
	void InitParse() override;
	int parse() override;
};

struct FileIoInfo 
{
	int used;
	std::wstring file_name;
};

class EventRecordFileio : public EventRecord
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	bool Output() override;
	EventRecord* renameCache();
	void GetLastWrittenInterval();
	inline const std::wstring& GetFileName() const { return _file_name; }
	EventRecordFileio(PEVENT_RECORD raw_rec);
	EventRecordFileio();
	~EventRecordFileio();
	//static Unordered_map file_context;  // need to define its hash function
	static std::unordered_map<ULONG64,std::wstring> file_context;

	static std::unordered_map<ULONG64, FileIoInfo> file_key2file_info_map;
	static std::unordered_map<ULONG64, FileIoInfo> file_object2file_info_map;
	static std::unordered_map<ULONG64, EventRecordFileio*> fileiorename_cache_map;

	static long EventRecordFileio::parse_num;
	static ULONG64 collector_pid;

private:
	void _ParseFileName();
	void _TryProcessMacro();
	void _OnConvertPathError();
    void _UploadFile();
    void AddIsDownloadParameter();
private:
	std::wstring _file_name;
	bool _force_convert_path;
};

class EventRecordRegistry : public EventRecord
{
public:
	EventRecordRegistry(PEVENT_RECORD raw_rec);
	~EventRecordRegistry();
	int parse() override;
    bool Output() override;
	static std::vector<bool> isroot_match;
private:    
    void ParseRegistryKCBCreate();
    void ParseRegistryCreate();
    void ParseRegistryOpen();
    void ParseRegistrySetValue();
    void ParseRegistryClose(); 
    void ParseRegistryDelete();
    void ParseRegistryDeleteValue();
    void ParseRegistryQuery();
public:
	//static MapAutoCleanup<ULONG64,std::wstring>key_handle2key_name_map;
    // mod by zxw on 20200512 key=handle+pid
    static MapAutoCleanup<std::wstring, std::wstring> key_handle2key_name_map;
	static std::unordered_map<DWORD, std::wstring> thread2_keyname;  // save TID,key name not have corresponding keyhandle yet

    static wstring s_openKeyName;
    static wstring s_openKeyHandle; 
    static wstring s_createKeyName;
    static wstring s_createKeyHandle;
    static wstring s_createKey;
};

class EventRecordProcess : public EventRecord
{
public:
	void InitParse() override;
	int parse() override;
	bool Output() override;
    EventRecordProcess();
	EventRecordProcess(PEVENT_RECORD raw_rec);
	~EventRecordProcess();
};

class EventRecordTcpip : public EventRecord
{
public:
	EventRecordTcpip(PEVENT_RECORD raw_rec);
    EventRecordTcpip();
	~EventRecordTcpip();
	void InitParse() override;
	int parse() override;
	bool Output() override;
};

class EventRecordUdpip : public EventRecord
{
public:
	EventRecordUdpip(PEVENT_RECORD raw_rec);
    EventRecordUdpip();
	~EventRecordUdpip();
	void InitParse() override;
	int parse() override;
	bool Output() override;
};

class EventRecordImage : public EventRecord
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	bool Output() override;
	void certificate();
    void CheckCertificate(std::list<SIGN_NODE_INFO> SignChain);
	EventRecordImage();
	EventRecordImage(PEVENT_RECORD raw_rec);
	~EventRecordImage();

private:
	void _OnConvertPathError();

private:
	static STRING_SET _dll_need_rva_set;
	bool _need_rva;

	bool _force_convert_path;
	bool _convert_path_succ;
};

class EventRecordVisibleWindow : public EventRecord
{
public:
	EventRecordVisibleWindow();
	~EventRecordVisibleWindow();
	int parse() override { return 1; };
};

class EventRecordMouse : public EventRecord
{
public:
	EventRecordMouse();
	~EventRecordMouse();
	int parse() override { return 1; };
};

class EventRecordKeyBoard : public EventRecord
{
public:
	EventRecordKeyBoard();
	~EventRecordKeyBoard();
	int parse() override { return 1; };
};

class EventMacroResult : public EventRecord
{
public:
	EventMacroResult(EventRecordFileio* rec_file_io);
	~EventMacroResult();

	virtual int parse() override;
	virtual bool Output() override;

private:
	static uint_32 _parse_counter;
	static unordered_map<std::wstring, int_32> _detected_macro_file_record_map;
	EM_FileioEventOPC _original_opcode;
	std::wstring _original_pname;

	EM_MarcoDetectResult _result;
	std::wstring _file_path;
	STRING_VECTOR _macro_contents;
};

class EventRemovableDevice : public EventRecord
{
public:
	EventRemovableDevice();
	~EventRemovableDevice();
	int parse() override { return 1; };
};

class EventIpconfig : public EventRecord
{
public:
	EventIpconfig();
	~EventIpconfig();
	int parse() override { return 1; };
};

class EventHealthCheck : public EventRecord
{
public:
	EventHealthCheck(const string& unique_id);
	~EventHealthCheck();

	int parse() override { return 1; }
};

class EventInitSignal : public EventRecord
{
public:
	EventInitSignal();
	~EventInitSignal();

	int parse() override { return 1; }
};

class EventAutorunInfo : public EventRecord
{
public:
	EventAutorunInfo(const String& file_path);
	virtual ~EventAutorunInfo() override;

	virtual int parse() override { return 1; }
};

class EventRansomCheck : public EventRecord{
public:
	EventRansomCheck();
	virtual ~EventRansomCheck() override;

	virtual int parse() override { return 1; }
};

class EventPowershellCheck : public EventRecord {
public:
	EventPowershellCheck();
	virtual ~EventPowershellCheck() override;

	virtual int parse() override { return 1; }
};

class EventZoneIdentifier : public EventRecord {
public:
    EventZoneIdentifier();
    virtual ~EventZoneIdentifier() override;

    virtual int parse() override { return 1; }
};
class EventDriverLoaded : public EventRecord {
public:
    EventDriverLoaded();
    virtual ~EventDriverLoaded() override;

    virtual int parse() override { return 1; }
};
class EventProcessAccess : public EventRecord {
public:
    EventProcessAccess();
    virtual ~EventProcessAccess() override;

    virtual int parse() override { return 1; }
};
class EventHashInfo : public EventRecord {
public:
    EventHashInfo();
    virtual ~EventHashInfo() override;

    virtual int parse() override { return 1; }
};

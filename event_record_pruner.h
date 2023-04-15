#pragma once
#include "event_record_subclass.h"
#include "event_record_extra.h"
#include "publicstruct.h"

struct ProcessNetworkPrunCacheData
{
    ULONG64 time_stamp;
    int thread_id;
    
	uint_32 s_ip;
	uint_16 s_port;
	uint_32 d_ip;
	uint_16	d_port;

	ProcessNetworkPrunCacheData(ULONG64 time_stamp_t, int thread_id_t, uint_32 s_ip_t, uint_16 s_port_t, uint_32 d_ip_t, uint_16 d_port_t)
		: time_stamp(time_stamp_t), thread_id(thread_id_t), s_ip(s_ip_t), s_port(s_port_t), d_ip(d_ip_t), d_port(d_port_t)
	{

	}

	bool operator<(const ProcessNetworkPrunCacheData& rhs) const
	{
		if (s_port == rhs.s_port)
		{
			if (d_ip == rhs.d_ip)
			{
				return d_port < rhs.d_port;
			}
			return d_ip < rhs.d_ip;
		}
		return s_port < rhs.s_port;
	}

	bool operator==(const ProcessNetworkPrunCacheData& rhs) const
	{
		return (s_ip == rhs.s_ip && s_port == rhs.s_port && d_ip == rhs.d_ip && d_port == rhs.d_port);
	}
};

namespace std
{
    template <>
    struct hash<ProcessNetworkPrunCacheData>
    {
        std::size_t operator()(const ProcessNetworkPrunCacheData &key) const
        {
            using std::size_t;
            using std::hash;

            return ((hash<uint_32>()(key.d_ip)
                ^ (hash<uint_16>()(key.s_port) << 1)) >> 1)
                ^ (hash<uint_16>()(key.d_port) << 1);
        }
    };
}

using ProcessNetworkPrunCacheSet = std::set<ProcessNetworkPrunCacheData>;

class EventRecordPruner
{
	SINGLETON_DEFINITION(EventRecordPruner);
	DISABLE_COPY(EventRecordPruner);

public:
	EventRecordPruner();
	~EventRecordPruner();

	void LogCacheSize() const;
	void CleanCache();
    void CleanFileIoReadCache();
	void OnProcessEnd(DWORD process_id);
	void OnFileIoClose(EventRecordFileio* rec);
    void SetFileIoWriteTag(std::wstring file_name, DWORD process_id);
	bool PrunFileIoReadWrite(EventRecordFileio* rec);
    bool PrunFileIoDelete(EventRecordFileio* rec);
    bool PrunPowerShell(EventRecordPowerShell* rec);

	void CleanProcessCache(DWORD process_id);
    /*
	bool PrunTcpIpSend(EventRecordTcpip* rec);
	bool PrunTcpIpRecv(EventRecordTcpip* rec);
	bool PrunUdpIpSend(EventRecordUdpip* rec);
	bool PrunUdpIpRecv(EventRecordUdpip* rec);
    */
    // add by zxw on 20191230
    bool PrunTcpIpEvent(EventRecordTcpip* rec);
    bool PrunUdpIpEvent(EventRecordUdpip* rec);
    // add by zxw on 20200703
    bool PrunRegistryEvent(EventRecordRegistry* rec);
    //void CleanNetworkCache();
    //void CleanNetworkCache(DWORD process_id);
    void CleanNetworkCache(ULONG64 time_stamp);
    void EventRecordPruner::CleanNetworkCache(std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> &network, ULONG64 time_stamp, uint_32 provider_id, int_32 opcode);

    void PushSendNetWorkEvent(uint_32 provider_id, int_32 opcode, DWORD process_id, uint_32 s_size, ProcessNetworkPrunCacheData net_data);
private:
	std::unordered_map<DWORD, std::set<std::wstring>> _process_file_write_cache;
    //std::unordered_map<std::wstring, std::set<DWORD>> _file_process_read_cache;
	std::unordered_map<std::wstring, std::unordered_map<DWORD, SFileIoTags>> _file_process_read_cache;
    std::unordered_map<DWORD, std::set<std::wstring>> _process_file_delete_cache;
    std::unordered_map<DWORD, std::set<DWORD>> _process_powershell_cache;

	std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> _process_tcp_send_cache;
	std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> _process_tcp_recv_cache;
    //std::unordered_map<DWORD, ProcessNetworkPrunCacheData> _process_tcp_recv_cache;
	std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> _process_udp_send_cache;
	//std::unordered_map<DWORD, ProcessNetworkPrunCacheData> _process_udp_recv_cache;
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> _process_udp_recv_cache;

    // 
    static ULONG64 _time_cache;
};
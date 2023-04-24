#include "stdafx.h"
#include "event_record_pruner.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "filter.h"

ULONG64 EventRecordPruner::_time_cache;

STRING_SET g_registry_create_set =
{    
    "software\\microsoft",
    "software\\classes",
    "software\\wow6432node",
    "software\\policies",

    "\\registry\\machine\\",
    "\\registry\\classes_root\\",
    "\\registry\\current_config\\",
    "\\registry\\current_user\\",

    "\\registry\\machine\\system",
    "\\registry\\classes_root\\system",
    "\\registry\\current_user\\system",
    "\\registry\\current_config\\system",  

    "\\registry\\machine\\software",
    "\\registry\\classes_root\\software",
    "\\registry\\current_user\\software",
    "\\registry\\current_config\\software",

    "\\registry\\machine\\software\\microsoft",
    "\\registry\\classes_root\\software\\microsoft",
    "\\registry\\current_user\\software\\microsoft",
    
    "\\registry\\machine\\software\\classes",
    "\\registry\\classes_root\\software\\classes",
    "\\registry\\current_user\\software\\classes",  
    
    "\\registry\\machine\\software\\wow6432node",   
    "\\registry\\current_user\\software\\wow6432node",
    
    "\\registry\\machine\\software\\policies",
    "\\registry\\current_user\\software\\policies",
    
    "\\registry\\machine\\software\\wow6432node\\microsoft",
    "\\registry\\current_user\\software\\wow6432node\\microsoft",

    "\\registry\\machine\\software\\policies\\microsoft",
    "\\registry\\current_user\\software\\policies\\microsoft",
    
    "\\registry\\machine\\software\\microsoft\\systemcertificates",
    "\\registry\\current_user\\software\\microsoft\\systemcertificates",
};

EventRecordPruner::EventRecordPruner()
{

}

EventRecordPruner::~EventRecordPruner()
{

}

void EventRecordPruner::LogCacheSize() const
{
	LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: process_file_write_cache size = " + std::to_wstring(_process_file_write_cache.size()), LogLevel::INFO);
	LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: file_process_read_cache size = " + std::to_wstring(_file_process_read_cache.size()), LogLevel::INFO);
    LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: process_file_delete_cache size = " + std::to_wstring(_process_file_delete_cache.size()), LogLevel::INFO);
    LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: process_tcp_send_cache size = " + std::to_wstring(_process_tcp_send_cache.size()), LogLevel::INFO);
	LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: process_udp_send_cache size = " + std::to_wstring(_process_udp_send_cache.size()), LogLevel::INFO);
    LoggerRecord::WriteLog(L"EventRecordPruner::LogCacheSize: process_powershell_cache size = " + std::to_wstring(_process_powershell_cache.size()), LogLevel::INFO);
}

void EventRecordPruner::CleanCache()
{
	LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: process_file_write_cache size before clean = " + std::to_wstring(_process_file_write_cache.size()), LogLevel::INFO);
	std::unordered_map<DWORD, std::set<std::wstring>>().swap(_process_file_write_cache);
	LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: file_process_read_cache size before clean = " + std::to_wstring(_file_process_read_cache.size()), LogLevel::INFO);
    //std::unordered_map<std::wstring, std::unordered_map<DWORD, SFileIoTags>>().swap(_file_process_read_cache);
    CleanFileIoReadCache();

    LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: process_file_delete_cache size before clean = " + std::to_wstring(_process_file_delete_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::set<std::wstring>>().swap(_process_file_delete_cache);

    LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: process_powershell_cache size before clean = " + std::to_wstring(_process_powershell_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::set<DWORD>>().swap(_process_powershell_cache);

    
    // ADD BY ZXW ON 20200728
    if (EventRecord::frequency.QuadPart != 0)
    {
        LARGE_INTEGER start_time;
        QueryPerformanceCounter(&start_time);
        ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart) * 10000000.0); //100-ns 
        ULONG64 time_stamp = (EventRecord::start_systemtime + intervaltime) * 100; //1 * 100ns = 100ns 
        CleanNetworkCache(time_stamp);
    }    

    /*
	LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: process_tcp_send_cache size before clean = " + std::to_wstring(_process_tcp_send_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, DWORD>>().swap(_process_tcp_send_cache);
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: _process_tcp_recv_cache size before clean = " + std::to_wstring(_process_tcp_recv_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, DWORD>>().swap(_process_tcp_recv_cache);
	LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: process_udp_send_cache size before clean = " + std::to_wstring(_process_udp_send_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, DWORD>>().swap(_process_udp_send_cache);
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanCache: _process_udp_recv_cache size before clean = " + std::to_wstring(_process_udp_recv_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, DWORD>>().swap(_process_udp_recv_cache);
    */
}

void EventRecordPruner::CleanFileIoReadCache() 
{
    auto sclock = clock();
    static int clean_counts = 0;
    clean_counts++;
    // if size is over 10000 or time over 6h clean
    if (_file_process_read_cache.size() > 10000 || clean_counts > 6*6) {
        clean_counts = 0;
        std::unordered_map<std::wstring, std::unordered_map<DWORD, SFileIoTags>>().swap(_file_process_read_cache);
        LoggerRecord::WriteLog(L"EventRecordPruner::CleanFileIoReadCache clean", LogLevel::INFO);
        return;
    }

    for (auto iter = _file_process_read_cache.begin(); iter != _file_process_read_cache.end(); ) {
        auto &cache_map = iter->second;
        for (auto iter_data = cache_map.begin(); iter_data != cache_map.end(); ) {
            auto& tags = iter_data->second;
            if (tags.read_tag == false || tags.write_tag == true)
            {                
                iter_data = cache_map.erase(iter_data);
            }
            else {
                iter_data++;
            }
            tags.read_tag = false;
            tags.write_tag = false;
        }

        if (cache_map.size() == 0)
            iter = _file_process_read_cache.erase(iter);
        else
            iter++;
    }

    if (_file_process_read_cache.size() == 0) {
        std::unordered_map<std::wstring, std::unordered_map<DWORD, SFileIoTags>>().swap(_file_process_read_cache);
    }

    if (clock() - sclock > 1) {
        LoggerRecord::WriteLog(L"CleanFileIoReadCache after time " + std::to_wstring(clock() - sclock), LogLevel::INFO);
    }
}

void EventRecordPruner::OnProcessEnd(DWORD process_id)
{
	CleanProcessCache(process_id);
    //CleanNetworkCache(process_id);
}

void EventRecordPruner::OnFileIoClose(EventRecordFileio* rec)
{
    // remove by zxw on 20200728
    /*
	auto iter_f = _file_process_read_cache.find(rec->GetFileName());
	if (iter_f != _file_process_read_cache.end())
	{
		std::set<DWORD>& cache_set = iter_f->second;
		cache_set.erase(rec->get_process_id_());
		if (cache_set.empty())
		{
			_file_process_read_cache.erase(iter_f);
		}
	}
    */
}

void EventRecordPruner::SetFileIoWriteTag(std::wstring file_name, DWORD process_id)
{
    auto iter_f = _file_process_read_cache.find(file_name);
    if (iter_f != _file_process_read_cache.end()) 
    {
        auto& cache_set = iter_f->second;        
        auto file_iter = cache_set.find(process_id);
        if (file_iter != cache_set.end())
        { 
            auto& tags = file_iter->second;
            tags.write_tag = true;
        }
    }
}

bool EventRecordPruner::PrunFileIoReadWrite(EventRecordFileio* rec)
{
	if (!rec)	return true;

	DWORD process_id = rec->get_process_id_();
	EM_FileioEventOPC opcode = (EM_FileioEventOPC)rec->get_event_identifier_().opcode();
	const std::wstring& file_name = rec->GetStringParameter(parameter_index_enum::FileName);
	switch (opcode)
	{
	case EM_FileioEventOPC::FileIoRead:
	{   
        SFileIoTags stags(true, false);
		auto iter_f = _file_process_read_cache.find(file_name);
		if (iter_f == _file_process_read_cache.end())
		{            
			_file_process_read_cache[file_name][process_id] = stags;
			return true;
		}
		else
		{
			auto& cache_set = iter_f->second;
            auto file_iter = cache_set.find(process_id);
			if (file_iter == cache_set.end())
			{
				cache_set[process_id] = stags;
				return true;
			}
			else
			{
                auto& tags = file_iter->second;
                tags.read_tag = true;
				return false;
			}
		}
	}
	break;

	case EM_FileioEventOPC::FileIoWirte:
	{
        SetFileIoWriteTag(file_name, process_id);
		auto iter_f = _process_file_write_cache.find(process_id);
		if (iter_f == _process_file_write_cache.end())
		{
			_process_file_write_cache[process_id].insert(file_name);
			//_file_process_read_cache.erase(file_name);
			return true;
		}
		else
		{
			std::set<std::wstring>& cache_set = iter_f->second;
			if (cache_set.find(file_name) == cache_set.end())
			{
				cache_set.insert(file_name);
				//_file_process_read_cache.erase(file_name);
				return true;
			}
			else
			{
				return false;
			}
		}
	}
	break;
	}

	return true;
}
// add by zxw on 20200804 PrunFileIoDelete the same pid and filename send only one event
bool EventRecordPruner::PrunFileIoDelete(EventRecordFileio * rec) 
{
    if (!rec)	return true;

    DWORD process_id = rec->get_process_id_();  
    const std::wstring& file_name = rec->GetStringParameter(parameter_index_enum::FileName);   
    auto iter_f = _process_file_delete_cache.find(process_id);
    if (iter_f == _process_file_delete_cache.end()) {
        _process_file_delete_cache[process_id].insert(file_name);
        return true;
    }
    else {
        std::set<std::wstring>& cache_set = iter_f->second;
        if (cache_set.find(file_name) == cache_set.end()) {
            cache_set.insert(file_name);            
            return true;
        }
        else {
            return false;
        }
    }    
}
// add by zxw on 20200804 PrunPowerShell the same pid and tid send only one event
bool EventRecordPruner::PrunPowerShell(EventRecordPowerShell * rec) 
{
    if (!rec)	return true;

    DWORD process_id = rec->get_process_id_();
    DWORD thread_id = rec->get_thread_id_();
    auto iter_f = _process_powershell_cache.find(process_id);
    if (iter_f == _process_powershell_cache.end()) {
        _process_powershell_cache[process_id].insert(thread_id);
        return true;
    }
    else {
        std::set<DWORD>& cache_set = iter_f->second;
        if (cache_set.find(thread_id) == cache_set.end()) {
            cache_set.insert(thread_id);
            return true;
        }
        else {
            return false;
        }
    }
}

void EventRecordPruner::CleanProcessCache(DWORD process_id)
{
	_process_file_write_cache.erase(process_id);
    // ADD BY ZXW ON 20200728
    _process_file_delete_cache.erase(process_id);
    _process_powershell_cache.erase(process_id);
	_process_tcp_send_cache.erase(process_id);
    _process_tcp_recv_cache.erase(process_id);
    _process_udp_send_cache.erase(process_id);
    _process_udp_recv_cache.erase(process_id);
}

/*
bool EventRecordPruner::PrunTcpIpSend(EventRecordTcpip* rec)
{
	if (!rec)	return true;

	DWORD process_id = rec->get_process_id_();
	uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
	uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
	uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
	uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

	auto iter_f = _process_tcp_send_cache.find(process_id);
	if (iter_f == _process_tcp_send_cache.end())
	{
		_process_tcp_send_cache[process_id].emplace(s_ip, s_port, d_ip, d_port);
		return true;
	}
	else
	{
		ProcessNetworkPrunCacheSet& cache_set = iter_f->second;
		ProcessNetworkPrunCacheData cache_data(s_ip, s_port, d_ip, d_port);
		if (cache_set.find(cache_data) == cache_set.end())
		{
			cache_set.insert(cache_data);
			return true;
		}
		else
		{
			return false;
		}
	}
}

bool EventRecordPruner::PrunTcpIpRecv(EventRecordTcpip* rec)
{
	if (!rec)	return true;

	DWORD process_id = rec->get_process_id_();
	uint_32 prev_provider_id, prev_opcode;
	InitCollector::GetCollector()->GetProcessLastEvent(process_id, prev_provider_id, prev_opcode);
	if (prev_provider_id != ETWTcpIp || prev_opcode != EM_TcpIpEventOPC::TcpIpRecvIPV4)
	{
		_process_tcp_recv_cache.erase(process_id);
		return true;
	}

	uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
	uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
	uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
	uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

	ProcessNetworkPrunCacheData cache_data(s_ip, s_port, d_ip, d_port);
	auto iter_f = _process_tcp_recv_cache.find(process_id);
	if (iter_f == _process_tcp_recv_cache.end())
	{
		_process_tcp_recv_cache.emplace(std::make_pair(process_id, cache_data));
		return true;
	}
	else
	{
		if (iter_f->second == cache_data)
		{
			return false;
		}
		else
		{
			_process_tcp_recv_cache.erase(iter_f);
			_process_tcp_recv_cache.emplace(std::make_pair(process_id, cache_data));
			return true;
		}
	}
}

bool EventRecordPruner::PrunUdpIpSend(EventRecordUdpip* rec)
{
	if (!rec)	return true;

	DWORD process_id = rec->get_process_id_();
	uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
	uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
	uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
	uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

	auto iter_f = _process_udp_send_cache.find(process_id);
	if (iter_f == _process_udp_send_cache.end())
	{
		_process_udp_send_cache[process_id].emplace(s_ip, s_port, d_ip, d_port);
		return true;
	}
	else
	{
		ProcessNetworkPrunCacheSet& cache_set = iter_f->second;
		ProcessNetworkPrunCacheData cache_data(s_ip, s_port, d_ip, d_port);
		if (cache_set.find(cache_data) == cache_set.end())
		{
			cache_set.insert(cache_data);
			return true;
		}
		else
		{
			return false;
		}
	}
}

bool EventRecordPruner::PrunUdpIpRecv(EventRecordUdpip* rec)
{
	if (!rec)	return true;

	DWORD process_id = rec->get_process_id_();
	uint_32 prev_provider_id, prev_opcode;
	InitCollector::GetCollector()->GetProcessLastEvent(process_id, prev_provider_id, prev_opcode);
	if (prev_provider_id != ETWUdpIp || prev_opcode != EM_UdpIpEventOPC::UdpIpRecvIPV4)
	{
		_process_udp_recv_cache.erase(process_id);
		return true;
	}

	uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
	uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
	uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
	uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

	ProcessNetworkPrunCacheData cache_data(s_ip, s_port, d_ip, d_port);
	auto iter_f = _process_udp_recv_cache.find(process_id);
	if (iter_f == _process_udp_recv_cache.end())
	{
		_process_udp_recv_cache.emplace(std::make_pair(process_id, cache_data));
		return true;
	}
	else
	{
		if (iter_f->second == cache_data)
		{
			return false;
		}
		else
		{
			_process_udp_recv_cache.erase(iter_f);
			_process_udp_recv_cache.emplace(std::make_pair(process_id, cache_data));
			return true;
		}
	}
}
*/
//
void EventRecordPruner::CleanNetworkCache(std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>> &network, ULONG64 time_stamp, uint_32 provider_id, int_32 opcode)
{
    auto sclock = clock();
    for (auto iter = network.begin(); iter != network.end(); )
    {
        auto &cache_map = iter->second;
        for (auto iter_data = cache_map.begin(); iter_data != cache_map.end(); )
        {
            if (time_stamp - iter_data->first.time_stamp > NS_TEN_SECOND * 10)   // over 100s
            {
                PushSendNetWorkEvent(provider_id, opcode, iter->first, iter_data->second, iter_data->first);
                iter_data = cache_map.erase(iter_data);               
            }
            else
            {
                iter_data++;
            }
        }

        if (cache_map.size() <= 0)
            iter = network.erase(iter);
        else    
            iter++;
    }
    if (network.size() <= 0)
    {
        std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>>().swap(network);
    }

    if (clock() - sclock > 1)
    {
        LoggerRecord::WriteLog(L"CleanNetworkCache after time " + std::to_wstring(clock() - sclock), LogLevel::INFO);
    }
}
void EventRecordPruner::PushSendNetWorkEvent(uint_32 provider_id, int_32 opcode, DWORD process_id, uint_32 s_size, ProcessNetworkPrunCacheData net_data)
{
    if (Filter::GetInstance().IsSuperWhiteListProcess(process_id))	return;
    if (Filter::GetInstance().IsPrivilegeProcess(process_id)) return;

    EventRecord* rec = nullptr;
    if (provider_id == ETWTcpIp)
    {
        rec = new EventRecordTcpip;  
    }else if (provider_id == ETWUdpIp)
    {
        rec = new EventRecordUdpip;
    }

    if (rec != nullptr)
    {
        EventIdentifier temp_EventIdentifier(provider_id, opcode);
        rec->time_stamp_ = net_data.time_stamp;        
        rec->event_identifier_ = temp_EventIdentifier;
        rec->thread_id_ = net_data.thread_id;
        rec->process_id_ = process_id;

        //tcp/ip  udp 的都只要一个pid  PID 0 4
        ParameterValue parameter_value;
        parameter_value.d = process_id;
        rec->parameter_list_.push_back(parameter_value);

        //size 4 4
        parameter_value.d = s_size;
        rec->parameter_list_.push_back(parameter_value);

        //daddr 8 4
        parameter_value.d = net_data.d_ip;
        rec->parameter_list_.push_back(parameter_value);

        //saddr 12 4
        parameter_value.d = net_data.s_ip;
        rec->parameter_list_.push_back(parameter_value);

        //dport 16 2
        parameter_value.d = net_data.d_port;
        rec->parameter_list_.push_back(parameter_value);

        //sport 18 2
        parameter_value.d = net_data.s_port;
        rec->parameter_list_.push_back(parameter_value);

        if (InitCollector::GetCollector())
            InitCollector::GetCollector()->PushSendRecord(rec);
    }
}
/*
void EventRecordPruner::CleanNetworkCache(DWORD process_id)
{
    _process_tcp_send_cache.erase(process_id);
    _process_tcp_recv_cache.erase(process_id);
    _process_udp_send_cache.erase(process_id);
    _process_udp_recv_cache.erase(process_id);
}

void EventRecordPruner::CleanNetworkCache()
{    
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanNetworkCache: process_file_write_cache size before clean = " + std::to_wstring(_process_tcp_send_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>>().swap(_process_tcp_send_cache);
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanNetworkCache: file_process_read_cache size before clean = " + std::to_wstring(_process_tcp_recv_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>>().swap(_process_tcp_recv_cache);
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanNetworkCache: process_udp_send_cache size before clean = " + std::to_wstring(_process_udp_send_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>>().swap(_process_udp_send_cache);
    LoggerRecord::WriteLog(L"EventRecordPruner::CleanNetworkCache: process_tcp_send_cache size before clean = " + std::to_wstring(_process_udp_recv_cache.size()), LogLevel::INFO);
    std::unordered_map<DWORD, std::unordered_map<ProcessNetworkPrunCacheData, uint_32>>().swap(_process_udp_recv_cache);
}
*/
void EventRecordPruner::CleanNetworkCache(ULONG64 time_stamp)
{
    LoggerRecord::WriteLog(L"CleanNetworkCache: _process_tcp_send_cache size before clean = " + std::to_wstring(_process_tcp_send_cache.size()), LogLevel::INFO);
    CleanNetworkCache(_process_tcp_send_cache, time_stamp, ETWTcpIp, EM_TcpIpEventOPC::TcpIpSendIPV4);
    LoggerRecord::WriteLog(L"CleanNetworkCache: _process_tcp_recv_cache size before clean = " + std::to_wstring(_process_tcp_recv_cache.size()), LogLevel::INFO);
    CleanNetworkCache(_process_tcp_recv_cache, time_stamp, ETWTcpIp, EM_TcpIpEventOPC::TcpIpRecvIPV4);
    LoggerRecord::WriteLog(L"CleanNetworkCache: process_udp_send_cache size before clean = " + std::to_wstring(_process_udp_send_cache.size()), LogLevel::INFO);
    CleanNetworkCache(_process_udp_send_cache, time_stamp, ETWUdpIp, EM_UdpIpEventOPC::UdpIpSendIPV4);
    LoggerRecord::WriteLog(L"CleanNetworkCache: process_tcp_send_cache size before clean = " + std::to_wstring(_process_udp_recv_cache.size()), LogLevel::INFO);
    CleanNetworkCache(_process_udp_recv_cache, time_stamp, ETWUdpIp, EM_UdpIpEventOPC::UdpIpRecvIPV4);
}

bool EventRecordPruner::PrunTcpIpEvent(EventRecordTcpip * rec)
{
    if (!rec)	return true;

    auto process_id = rec->get_process_id_();
    auto thread_id = rec->get_thread_id_();
    auto event_opcode = rec->get_event_identifier_().opcode();
    auto time_stamp = rec->get_time_stamp_();
    /*
    if (time_stamp - _time_cache > NS_TEN_SECOND * 10)   // 100S
    {
        _time_cache = time_stamp;
        CleanNetworkCache(time_stamp);
    }   
    */
    uint_32 s_size = (uint_32)rec->GetDataParameter(parameter_index_enum::size);
    uint_32 s_ip = (uint_32)rec->GetDataParameter(parameter_index_enum::saddr);
    uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
    uint_32 d_ip = (uint_32)rec->GetDataParameter(parameter_index_enum::daddr);
    uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

    switch (event_opcode)
    {
    case EM_TcpIpEventOPC::TcpIpSendIPV4:
    {
        ProcessNetworkPrunCacheData cache_data(time_stamp, thread_id, s_ip, s_port, d_ip, d_port);
        auto& iter_f = _process_tcp_send_cache.find(process_id);
        if (iter_f == _process_tcp_send_cache.end())
        {
            // mod 20200306 first event send immediately but size set zero
            _process_tcp_send_cache[process_id][cache_data] = 0;
            return true;
        }
        else
        {
            auto& cache_map = iter_f->second;     
            auto& iter_data = cache_map.find(cache_data);
            if (iter_data == cache_map.end())
            {
                // mod 20200306 first event send immediately but size set zero
                _process_tcp_send_cache[process_id][cache_data] = 0;
                return true;
            }
            else
            {
                /*
                if (time_stamp - iter_data->first.time_stamp > NS_TEN_SECOND * 6)   // over one min
                {
                    s_size += iter_data->second;
                    rec->SetParameter(parameter_index_enum::size, s_size);
                    cache_map.erase(iter_data);
                    return true;
                }
                */

                iter_data->second += s_size;
                return false;
            }
        }
    }
        break;
    case EM_TcpIpEventOPC::TcpIpRecvIPV4:
    {
        ProcessNetworkPrunCacheData cache_data(time_stamp, thread_id, s_ip, s_port, d_ip, d_port);
        auto& iter_f = _process_tcp_recv_cache.find(process_id);
        if (iter_f == _process_tcp_recv_cache.end())
        {
            // mod 20200306 first event send immediately but size set zero
            _process_tcp_recv_cache[process_id][cache_data] = 0;         
            return true;
        }
        else
        {
            auto& cache_map = iter_f->second;
            auto& iter_data = cache_map.find(cache_data);           
            if (iter_data == cache_map.end())
            {
                // mod 20200306 first event send immediately but size set zero
                _process_tcp_recv_cache[process_id][cache_data] = 0;               
                return true;
            }
            else
            {
                /*
                if (time_stamp - iter_data->first.time_stamp > NS_TEN_SECOND * 6)   // over one min
                {
                    s_size += iter_data->second;
                    rec->SetParameter(parameter_index_enum::size, s_size);
                    cache_map.erase(iter_data);
                    return true;
                }
                */

                iter_data->second += s_size;
                return false;
            }
        }
    }
        break;
    default:
        break;
    }

    return true;
}

bool EventRecordPruner::PrunUdpIpEvent(EventRecordUdpip * rec)
{
    if (!rec)	return true;

    auto process_id = rec->get_process_id_();
    auto thread_id = rec->get_thread_id_();
    auto event_opcode = rec->get_event_identifier_().opcode();
    auto time_stamp = rec->get_time_stamp_();
    /*
    if (time_stamp - _time_cache > NS_TEN_SECOND * 10)   // 100S
    {
        _time_cache = time_stamp;
        CleanNetworkCache(time_stamp);
    }
    */
    uint_32 s_size = (uint_32)rec->GetDataParameter(parameter_index_enum::size);
    uint_32 s_ip = (uint_32)rec->GetDataParameter(parameter_index_enum::saddr);
    uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
    uint_32 d_ip = (uint_32)rec->GetDataParameter(parameter_index_enum::daddr);
    uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);

    switch (event_opcode)
    {
    case EM_UdpIpEventOPC::UdpIpSendIPV4:
    {
        ProcessNetworkPrunCacheData cache_data(time_stamp, thread_id, s_ip, s_port, d_ip, d_port);
        auto& iter_f = _process_udp_send_cache.find(process_id);
        if (iter_f == _process_udp_send_cache.end())
        {
            // mod 20200306 first event send immediately but size set zero
            _process_udp_send_cache[process_id][cache_data] = 0;
            return true;
        }
        else
        {
            auto& cache_map = iter_f->second; 
            auto& iter_data = cache_map.find(cache_data);
            if (iter_data == cache_map.end())
            {
                // mod 20200306 first event send immediately but size set zero
                _process_udp_send_cache[process_id][cache_data] = 0;
                return true;
            }
            else
            {
                /*
                if (time_stamp - iter_data->first.time_stamp > NS_TEN_SECOND * 6)   // over one min
                {
                    s_size += iter_data->second;
                    rec->SetParameter(parameter_index_enum::size, s_size);
                    cache_map.erase(iter_data);
                    return true;
                }
                */

                iter_data->second += s_size;
                return false;
            }
        }
    }
    break;
    case EM_UdpIpEventOPC::UdpIpRecvIPV4:
    {
        ProcessNetworkPrunCacheData cache_data(time_stamp, thread_id, s_ip, s_port, d_ip, d_port);
        auto& iter_f = _process_udp_recv_cache.find(process_id);
        if (iter_f == _process_udp_recv_cache.end())
        {
            // mod 20200306 first event send immediately but size set zero
            _process_udp_recv_cache[process_id][cache_data] = 0;
            return true;
        }
        else
        {
            auto& cache_map = iter_f->second;   
            auto& iter_data = cache_map.find(cache_data);
            if (iter_data == cache_map.end())
            {
                // mod 20200306 first event send immediately but size set zero
                _process_udp_recv_cache[process_id][cache_data] = 0;
                return true;
            }
            else
            {
                /*
                if (time_stamp - iter_data->first.time_stamp > NS_TEN_SECOND * 6)   // over one min
                {
                    s_size += iter_data->second;
                    rec->SetParameter(parameter_index_enum::size, s_size);
                    cache_map.erase(iter_data);
                    return true;
                }
                */

                iter_data->second += s_size;
                return false;
            }
        }
    }
        break;
    default:
        break;
    }

    return true;
}

bool EventRecordPruner::PrunRegistryEvent(EventRecordRegistry * rec) 
{
    if (!rec)	return true;
    auto event_opcode = rec->get_event_identifier_().opcode();
    auto event_keyname = ToolFunctions::WStringToString(rec->GetStringParameter(parameter_index_enum::KeyName));
    transform(event_keyname.begin(), event_keyname.end(), event_keyname.begin(), ::tolower);
    switch (event_opcode) {
    case EM_RegistryEventOPC::RegistryCreate:
    {
        if (g_registry_create_set.find(event_keyname) != g_registry_create_set.end())
            return true;
    }
    break;
    default:
        break;
    }

    return false;
}

#include "stdafx.h"
#include "sysmon_pruning.h"
#include "tool_functions.h"

std::unordered_map<DWORD, std::set<DWORD>> SysmonPruning::parentid_processid_map_;

SysmonPruning::SysmonPruning()
{
    time(&init_time_);
}


SysmonPruning::~SysmonPruning()
{
}

void SysmonPruning::LogCacheSize() const 
{
    LoggerRecord::WriteLog(L"SysmonPruning::LogCacheSize: process_file_write_cache size = " + std::to_wstring(parentid_processid_map_.size()), LogLevel::INFO);

}

void SysmonPruning::CleanCache() 
{
    time_t now_time;
    time(&now_time);
    if (now_time - init_time_ > 60*10)  // every 10min clean cache
    {
        init_time_ = now_time;
        LoggerRecord::WriteLog(L"SysmonPruning::CleanCache: parentid_processid_map_ size before clean = " + std::to_wstring(parentid_processid_map_.size()), LogLevel::INFO);
        std::unordered_map<DWORD, std::set<DWORD>>().swap(parentid_processid_map_);
    }  
}

bool SysmonPruning::pruningProcessAccess(DWORD ppid, DWORD pid) 
{
    SysmonPruning::GetInstance().CleanCache();

    auto iter_f = parentid_processid_map_.find(ppid);
    if (iter_f == parentid_processid_map_.end()) {
        parentid_processid_map_[ppid].insert(pid);
        return true;
    }
    else {
        auto& cache_set = iter_f->second;
        if (cache_set.find(pid) == cache_set.end()) {
            cache_set.insert(pid);
            return true;
        }
        else {
            return false;
        }
    }
    return false;
}

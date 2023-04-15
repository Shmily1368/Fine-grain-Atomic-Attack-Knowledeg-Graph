#pragma once

#include <Windows.h>
#include <unordered_map>
#include "event_record.h"

class SysmonPruning
{
    SINGLETON_DEFINITION(SysmonPruning);
    DISABLE_COPY(SysmonPruning);
public:
    SysmonPruning();
	~SysmonPruning();

    void LogCacheSize() const;
    void CleanCache();

	static bool pruningProcessAccess(DWORD ppid, DWORD pid);

private:
    static std::unordered_map<DWORD, std::set<DWORD>> parentid_processid_map_;
    time_t init_time_;
};


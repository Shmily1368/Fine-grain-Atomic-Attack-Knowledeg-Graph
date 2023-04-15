#pragma once
#include "lock_base.h"
#include <shared_mutex>

class RwLock : public LockBase
{
public:
	RwLock();
	virtual ~RwLock();

	virtual void Lock() override;
	virtual void Unlock() override;

	void ReadLock();
	void ReadUnlock();
	void WriteLock();
	void WriteUnlock();

private:
	std::shared_mutex _mutex;
};
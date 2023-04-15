#include "stdafx.h"
#include "auto_lock.h"
#include "lock_base.h"

AutoLock::AutoLock(LockBase& lock)
	: _lock(lock)
{
	_lock.Lock();
}

AutoLock::~AutoLock()
{
	_lock.Unlock();
}

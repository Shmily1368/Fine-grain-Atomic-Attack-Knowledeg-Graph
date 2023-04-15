#include "stdafx.h"
#include "rwlock.h"

RwLock::RwLock()
{

}

RwLock::~RwLock()
{

}

void RwLock::Lock()
{
	WriteLock();
}

void RwLock::Unlock()
{
	WriteUnlock();
}

void RwLock::ReadLock()
{
	_mutex.lock_shared();
}

void RwLock::ReadUnlock()
{
	_mutex.unlock_shared();
}

void RwLock::WriteLock()
{
	_mutex.lock();
}

void RwLock::WriteUnlock()
{
	_mutex.unlock();
}

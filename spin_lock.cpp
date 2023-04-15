#include "stdafx.h"
#include "spin_lock.h"

SpinLock::SpinLock()
{

}

SpinLock::~SpinLock()
{

}

void SpinLock::Lock()
{
	while (_flag.test_and_set(std::memory_order_acquire))
	{

	}
}

void SpinLock::Unlock()
{
	_flag.clear(std::memory_order_release);
}

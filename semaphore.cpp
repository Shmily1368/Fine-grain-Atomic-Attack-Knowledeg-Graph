#include "stdafx.h"
#include "semaphore.h"

Semaphore::Semaphore()
{

}

Semaphore::~Semaphore()
{

}

void Semaphore::Wait()
{
	std::unique_lock<std::mutex> unique_lock(_lock);
	_cond.wait(unique_lock);
}

void Semaphore::NotifyOne()
{
	std::unique_lock<std::mutex> unique_lock(_lock);
	_cond.notify_one();
}

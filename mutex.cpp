#include "stdafx.h"
#include "mutex.h"

Mutex::Mutex()
{

}

Mutex::~Mutex()
{

}

void Mutex::Lock()
{
	_mutex.lock();
}

void Mutex::Unlock()
{
	_mutex.unlock();
}


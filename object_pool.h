#pragma once
#include "concurrentqueue.h"

template<class T>
class ObjectPool
{
	DISABLE_COPY(ObjectPool);

public:
	ObjectPool(size_t cache_limit, bool instant_alloc = false);
	~ObjectPool();

	template<class... Args>
	T* Pop(Args&&... args);
	void Push(T* rcy_obj);

private:
	size_t _cache_limit;
	size_t _object_bytes;

	using ObjectQueue = moodycamel::ConcurrentQueue<void*>;
	ObjectQueue _cache_queue;
};

template<class T>
ObjectPool<T>::ObjectPool(size_t cache_limit, bool instant_alloc /*= false*/)
	: _cache_limit(cache_limit)
	, _object_bytes(sizeof(T))
{
	if (instant_alloc)
	{
		for (size_t i = 0; i < _cache_limit; ++i)
		{
			_cache_queue.enqueue(::operator new(_object_bytes));
		}
	}
}

template<class T>
ObjectPool<T>::~ObjectPool()
{
	void* raw_p;
	while (_cache_queue.try_dequeue(raw_p))
	{
		::operator delete(raw_p);
	}
}

template<class T>
template<class... Args>
T* ObjectPool<T>::Pop(Args&&... args)
{
	void* raw_p = nullptr;
	if (_cache_queue.try_dequeue(raw_p))
	{
		return new(raw_p) T(std::forward<Args>(args)...);
	}

	return new T(std::forward<Args>(args)...);
}

template<class T>
void ObjectPool<T>::Push(T* rcy_obj)
{
	rcy_obj->~T();

	if (_cache_queue.size_approx() < _cache_limit)
	{
		_cache_queue.enqueue((void*)rcy_obj);
	}
	else
	{
		::operator delete((void*)rcy_obj);
	}
}

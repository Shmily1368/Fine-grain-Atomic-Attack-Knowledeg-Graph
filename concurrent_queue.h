#pragma once
#include <thread>
#include <mutex>
template<typename Data>

class concurrent_queue

{

private:

	unsigned int _size;

	struct queue_block

	{

		Data q[0x40];

		unsigned short head, tail;

		queue_block *next;

		queue_block() { head = tail = 0; next = NULL; }

	};

	queue_block *head, *tail;



	mutable std::mutex the_mutex;

public:



	concurrent_queue() { _size = 0; head = tail = NULL;}

	~concurrent_queue()

	{

		while (head)

		{

			queue_block *p = head;

			head = head->next;

			delete p;
		}

	}

	void push(const Data& data)
	{

		std::lock_guard<std::mutex> lock(the_mutex);

		if (!head)

			head = tail = new queue_block;

		if (((tail->tail + 1) & 0x3f) == tail->head)

		{

			tail->next = new queue_block;

			tail = tail->next;

		}

		tail->q[tail->tail] = data;

		tail->tail = (tail->tail + 1) & 0x3f;

		_size++;

	}

	bool empty() const

	{

		std::lock_guard<std::mutex> lock(the_mutex);

		return head == NULL;

	}

	Data& front()

	{

		std::lock_guard<std::mutex> lock(the_mutex);

		return head->q[head->head];

	}

	bool front_pop(Data& newp)

	{
		std::lock_guard<std::mutex> lock(the_mutex);
		if (head == NULL) return false;
		newp = head->q[head->head];
		head->q[head->head] = nullptr;
		head->head = (head->head + 1) & 0x3f;

		if (head->head == head->tail)

		{

			queue_block *p = head;

			head = head->next;

			delete p;

		}

		_size--;
		return true;
	}


	Data const& front() const

	{

		std::lock_guard<std::mutex> lock(the_mutex);

		return head->q[head->head];

	}

	void pop()

	{

		std::lock_guard<std::mutex> lock(the_mutex);

		head->head = (head->head + 1) & 0x3f;

		if (head->head == head->tail)

		{

			queue_block *p = head;

			head = head->next;

			delete p;

		}

		_size--;

	}

	int size()

	{

		std::lock_guard<std::mutex> lock(the_mutex);

		return _size;

	}

};
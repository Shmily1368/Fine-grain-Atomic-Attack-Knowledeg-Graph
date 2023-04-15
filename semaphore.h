#pragma once

/********************************************************************
	Created:		2019-04-04
	Author:			xuduo;
	Version:		1.0.0(version);
	Description:	Semaphore;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019-04-04 |	1.0.0	 |	xuduo		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#include <condition_variable>

class Semaphore
{
	DISABLE_COPY(Semaphore);

public:
	Semaphore();
	~Semaphore();

	void Wait();
	void NotifyOne();

private:
	std::condition_variable _cond;
	std::mutex _lock;
};
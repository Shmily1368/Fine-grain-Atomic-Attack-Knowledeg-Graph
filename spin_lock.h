#pragma once

/********************************************************************
	Created:		2019-05-06
	Author:			xuduo;
	Version:		1.0.0(version);
	Description:	ÊµÏÖ×ÔÐýËø;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019-05-06 |	1.0.0	 |	xuduo		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#include "lock_base.h"
#include <atomic>

class SpinLock : public LockBase
{
public:
	SpinLock();
	virtual ~SpinLock();

	virtual void Lock() override;
	virtual void Unlock() override;

private:
	std::atomic_flag _flag = ATOMIC_FLAG_INIT;
};

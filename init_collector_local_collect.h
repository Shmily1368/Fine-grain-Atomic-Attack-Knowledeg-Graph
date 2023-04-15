/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(版本号);
	Description:	初始化采集器的离线采集子类，不适用offline作为类名的原因是与online太重合;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019.01.07    |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/
#pragma once
#include "init_collector.h"

class InitCollectorOfflineCollect : public InitCollector
{
public:
	InitCollectorOfflineCollect() : InitCollector(EM_InitCollectorMode::OFFLINE_COLLECT_MODE)
	{
	}

	virtual void Init() override;
	virtual void Excute() override;
	virtual void Clean() override;
	virtual void InitFilter() override;
};
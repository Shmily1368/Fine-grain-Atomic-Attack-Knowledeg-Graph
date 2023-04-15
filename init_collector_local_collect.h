/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(�汾��);
	Description:	��ʼ���ɼ��������߲ɼ����࣬������offline��Ϊ������ԭ������online̫�غ�;
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
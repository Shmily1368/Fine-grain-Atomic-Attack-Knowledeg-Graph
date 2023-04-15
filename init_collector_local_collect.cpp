#include "stdafx.h"
#include "init_collector_local_collect.h"

void InitCollectorOfflineCollect::Init()
{
	InitCallStackEnableEvent();
}

void InitCollectorOfflineCollect::Excute()
{
	_etw_configuration.ConfigureEtwSession(false, NULL);
}

void InitCollectorOfflineCollect::Clean()
{
	delete this;
}

void InitCollectorOfflineCollect::InitFilter()
{

}


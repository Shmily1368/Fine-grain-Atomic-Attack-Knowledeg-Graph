/********************************************************************
	Created:		2019-02-11
	Author:			chips;
	Version:		1.0.0(version);
	Description:	time util function;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/02/11 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#include "stdafx.h"
#include "time_util.h"
#include <time.h>
#include <stdio.h>

std::string TimeUtil::NowString()
{
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	char time_buf[256];
	snprintf(time_buf, 256, "%04d-%02d-%02d-%02d-%02d-%02d", timeinfo->tm_year + 1900,
		timeinfo->tm_mon + 1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

	return time_buf;
}

std::string TimeUtil::Today()
{
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	char time_buf[32];
	snprintf(time_buf, 32, "%04d-%02d-%02d", timeinfo->tm_year + 1900,
		timeinfo->tm_mon, timeinfo->tm_mday);

	return time_buf;
}

time_t TimeUtil::NowTimestamp() {
	return time(0);
}
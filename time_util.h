#pragma once

#include <ctime>

class TimeUtil
{
public:
	static std::string NowString();
	static std::string Today();
	static time_t NowTimestamp();
};
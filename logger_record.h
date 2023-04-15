#pragma once

#include <log4cplus\logger.h>
#include <log4cplus\configurator.h>
#include <log4cplus\layout.h> 
#include <log4cplus\loggingmacros.h> 
#include <log4cplus\helpers\stringhelper.h> 
#include <log4cplus\consoleappender.h>
#include <log4cplus\fileappender.h>

const log4cplus::tstring LOG_CONFIGUER_FILE_PATH(L"LogConfig.properites");
const log4cplus::tstring LOG_FILE_PATH(L"RunOutput.log");

enum LogLevel 
{ 
	TRACE,
	DEBUG,
	INFO,
	WARN,
	ERR,
	FATAL
};


using namespace log4cplus;
using namespace log4cplus::helpers;

class LoggerRecord
{
public:
	static void WriteLog(log4cplus::tstring contents, int level = DEBUG);
	static void InitLoggerRecord(bool console = false, log4cplus::tstring ConfigureFilePath = LOG_CONFIGUER_FILE_PATH, log4cplus::tstring OutputFilePath = LOG_FILE_PATH);

private:
	LoggerRecord(bool console = true, log4cplus::tstring ConfigureFilePath = LOG_CONFIGUER_FILE_PATH, log4cplus::tstring OutputFilePath = LOG_FILE_PATH);
	~LoggerRecord();
	static Logger logger;
};
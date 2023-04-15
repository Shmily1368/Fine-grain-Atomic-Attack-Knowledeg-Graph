#include "stdafx.h"

using namespace std;

Logger LoggerRecord::logger;

//Output in screen,only swt console = true
//Output in file,you can set ConfigureFilePath and OutputFilePath
//If use Configure file,the OutputFilePath should be set in config,not in here
LoggerRecord::LoggerRecord(bool console, log4cplus::tstring ConfigureFilePath, log4cplus::tstring OutputFilePath)
{
	/* step 1: Instantiate an appender object,define where to output, screen means console; file is path */
	SharedObjectPtr<Appender> _append;
	if (console)
	{
		_append = new ConsoleAppender();
		_append->setName(LOG4CPLUS_TEXT("Log in Screen"));
	}
	else
	{
		if (ConfigureFilePath.length() == 0)
		{
			_append = new FileAppender(OutputFilePath);
			_append->setName(LOG4CPLUS_TEXT("Log in File"));
		}
		else
		{
			log4cplus::initialize();
			PropertyConfigurator::doConfigure(ConfigureFilePath);
			logger = Logger::getRoot();
			return;
		}
	}

	/* step 2: Instantiate a layout object,define foramt */
	//std::string pattern = "%d{%m/%d/%y %H:%M:%S}  - %m [%l]%n";  
	//log4cplus::tstring pattern = LOG4CPLUS_TEXT("%d{%m/%d/%y %H:%M:%S}  - %m [%l]%n");
	log4cplus::tstring pattern = LOG4CPLUS_TEXT("| %D:%d{ %Q } | %p | %t | %l | %m | %n");
	std::auto_ptr<Layout> _layout(new PatternLayout(pattern));

	/* step 3: Attach the layout object to the appender */
	_append->setLayout(_layout);

	/* step 4: Instantiate a logger object */
	logger = Logger::getInstance(LOG4CPLUS_TEXT("test"));

	/* step 5: Attach the appender object to the logger*/
	logger.addAppender(_append);

	/* step 6:  Set a priority for the logger,can use var such as INFO_LOG_LEVEL to decide what level info output  */
	logger.setLogLevel(ALL_LOG_LEVEL);
}

LoggerRecord::~LoggerRecord()
{
	
}

void LoggerRecord::WriteLog(log4cplus::tstring contents, int level)
{
	switch (level)
	{
	case TRACE:
		LOG4CPLUS_TRACE(logger, contents); break;
	case DEBUG:
		LOG4CPLUS_DEBUG(logger, contents); break;
	case INFO:
		LOG4CPLUS_INFO(logger, contents); break;
	case WARN:
		LOG4CPLUS_WARN(logger, contents); break;
	case ERR:
		LOG4CPLUS_ERROR(logger, contents); break;
	case FATAL:
		LOG4CPLUS_FATAL(logger, contents); break;
	}
}

void LoggerRecord::InitLoggerRecord(bool console, log4cplus::tstring ConfigureFilePath, log4cplus::tstring OutputFilePath)
{
	/* step 1: Instantiate an appender object,define where to output, screen means console; file is path */
	//实例化一个 appender 对象，定义输出的位置，screen 表示控制台； 文件是路径 
	SharedObjectPtr<Appender> _append;
	if (console) {
		_append = new ConsoleAppender();
		_append->setName(LOG4CPLUS_TEXT("Log in Screen"));
	}
	else
	{
		if (ConfigureFilePath.length() == 0)
		{
			_append = new FileAppender(OutputFilePath);
			_append->setName(LOG4CPLUS_TEXT("Log in File"));
		}
		else
		{
			log4cplus::initialize();
			PropertyConfigurator::doConfigure(ConfigureFilePath);
			logger = Logger::getRoot();
			return;
		}
	}

	/* step 2: Instantiate a layout object,define foramt */
	//std::string pattern = "%d{%m/%d/%y %H:%M:%S}  - %m [%l]%n";  
	//log4cplus::tstring pattern = LOG4CPLUS_TEXT("%d{%m/%d/%y %H:%M:%S}  - %m [%l]%n");
	log4cplus::tstring pattern = LOG4CPLUS_TEXT("| %D:%d{ %Q } | %p | %t | %l | %m | %n");
	std::auto_ptr<Layout> _layout(new PatternLayout(pattern));

	/* step 3: Attach the layout object to the appender */
	_append->setLayout(_layout);

	/* step 4: Instantiate a logger object */
	logger = Logger::getInstance(LOG4CPLUS_TEXT("test"));

	/* step 5: Attach the appender object to the logger*/
	logger.addAppender(_append);

	/* step 6:  Set a priority for the logger,can use var such as INFO_LOG_LEVEL to decide what level info output  */
	logger.setLogLevel(ALL_LOG_LEVEL);
}
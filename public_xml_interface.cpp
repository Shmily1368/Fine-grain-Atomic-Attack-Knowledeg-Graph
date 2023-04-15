#include "stdafx.h"
#include "public_xml_interface.h"
#include "pugixml/pugixml.hpp"

bool public_xml_interface::ParseSecurityAudit(String szxml, std::unordered_map<String, String>& mdata)
{
	try
	{
		pugi::xml_document doc;
		if (!doc.load_string(szxml.c_str()))
		{
			LoggerRecord::WriteLog(L"ParseSecurityAudit load_string failed,error:" + std::to_wstring(GetLastError()), ERR);
			return false;
		}
		pugi::xml_node System = doc.child("Event").child("System");
		mdata["EventID"] = System.child_value("EventID");
		pugi::xml_node TimeCreated = System.child("TimeCreated");
		mdata["SystemTime"] = TimeCreated.attribute("SystemTime").value();
		pugi::xml_node Execution = System.child("Execution");
		mdata["ProcessID"] = Execution.attribute("ProcessID").value();
		mdata["ThreadID"] = Execution.attribute("ThreadID").value();

		pugi::xml_node EventData = doc.child("Event").child("EventData");
		for (pugi::xml_node Data = EventData.first_child(); Data; Data = Data.next_sibling())
		{
			std::string strName = Data.attribute("Name").value();
			if (!strName.empty())
			{
				mdata[strName] = Data.child_value();
			}
		}
	}
	catch (...)
	{
		LoggerRecord::WriteLog(L"ParseSecurityAudit catch exception,error:" + std::to_wstring(GetLastError()), ERR);
		return false;
	}
	
	return true;
}

bool public_xml_interface::ParseTaskContent(String szxml, std::unordered_map<String, String>& mdata)
{
    try
    {
        pugi::xml_document doc;
        if (!doc.load_string(szxml.c_str()))
        {
            LoggerRecord::WriteLog(L"ParseTaskContent load_string failed,error:" + std::to_wstring(GetLastError()), ERR);
            return false;
        }
        pugi::xml_node RegistrationInfo = doc.child("Task").child("RegistrationInfo");
        mdata["Date"] = RegistrationInfo.child_value("Date");
        mdata["Author"] = RegistrationInfo.child_value("Author");

        pugi::xml_node Exec = doc.child("Task").child("Actions").child("Exec");
        mdata["Command"] = Exec.child_value("Command");
    }
    catch (...)
    {
        LoggerRecord::WriteLog(L"ParseTaskContent catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return false;
    }

    return true;
}

bool public_xml_interface::ParseSysmon(String szxml, std::unordered_map<String, String>& mdata) 
{
    try {
        pugi::xml_document doc;
        if (!doc.load_string(szxml.c_str())) {
            LoggerRecord::WriteLog(L"ParseSysmon load_string failed,error:" + std::to_wstring(GetLastError()), ERR);
            return false;
        }
        pugi::xml_node System = doc.child("Event").child("System");
        mdata["EventID"] = System.child_value("EventID");

        pugi::xml_node EventData = doc.child("Event").child("EventData");
        for (pugi::xml_node Data = EventData.first_child(); Data; Data = Data.next_sibling()) {
            std::string strName = Data.attribute("Name").value();
            if (!strName.empty()) {
                mdata[strName] = Data.child_value();
            }
        }
    }
    catch (...) {
        LoggerRecord::WriteLog(L"ParseSecurityAudit catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return false;
    }

    return true;
}

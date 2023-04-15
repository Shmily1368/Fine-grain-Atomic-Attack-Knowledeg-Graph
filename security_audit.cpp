#include "stdafx.h"
#include "security_audit.h"
#include "json_include/rapidjson/writer.h"
#include "json_include/rapidjson/document.h"
#include "json_include/rapidjson/prettywriter.h"
#include "json_include/rapidjson/stringbuffer.h"
#include "public_xml_interface.h"
#include "common.h"
#include "tool_functions.h"
/*
std::unordered_set<long> security_set = {
	1102,
	4624,
	4625,
	4634,
	4657,
	4697,
	4698,
	4720,
	4723,
	4724,	
	4726,
	4738,
	4740,
	4794,
	5025
};
*/
std::unordered_set<long> security_set;
std::wstring wstrQuery;

void security_audit::Init()
{
    security_set.clear();

    std::fstream fp;
    String read_str;
    long event_id;

    fp.open("security_audit/security_event_set", ios::in | ios::binary);
    wstrQuery = L"*[System[(EventID=1100";
    while (getline(fp, read_str))
    {
        event_id = atol(ToolFunctions::DecryptStrEx(read_str).c_str());       
        security_set.insert(event_id);

        wstrQuery += L" or EventID=";
        wstrQuery += to_wstring(event_id);
    }
    fp.close();

    wstrQuery += L")]]";

    LoggerRecord::WriteLog(wstrQuery, INFO);
}

String security_audit::MakeSecurityAudit(std::unordered_map<String, String>& mdata, long& pid, long& tid)
{
	String strData = "";
	try
	{
		if (mdata.size() <= 0)
		{
			return "";
		}
		auto EventID = atol(mdata["EventID"].c_str());
		if (security_set.find(EventID) == security_set.end())
		{
            LoggerRecord::WriteLog(L"security_set is not EventID: " + to_wstring(EventID), LogLevel::WARN);
			return "";
		}

        pid = atol(mdata["ProcessID"].c_str());
        tid = atol(mdata["ThreadID"].c_str());
		auto SystemTime = mdata["SystemTime"];

        auto ProcessId = pid;
        auto iter = mdata.find("ProcessId");
        if (iter != mdata.end())
        {
            ProcessId = strtol(iter->second.c_str(), nullptr, 16);
        }

		// json
		rapidjson::Document record_document;
		rapidjson::Document::AllocatorType& doc_allocator = record_document.GetAllocator();
		rapidjson::Value rec_doc_root(rapidjson::kObjectType);
		rec_doc_root.AddMember("EventID", EventID, doc_allocator);
		rec_doc_root.AddMember("ProcessId", ProcessId, doc_allocator);
		//rec_doc_root.AddMember("ThreadId", ThreadId, doc_allocator);
		rec_doc_root.AddMember("SystemTime", rapidjson::StringRef(SystemTime.c_str()), doc_allocator);
		do 
		{
			if (EventID == SECURITY_LOG_CLEARED || EventID == SECURITY_FIREWALL_STOPPED)
			{
				break;
			}
            rapidjson::Value str_val;
            auto iter = mdata.find("SubjectUserName");
            if (iter != mdata.end())
            {
                auto TargetUserName = iter->second;                
                str_val.SetString(TargetUserName.c_str(), (rapidjson::SizeType)TargetUserName.length(), doc_allocator);
                rec_doc_root.AddMember("SubjectUserName", str_val, doc_allocator);
            }

            iter = mdata.find("SubjectDomainName");
            if (iter != mdata.end())
            {
                auto TargetDomainName = iter->second;
                str_val.SetString(TargetDomainName.c_str(), (rapidjson::SizeType)TargetDomainName.length(), doc_allocator);
                rec_doc_root.AddMember("SubjectDomainName", str_val, doc_allocator);
            }

            iter = mdata.find("TargetUserName");
            if (iter != mdata.end())
            {
                auto TargetUserName = iter->second;
                str_val.SetString(TargetUserName.c_str(), (rapidjson::SizeType)TargetUserName.length(), doc_allocator);
                rec_doc_root.AddMember("TargetUserName", str_val, doc_allocator);
            }

            iter = mdata.find("TargetDomainName");
            if (iter != mdata.end())
            {
                auto TargetDomainName = iter->second;
                str_val.SetString(TargetDomainName.c_str(), (rapidjson::SizeType)TargetDomainName.length(), doc_allocator);
                rec_doc_root.AddMember("TargetDomainName", str_val, doc_allocator);
            }

            iter = mdata.find("ProcessName");
            if (iter != mdata.end())
            {
                auto ProcessName = iter->second;
                str_val.SetString(ProcessName.c_str(), (rapidjson::SizeType)ProcessName.length(), doc_allocator);
                rec_doc_root.AddMember("ProcessName", str_val, doc_allocator);
            }
			
            
            if (EventID == SECURITY_ACCOUNT_LOGGED_OFF)
            {
                auto LogonType = atol(mdata["LogonType"].c_str());
                rec_doc_root.AddMember("LogonType", LogonType, doc_allocator);
            }
            else if (EventID == SECURITY_ACCOUNT_LOGGED_ON)
			{
				auto LogonType = atol(mdata["LogonType"].c_str());
				rec_doc_root.AddMember("LogonType", LogonType, doc_allocator);

                auto WorkstationName = mdata["WorkstationName"];
                str_val.SetString(WorkstationName.c_str(), (rapidjson::SizeType)WorkstationName.length(), doc_allocator);
                rec_doc_root.AddMember("WorkstationName", str_val, doc_allocator);

                auto IpAddress = mdata["IpAddress"];
                str_val.SetString(IpAddress.c_str(), (rapidjson::SizeType)IpAddress.length(), doc_allocator);
                rec_doc_root.AddMember("IpAddress", str_val, doc_allocator);

                auto IpPort = mdata["IpPort"];
                str_val.SetString(IpPort.c_str(), (rapidjson::SizeType)IpPort.length(), doc_allocator);
                rec_doc_root.AddMember("IpPort", str_val, doc_allocator);               
			}
			else if (EventID == SECURITY_ACCOUNT_LOGGED_FAILED)
			{			
				auto LogonType = atol(mdata["LogonType"].c_str());
				rec_doc_root.AddMember("LogonType", LogonType, doc_allocator);
				
                auto WorkstationName = mdata["WorkstationName"];
                str_val.SetString(WorkstationName.c_str(), (rapidjson::SizeType)WorkstationName.length(), doc_allocator);
                rec_doc_root.AddMember("WorkstationName", str_val, doc_allocator);

                auto Status = mdata["Status"];
				str_val.SetString(Status.c_str(), (rapidjson::SizeType)Status.length(), doc_allocator);
				rec_doc_root.AddMember("Status", str_val, doc_allocator);	

                auto IpAddress = mdata["IpAddress"];
                str_val.SetString(IpAddress.c_str(), (rapidjson::SizeType)IpAddress.length(), doc_allocator);
                rec_doc_root.AddMember("IpAddress", str_val, doc_allocator);

                auto IpPort = mdata["IpPort"];
                str_val.SetString(IpPort.c_str(), (rapidjson::SizeType)IpPort.length(), doc_allocator);
                rec_doc_root.AddMember("IpPort", str_val, doc_allocator);
			}
			else if (EventID == SECURITY_DSRM_CHANGE_PASSWORD)
			{
				auto Status = mdata["Status"];
				
				str_val.SetString(Status.c_str(), (rapidjson::SizeType)Status.length(), doc_allocator);
				rec_doc_root.AddMember("Status", str_val, doc_allocator);
			}
			else if (EventID == SECURITY_SERVICE_INSTALLED)
			{
				auto strValue = mdata["ServiceName"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ServiceName", str_val, doc_allocator);
				
				strValue = mdata["ServiceFileName"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ServiceFileName", str_val, doc_allocator);

				strValue = mdata["ServiceType"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ServiceType", str_val, doc_allocator);

				auto ServiceStartType = atol(mdata["ServiceStartType"].c_str());
				rec_doc_root.AddMember("ServiceStartType", ServiceStartType, doc_allocator);

				strValue = mdata["ServiceStartType"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ServiceStartType", str_val, doc_allocator);
			}
			else if (EventID == SECURITY_REGISTRY_MODIFIED)
			{
				auto strValue = mdata["ObjectName"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ObjectName", str_val, doc_allocator);

				strValue = mdata["ObjectValueName"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("ObjectValueName", str_val, doc_allocator);

				strValue = mdata["OldValue"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("OldValue", str_val, doc_allocator);

				strValue = mdata["NewValue"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("NewValue", str_val, doc_allocator);
			}
			else if (EventID == SECURITY_SCHEDULED_CREATED)
			{
				auto strValue = mdata["TaskName"];
				str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
				rec_doc_root.AddMember("TaskName", str_val, doc_allocator);

				strValue = mdata["TaskContent"];
                std::unordered_map<String, String> mtask;
                if (public_xml_interface::GetInstance().ParseTaskContent(strValue, mtask))
                {
                    rapidjson::Value argu_doc(rapidjson::kObjectType);

                    strValue = mtask["Date"];
                    str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
                    argu_doc.AddMember("Date", str_val, doc_allocator);

                    strValue = mtask["Author"];
                    str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
                    argu_doc.AddMember("Author", str_val, doc_allocator);

                    strValue = mtask["Command"];
                    str_val.SetString(strValue.c_str(), (rapidjson::SizeType)strValue.length(), doc_allocator);
                    argu_doc.AddMember("Command", str_val, doc_allocator);
                    
                    rec_doc_root.AddMember("TaskContent", argu_doc, doc_allocator);
                }              
			}			
		} while (0);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		rec_doc_root.Accept(writer);
		strData = buffer.GetString();		
	}
	catch (...)
	{
		LoggerRecord::WriteLog(L"MakeSecurityAudit catch exception,error:" + std::to_wstring(GetLastError()), ERR);
		return "";
	}
	
	return strData;
}

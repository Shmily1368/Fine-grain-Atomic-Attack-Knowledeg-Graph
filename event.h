#pragma once

#include <iostream>
#include <string>
#include "CJsonObject.hpp"
#include "tool_functions.h"
#include "event_record_manager.h"
using namespace std;

class argument {
public:
	string IrpPtr = "";
	string FileObject = "";
	int64 Offset = -1;
	int64 IoSize = -1;
	int64 IoFlags = -1;
	int64 CreateOptions = -1;
	int64 FileAttributes = -1;
	int64 ShareAccess = -1;
	string OpenPath = "";
	int64 ProcessId = -1;
	string ImageFileName = "";
	int32 size = -1;
	string magic = "";
	string sdhash = "";
	int32 action = -1;
	string toString(void) {                          //print the format which svm needs.
		stringstream ss;
		string output;
		ss << "{";
		ss << " IrpPtr:" << IrpPtr;
		ss << " FileObject:" << FileObject;
		ss << " Offset:" << Offset;
		ss << " IoSize:" << IoSize;
		ss << " IoFlags:" << IoFlags;
		ss << " CreateOptions:" << CreateOptions;
		ss << " FileAttributes:" << FileAttributes;
		ss << " ShareAccess:" << ShareAccess;
		ss << " OpenPath:" << OpenPath;
		ss << " ProcessId:" << ProcessId;
		ss << " ImageFileName:" << ImageFileName;
		ss << " size:" << size;
		ss << " magic:" << magic;
		ss << " action:" << action;
		ss << "}";
		output = ss.str();
		return output;
	}
};
class event{
public:
	event(){
		;
	}
	event(string eventname, int32 pid, int64 timestamp) {
		EventName = eventname;
		processID = pid;
		TimeStamp = timestamp;
	}
	event(string eventline) {                                           //use cJsonObject to parsr json and create event 
		neb::CJsonObject oJson(eventline);
		oJson.Get("processID", processID);
		string time;
		oJson.Get("TimeStamp", time);
		if (time != "") {
			TimeStamp = gettime(time);
		}
		if (oJson.Get("EventName", EventName)) {
			if (EventName == "ProcessStart" || EventName == "ProcessDCStart") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("ImageFileName", this->arguments.ImageFileName);
				arguments.Get("ProcessId", this->arguments.ProcessId);
			}
			else if (EventName == "ProcessEnd" || EventName == "ProcessDCEnd") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("ProcessId", this->arguments.ProcessId);
			}
			else if (EventName == "FileIoCreate") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("IrpPtr", this->arguments.IrpPtr);
				arguments.Get("FileObject", this->arguments.FileObject);
				arguments.Get("CreateOptions", this->arguments.CreateOptions);
				arguments.Get("FileAttributes", this->arguments.FileAttributes);
				arguments.Get("ShareAccess", this->arguments.ShareAccess);
				arguments.Get("OpenPath", this->arguments.OpenPath);
			}
			else if (EventName == "FileIoCleanup" || EventName == "FileIoDirEnum" || EventName == "FileIoDelete" || EventName == "FileIoRename") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("IrpPtr", this->arguments.IrpPtr);
				arguments.Get("FileObject", this->arguments.FileObject);
			}
			else if (EventName == "FileIoRead" || EventName == "FileIoWrite") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("IrpPtr", this->arguments.IrpPtr);
				arguments.Get("FileObject", this->arguments.FileObject);
				arguments.Get("Offset", this->arguments.Offset);
				arguments.Get("IoSize", this->arguments.IoSize);
				arguments.Get("IoFlags", this->arguments.IoFlags);
			}
			else if (EventName == "FileIoChange") {
				neb::CJsonObject arguments;
				oJson.Get("arguments", arguments);
				arguments.Get("size", this->arguments.size);
				arguments.Get("sdhash", this->arguments.sdhash);
				arguments.Get("FileObject", this->arguments.FileObject);
				arguments.Get("magic", this->arguments.magic);
				arguments.Get("action", this->arguments.action);
				if (!arguments.Get("OpenPath", this->arguments.OpenPath)) {
					this->arguments.OpenPath = this->arguments.FileObject;
				}
			}
		}
		else {
			oJson.Get("CallStack", CallStack);
		}
	};
	
	// add by zxw on 20191114
	event(EventRecord &ev) {   
		processID = ev.get_process_id_();
		TimeStamp = ev.get_time_stamp_();
		auto ix = EventRecordManager::GetInstance().event_strucp_map.find(ev.get_event_identifier_());
		if (ix != EventRecordManager::GetInstance().event_strucp_map.end())
		{
			EventName = ix->first.event_name();
		}

		if (ev.get_event_identifier_().provider_id() == ETWStackWalk)
		{
			CallStack = ev.get_callstack_();			
		}
		else
		{
			if (EventName == "ProcessStart" || EventName == "ProcessDCStart") {
				arguments.ImageFileName = ToolFunctions::WStringToString(ev.GetStringParameter(parameter_index_enum::ImageFileName));
				arguments.ProcessId = ev.GetDataParameter(parameter_index_enum::ProcessId);
			}
			else if (EventName == "ProcessEnd" || EventName == "ProcessDCEnd") {
				arguments.ProcessId = ev.GetDataParameter(parameter_index_enum::ProcessId);
			}
			else if (EventName == "FileIoCreate") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
				arguments.CreateOptions = ev.GetDataParameter(parameter_index_enum::CreateOptions);
				arguments.FileAttributes = ev.GetDataParameter(parameter_index_enum::FileAttributes);
				arguments.ShareAccess = ev.GetDataParameter(parameter_index_enum::ShareAccess);
				arguments.OpenPath = ToolFunctions::WStringToString(ev.GetStringParameter(parameter_index_enum::OpenPath));
			}
			else if (EventName == "FileIoCleanup" || EventName == "FileIoDirEnum" || EventName == "FileIoDelete" || EventName == "FileIoRename") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
			}
			else if (EventName == "FileIoRead" || EventName == "FileIoWrite") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
				arguments.Offset = ev.GetDataParameter(parameter_index_enum::Offset);
				arguments.IoSize = ev.GetDataParameter(parameter_index_enum::IoSize);
				arguments.IoFlags = ev.GetDataParameter(parameter_index_enum::IoFlags);
			}
			else if (EventName == "FileIoChange") {		// 暂无此事件，不做详细处理
				arguments.size = ev.GetDataParameter(parameter_index_enum::size);
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
			}
		}		
	};
	
	int64 gettime(string time) {            //transfer the timestamp from string to int64
		int64 timestamp = stoll(time.substr(0, time.length()-3), nullptr, 0);
		return timestamp;
	}
	// add by zxw on 20191203
	void set_time_stamp(time_t time_stamp) { _time_stamp = time_stamp; }
	time_t get_time_stamp() { return _time_stamp; }
	string toString(void) {                          //print the format which svm needs.
		stringstream ss;
		string output;
		ss << "{";
		ss << " EventName:" << EventName;
		ss << " processID:" << processID;
		ss << " TimeStamp:" << TimeStamp;
		ss << " CallStack:" << CallStack;
		ss << " arguments:" << arguments.toString();
		ss << "}";
		output = ss.str();
		return output;
	}
public:
	string EventName = "";
	int32 processID = -1;
	int64 TimeStamp = -1;
	string CallStack = "";
	argument arguments;
private:
	// add by zxw on 20191203
	time_t _time_stamp;
};
typedef event* pevent;

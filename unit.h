#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>

#include "CJsonObject.hpp"


using namespace std;

#define READ 0x00000001
#define DELETE 0x00000002
#define WRITE 0x00000004
#define RENAME 0x00000008
#define DIR_ENUM 0x00000010
#define UNKNOWN 0x0000100
#define NORMAL 0x00000200

class unit {
public:
	int32 pid = -1;
	int64 created_time = -1;
	//string identifier = "";
	int32 read_bytes = 0;
	int32 write_bytes = 0;
	string process_name = "";
	string action = "";
	vector<string> apis;
	vector<string> filepath;
	int32 file_c = 0;
	//int32 path_c = 0;
	//int32 dir_c = 0;
	vector<int32> file_similarity;
	int32 file_magic_number_change = 0;
	vector<vector<int32>> file_size;
	//double id = -1;
	//vector<string> type_c;
	//int isFinish;
	vector<string> tempEvents;
	unit(){
		;
	}
	unit(int32 Pid, int64 timestamp, string processname, string filePath) {
		pid = Pid;
		created_time = timestamp;
		process_name = processname;
		filepath.push_back(filePath);
	}
	void eventToInt(vector<int32> &eventint) {
		unordered_map<string, int>event_dict = { {"FileIoCreate",0},{"FileIoRead",1},{"FileIoWrite",2},{"FileIoDelete",3},{"FileIoRename",4},{"FileIoDirEnum",5},{"FileIoCleanup",6}};
		for (int i = 0; i < tempEvents.size(); i++)
		{
			if (event_dict.find(tempEvents[i]) != event_dict.end()) {
				eventint.push_back(event_dict[tempEvents[i]]);
			}
		}
		
	}
	void setAction(vector<int32> &eventint) {                                     //make the action after the unit is finish.
		int action_id = 0;
		if (eventint.size() >= 2 && eventint[0] == 0 && eventint[eventint.size() - 1] == 6) {
			if (find(eventint.begin(), eventint.end(), 1) != eventint.end()) {
				action_id |= READ;
			}
			if (find(eventint.begin(), eventint.end(), 2) != eventint.end()) {
				action_id |= WRITE;
			}
			if (find(eventint.begin(), eventint.end(), 3) != eventint.end()) {
				action_id |= DELETE;
			}
			else if (find(eventint.begin(), eventint.end(), 4) != eventint.end()) {
				action_id |= RENAME;
			}
			else if (find(eventint.begin(), eventint.end(), 5) != eventint.end()) {
				action_id |= DIR_ENUM;
			}
			else {
				action_id |= NORMAL;
			}
		}
		else {
			action_id |= UNKNOWN;
		}
		if ((action_id & READ) && (action_id & WRITE)) {
			//if (&*find(eventint.rbegin(), eventint.rend(), 2) - &*find(eventint.begin(), eventint.end(), 1) > 0) {
			//	action = "overwrite";
			//}
			//else {
			//	action = "write";
			//}
			action = "overwrite";
		}
		else if ((action_id & READ) && !(action_id & WRITE)) {
			action = "read";
		}
		else if ((action_id & WRITE) && !(action_id & READ)) {
			action = "write";
		}
		else if (action_id & RENAME) {
			action = "rename";
		}
		else if (action_id & DELETE) {
			action = "delete";
		}
		else if (action_id & DIR_ENUM) {
			action = "dir_enum";
		}
		else if (action_id & NORMAL) {
			action = "normal";
		}
		else {
			action = "unknown";
		}
	}
};
typedef unit* punit;


#pragma once
#include <iostream>
#include "CJsonObject.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;
class feature {
public:
	int32 pid = -1;
	string process_name = "";
	int32 ppid = -1;
	string pprocess_name = "";

	int32 write_c = 0;
	int32 file_magic_number_change = 0;
	int32 file_similarity = 0;

	int32 delete_c = 0;
	unordered_map<string, int32> file_type_r_table;
	unordered_map<string, int32> file_type_w_table;
	int32 file_type_r_c = 0;
	int32 file_type_w_c = 0;

	string action_interpretation;
	vector<string> action_path_interpretation;
	int32 irp2 = 0;
	int32 irp3 = 0;
	int32 dir_enum_c = 0;
	int32 read_c = 0;
	unordered_map<string, unordered_set<string>> path_hash_table;
	int64 starting_time = 0;
	int64 last_current_time = 0;
	int64 current_time = 0;
	int32 path_c = 0;
	int32 file_c = 0;

	int32 rename_c = 0;
	int32 overwrite_c = 0;

	double entropy_sum = 0;
	double entropy_write_read = 0;

	double r_speed = 0;
	double w_speed = 0;
	double d_speed = 0;
	double o_speed = 0;
	double read_frac = 0;
	double write_frac = 0;
	double delete_frac = 0;
	double rename_frac = 0;
	double file_size_change = 0;
	int32 api1 = 0;
	int32 api3 = 0;

	feature() {
		;
	}
	feature(int32 Pid, string processname) {
		pid = Pid;
		process_name = processname;
	}
	string toString(void) {                          //print the format which svm needs.
		stringstream ss;
		string output;
		ss << "0";
		ss << " 1:" << api1;
		ss << " 2:" << api3;
		ss << " 3:" << setiosflags(ios::fixed) << setprecision(2) << d_speed;
		ss << " 4:" << delete_c;
		ss << " 5:" << setiosflags(ios::fixed) << setprecision(2) << delete_frac;
		ss << " 6:" << dir_enum_c;
		ss << " 7:" << setiosflags(ios::fixed) << setprecision(2) << entropy_sum;
		ss << " 8:" << setiosflags(ios::fixed) << setprecision(2) << entropy_write_read;
		ss << " 9:" << file_magic_number_change;
		ss << " 10:" << file_similarity;
		ss << " 11:" << setiosflags(ios::fixed) << setprecision(2) << file_size_change;
		ss << " 12:" << file_type_r_c;
		ss << " 13:" << file_type_w_c;
		ss << " 14:" << irp2;
		ss << " 15:" << irp3;
		ss << " 16:" << setiosflags(ios::fixed) << setprecision(2) << o_speed;
		ss << " 17:" << overwrite_c;
		//ss << " 18:" << path_c;
		//ss << " 19:" << setiosflags(ios::fixed) << setprecision(2) << r_speed;
		//ss << " 20:" << read_c;
		//ss << " 21:" << setiosflags(ios::fixed) << setprecision(2) << read_frac;
		//ss << " 19:" << rename_c;
		//ss << " 20:" << setiosflags(ios::fixed) << setprecision(2) << rename_frac;
		//ss << " 21:" << setiosflags(ios::fixed) << setprecision(2) << w_speed;
		//ss << " 22:" << write_c;
		//ss << " 23:" << setiosflags(ios::fixed) << setprecision(2) << write_frac;
		output = ss.str();
		return output;
	}
	void update_timestamp(punit unit) {             //update the feature timestamp
		current_time = unit->created_time / (int64)1000000;
		if (starting_time == 0) {
			starting_time = current_time;
			last_current_time = current_time;
		}
	}
	void update_file_type(punit unit) {             //process file type change feature.
		if (unit->filepath.size() == 0) {
			return;
		}
		string path = unit->filepath[0];
		if (path.rfind('.') == -1) {
			return;
		}
		else {
			path = path.substr(path.rfind('.')+1);
			if (unit->action == "write" || unit->action == "overwrite") {
				if (file_type_w_table.find(path) == file_type_w_table.end()) {
					file_type_w_table.insert(pair<string, int32>{ path ,1 });
					file_type_w_c += 1;
				}
				else {
					file_type_w_table[path] += 1;
				}
			}
			if (unit->action == "read" || unit->action == "overwrite") {
				if (file_type_r_table.find(path) == file_type_r_table.end()) {
					file_type_r_table.insert(pair<string, int32>{ path ,1 });
					file_type_r_c += 1;
				}
				else {
					file_type_r_table[path] += 1;
				}
			}
		}
	}
	void update_action_path_i(punit unit) {            //record the unit actions.
		if (unit->action == "write") {
			action_path_interpretation.push_back(unit->filepath[0]);
			action_interpretation += "w";
		}
		else if (unit->action == "delete") {
			action_path_interpretation.push_back(unit->filepath[0]);
			action_interpretation += "d";
		}
		else if (unit->action == "read") {
			action_path_interpretation.push_back(unit->filepath[0]);
			action_interpretation += "r";
		}
		else if (unit->action == "overwrite") {
			action_path_interpretation.push_back(unit->filepath[0]);
			action_interpretation += "o";
		}
		else if (unit->action == "rename") {
			action_path_interpretation.push_back(unit->filepath[0]);
			action_interpretation += "n";
		}
	}
	void cal_access_frequency(punit unit) {           //record the action(read\write\delete\overwrite) speed.
		string path = unit->filepath[0];
		file_c += 1;
		if (path_hash_table.find(path) != path_hash_table.end()) {
			if (path_hash_table[path].find(unit->action) == path_hash_table[path].end()) {
				path_hash_table[path].insert(unit->action);
			}
			else {
				return;
			}
		}
		else {
			path_hash_table.insert(pair<string, unordered_set<string>>{ path , unordered_set<string>({unit->action}) });
		}
		path_c += 1;
		if (current_time <= starting_time) {
			return;
		}
		if (unit->action == "write") {
			write_c += 1;
		}
		else if (unit->action == "delete") {
			delete_c += 1;
		}
		else if (unit->action == "read") {
			read_c += 1;
		}
		else if (unit->action == "overwrite") {
			overwrite_c += 1;
		}
		else if (unit->action == "rename") {
			rename_c += 1;
		}
		else if (unit->action == "dir_enum") {
			dir_enum_c += 1;
		}
		if (unit->action == "write") {
			w_speed = double(write_c) / double(current_time - starting_time);
		}
		else if (unit->action == "delete") {
			d_speed = double(delete_c) / double(current_time - starting_time);
		}
		else if (unit->action == "read") {
			r_speed = double(read_c) / double(current_time - starting_time);
		}
		else if (unit->action == "overwrite") {
			o_speed = double(overwrite_c) / double(current_time - starting_time);
		}
		last_current_time = current_time;
	}
	void cal_fraction() {                          //record the fraction
		if (file_c <= 10) {
			return;
		}
		write_frac = double(write_c) / double(file_c);
		read_frac = double(read_c) / double(file_c);
		delete_frac = double(delete_c) / double(file_c);
		rename_frac = double(rename_c) / double(file_c);
	}
	void update_file_size_change(punit unit) {     //record the file change percentage which the process causes.
		double file_size_change0 = 0, file_size_change1 = 0;
		if (unit->action == "overwrite") {
			for (int i = 0; i < unit->file_size.size(); i++) {
				if (unit->file_size[i][0] != 0) {
					file_size_change1 += double(unit->file_size[i][1] - unit->file_size[i][0]);
					file_size_change0 += double(unit->file_size[i][0]);
				}
			}
			if (file_size_change0 != 0) {
				file_size_change = file_size_change1 / file_size_change0;
			}
		}
	}
	void cal_system_call(punit unit) {            //record some key crypt-apis' amount. 
		unordered_set<string>encryption = { "CryptImportKey","CryptDecrypt" };
		for (int i = 0; i < unit->apis.size(); i++) {
			if (encryption.find(unit->apis[i]) != encryption.end()) {
				api1 = 1;
				break;
			}
		}
	}
	void update_file_magic_number_change(punit unit) {   //update the file magic number's change amount.
		file_magic_number_change += unit->file_magic_number_change;
	}
	void update_file_similarity(punit unit) {           //update the file similarity's change amount.
		for (int i = 0; i < unit->file_similarity.size(); i++) {
			file_similarity += (100 - unit->file_similarity[i]);
		}
	} 
	void cal_irp_sequence() {                          //update the irp sequence which contains units'actions.
		unordered_set<string> r;
		unordered_set<string> rw;
		unordered_set<string> recorded2;
		unordered_set<string> recorded3;
		for (int i = 0; i < action_path_interpretation.size(); i++) {
			string s = action_path_interpretation[i];
			if (action_interpretation.at(i) == 'r') {
				r.insert(s);
			}
			else if (action_interpretation.at(i) == 'w') {
				if (r.find(s) != r.end()) {
					if (recorded2.find(s) == recorded2.end()) {
						irp2 += 1;
						recorded2.insert(s);
					}
				}
				else {
					rw.insert(s);
				}
			}
			else if (action_interpretation.at(i) == 'o') {
				if (recorded2.find(s) == recorded2.end()) {
					irp2 += 1;
					recorded2.insert(s);
				}
				if (rw.find(s) == rw.end() && r.find(s) != r.end()) {
					if (recorded3.find(s) == recorded3.end()) {
						irp3 += 1;
						recorded3.insert(s);
					}	
				}
			}
			else if (action_interpretation.at(i) == 'd') {
				if (rw.find(s) == rw.end() && r.find(s) != r.end()) {
					if (recorded3.find(s) == recorded3.end()) {
						irp3 += 1;
						recorded3.insert(s);
					}
				}
			}
		}
	}
	void update_api(vector<string>&apis) {               //record some key apis' amount. 
		unordered_set<string>sensitive = { "K32GetProcessImageFileName"};

		for (int i = 0; i < apis.size(); i++) {
			if (sensitive.find(apis[i]) != sensitive.end()) {
				api3 = 1;
				break;
			}
		}
	}
};
typedef feature* pfeature;
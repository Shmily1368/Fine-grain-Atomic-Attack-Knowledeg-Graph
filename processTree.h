#pragma once
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

typedef class process {
public:
	int pid = -1;
	string path = "";
	int64 startTime = -1;
	bool isalive = false;
	string parentName;
	int parentPid = -1;
	process *parent = NULL;          //parent process
	vector<process *> son;           //son process

	vector<string> apis;             //apis which process executes
	vector<unit> units;             //units which process executes
	unordered_map<string, unit> tempunits;
	vector<string> tempApis;

	process() {
		isalive = true;
	}
	process(int Pid) {
		pid = Pid;
		isalive = true;
	}
	process(int Pid, string Path, int64 StartTime) {
		pid = Pid;
		path = Path;
		startTime = StartTime;
		isalive = true;
	}
	void setParent(process * Parent) {
		parent = Parent;
	}
	void addSon(process * Son) {
		son.push_back(Son);
	}
}process, *pprocess;

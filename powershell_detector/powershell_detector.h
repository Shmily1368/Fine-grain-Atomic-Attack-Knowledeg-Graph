#pragma once
//#include"stdafx.h"
#include"../assist_macro.h"
#include <mutex>
#include<string>
#include<iostream>
#include<queue>
#include<thread>
#include<map>
#include<vector>
#include"powershellStruct.h"
using namespace std;

class powershell_detector
{
	SINGLETON_DEFINITION(powershell_detector)
public:

	~powershell_detector();
	int  Init();
	void stop() { runable = 0; };
	void AddScript(string& script, int pid, int tid);

private:
	powershell_detector();
	int Thread_run();
	int runable;
	mutex m;
	std::thread t_detector;
	queue<powershell_Input> powershell_fileList;
	string get_random_filename(int len);
	string strTolower(string& temp);
	powershell_Result Check_code(string& code);
	vector<string> profileBehaviors(string& originalData, string& alternativeData);
	string vectorToString(vector<string>& behaviorTag);
	map<string, double> scoreValues;
	map<string ,vector<vector<string>>> behaviorCol;
	vector<vector<string>> behaviorCombos;
	vector<string> c1, c2, c3;
};


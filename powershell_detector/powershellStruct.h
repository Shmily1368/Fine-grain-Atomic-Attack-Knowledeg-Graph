#pragma once
#include<string>
#include<iostream>
#include<queue>
#include<thread>
using namespace std;
class powershell_Result {
public:
	int score;
	int pid;
	int tid;
	string verdict;
	string content;
	string command;
	powershell_Result() :score(0), pid(0), tid(0), verdict(), content(),command() {};
	string stringouput();
	//powershell_Result(int score,int pid,int tid ,string ver,string cont) :score(score),pid(pid),tid(tid), verdict(ver), content(cont) {};
	friend  ostream& operator<< (ostream& os, const powershell_Result& a);
	static powershell_Result dealResult(string& result, int pid, int tid);
};
class powershell_Input {
public:
	int pid;
	int tid;
	string scriptcontent;
	powershell_Input() :pid(pid), tid(tid), scriptcontent() {};
	powershell_Input(int pid, int tid, string content) :pid(pid), tid(tid), scriptcontent(content) {};

};
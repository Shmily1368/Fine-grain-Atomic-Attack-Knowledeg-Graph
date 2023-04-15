#include "stdafx.h"
#include"unit.h"
#include "event.h"
#include "processTree.h"
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <sys\stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "setting.h"

//#include <unistd.h>

unordered_map<int, pprocess> processTree;                         //the tree which contains live processes
vector<pprocess> processUnitTree;                                 //the vector which contains the processes which has unit to transfer to feature and detect.
unordered_map<string, vector<string>> fileMap;                    //the map which contains the files' sdhash.
int32 file_c = 0;
string magic_path = "tool\\file\\bin\\file.exe -b \"";
string sdhash_path = "tool\\sdhash\\sdhash.exe \"";
string compare_path = "tool\\sdhash\\sdhash.exe -c file.tmp -t 0";
string event_path = "output\\event.out";

string trim(string s) {
	size_t n = s.find_last_not_of("\r\n");
	if (n != string::npos) {
		s.erase(n + 1, s.size() - n);
	}
	n = s.find_first_not_of(" \r\n\t");
	if (n != string::npos) {
		s.erase(0, n);
	}
	return s;
}
void processEvent(event& singleEvent) {
	//if (Setting::GetInstance().enable_ransom_output())
	//{
	//	ofstream write(event_path, ios::app);
	//	write << singleEvent.toString() << endl;
	//	write.close();
	//}
	if (singleEvent.EventName != "") {                                                  //deal with different kinds of event
		if (singleEvent.EventName == "ProcessDCStart" || singleEvent.EventName == "ProcessStart") {
			if (singleEvent.arguments.ImageFileName.find("explorer") != -1) {
				return;
			}
			pprocess newProcess = new process(singleEvent.arguments.ProcessId, singleEvent.arguments.ImageFileName, singleEvent.TimeStamp);
			newProcess->parentPid = singleEvent.processID;
			if (processTree.find(singleEvent.processID) == processTree.end()) {
				pprocess parentProcess = new process(singleEvent.processID);
				parentProcess->addSon(newProcess);
				newProcess->setParent(parentProcess);
				newProcess->parentName = parentProcess->path;
				processUnitTree.push_back(parentProcess);
				processUnitTree.push_back(newProcess);
				processTree.insert(pair<int, pprocess>{ parentProcess->pid ,parentProcess });
				processTree.insert(pair<int, pprocess>{ newProcess->pid ,newProcess });
			}
			else {
                // add by zxw on 20200609
                bool isfind = false;
                auto iters = processUnitTree.begin();
                while (iters != processUnitTree.end()) {
                    auto ppro = *iters;
                    if (ppro->pid == newProcess->pid) {
                        pprocess parentProcess = processTree[singleEvent.processID];
                        ppro->path = newProcess->path;
                        ppro->startTime = newProcess->startTime;
                        ppro->isalive = newProcess->isalive;
                        ppro->setParent(parentProcess);
                        ppro->parentName = parentProcess->path;
                        ppro->parentPid = newProcess->parentPid;
                        parentProcess->addSon(ppro);

                        if (processTree.find(newProcess->pid) != processTree.end()) {
                            processTree[newProcess->pid] = ppro;
                            isfind = true;
                        }

                        break;
                    }
                    iters++;
                }
                if (isfind) {
                    delete newProcess; newProcess = nullptr;
                }
                else {
                    pprocess parentProcess = processTree[singleEvent.processID];
                    parentProcess->addSon(newProcess);
                    newProcess->setParent(parentProcess);
                    newProcess->parentName = parentProcess->path;// add by zxw on 20191211
                    processTree.insert(pair<int, pprocess>{ newProcess->pid, newProcess });
                    processUnitTree.push_back(newProcess);
                }
			}
		}
		else if (singleEvent.EventName == "ProcessEnd" || singleEvent.EventName == "ProcessDCEnd") {
			if (processTree.find(singleEvent.processID) != processTree.end()) {
				pprocess Process = processTree[singleEvent.arguments.ProcessId]; //when isalive == false, remove the process from processTree
				Process->isalive = false;                     //when units.size()==0 and isalive == false, remove the process from processUnitTree and delete the process
				processTree.erase(singleEvent.arguments.ProcessId);
			}
		}
		else {
			pprocess Process;
			if (processTree.find(singleEvent.processID) != processTree.end()) {
				Process = processTree[singleEvent.processID];
			}
			else {
				return;
				//Process = new process(singleEvent.processID);
				//processTree.insert(pair<int, pprocess>{ Process->pid, Process });
				//processUnitTree.push_back(Process);

			}
			if (singleEvent.EventName == "FileIoCreate") {
				unit newUnit(singleEvent.processID, singleEvent.TimeStamp, Process->path, singleEvent.arguments.OpenPath);
				newUnit.tempEvents.push_back(singleEvent.EventName);
				Process->tempunits.insert(pair<string, unit>{ singleEvent.arguments.FileObject ,newUnit });
			}
			else if (Process->tempunits.find(singleEvent.arguments.FileObject) != Process->tempunits.end()) {
				punit Unit = &(Process->tempunits[singleEvent.arguments.FileObject]);
				Unit->tempEvents.push_back(singleEvent.EventName);
				if (singleEvent.EventName == "FileIoRead") {
					Unit->read_bytes += singleEvent.arguments.IoSize;
				}
				else if (singleEvent.EventName == "FileIoWrite") {
					Unit->write_bytes += singleEvent.arguments.IoSize;
					event FileIoChange("FileIoChange", singleEvent.processID, singleEvent.TimeStamp);
					FileIoChange.arguments.action = 2;
					FileIoChange.arguments.FileObject = singleEvent.arguments.FileObject;
					if (Unit->filepath.size() <= 0) {
						return;
					}
					string openpath = Unit->filepath[0];
					FileIoChange.arguments.OpenPath = openpath;        //get the file's sdhash, magic number and filesize. 
					if (openpath != "" && openpath.find("file.tmp") == -1 && openpath.find("output.out") == -1 && openpath.find("allfeature.out") == -1 && openpath.find("features.all") == -1) {
						struct _stat info;
						if (_stat(openpath.c_str(), &info)!=0) {
							//cout << "get file size fail:" << openpath << endl;
							return;
						}
						FileIoChange.arguments.size = info.st_size;
						ifstream input(openpath, ios::binary);
						char magic[5] = { 0 };
						if (input.is_open()) {
							input.seekg(0, ios::beg);
							input.read((char*)magic, sizeof(magic)-1);
						}
						else {
							//cout << "get file magic number fail:" << openpath << endl;
							return;
						}
						FileIoChange.arguments.magic = magic;         //用文件读取字节直接代替file.exe

						//FILE *fp = _popen((magic_path + openpath + "\"").c_str(), "r");
						//if (!fp) {
						//	perror("magic popen error");
						//	_pclose(fp);
						//	return;
						//}
						//char s[1024];
						//while ((fgets(s, 1024, fp)) != NULL)
						//{
						//	FileIoChange.arguments.magic += s;
						//}
						//if (FileIoChange.arguments.magic.find("cannot open") != -1) {
						//	FileIoChange.arguments.magic = "";
						//}
						//_pclose(fp);
						//fp = _popen((sdhash_path + openpath + "\"").c_str(), "r");
						//if (!fp) {
						//	perror("sdhash file popen error");
						//	_pclose(fp);
						//	return;
						//}
						//char ts[1024];
						//while ((fgets(ts, 1024, fp)) != NULL)
						//{
						//	FileIoChange.arguments.sdhash += ts;
						//}
						//_pclose(fp);
						//string t = openpath;
						//if (t.find(':') != -1) {
						//	t = t.replace(t.find(':'), 1, "-");
						//	if (FileIoChange.arguments.sdhash.find(openpath) != -1) {
						//		FileIoChange.arguments.sdhash.replace(FileIoChange.arguments.sdhash.find(openpath), t.size(), t);
						//	}
						//}
						processEvent(FileIoChange);    //call fileiochange when write events happen.
					}

				}
				else if (singleEvent.EventName == "FileIoChange") {
					if (fileMap.find(singleEvent.arguments.OpenPath) != fileMap.end()) {
						vector<string> &file  = fileMap[singleEvent.arguments.OpenPath];
						int32 oldsize = atoi(file[0].c_str());
						vector<int32> size = { oldsize, singleEvent.arguments.size };
						Unit->file_size.push_back(size);
						file[0] = to_string(singleEvent.arguments.size);
						if (file[1] != singleEvent.arguments.magic && file[1] != "" && singleEvent.arguments.magic != "") {
							Unit->file_magic_number_change += 1;
						}
						if (singleEvent.arguments.magic != "") {
							file[1] = singleEvent.arguments.magic;
						}
						if (file[2] != "" && singleEvent.arguments.sdhash != "") {
							ofstream tempfile("file.tmp");
							tempfile << trim(file[2]) << endl << trim(singleEvent.arguments.sdhash);
							tempfile.close();
							FILE *fp = _popen(compare_path.c_str(), "r");
							if (!fp) {
								perror("sdhash compare popen error");
								_pclose(fp);
							}
							else {
								string temp;
								char ts[1024];
								while ((fgets(ts, 1024, fp)) != NULL)
								{
									temp += ts;
								}
								if (temp.size() >= 3 && (atoi(temp.substr(temp.size() - 3, 3).c_str()) > 0 || temp.substr(temp.size() - 3, 3) == "000")) {
									Unit->file_similarity.push_back(atoi(temp.substr(temp.size() - 3, 3).c_str()));
								}
								_pclose(fp);
							}
						}
						if (singleEvent.arguments.sdhash != "") {
							file[2] = singleEvent.arguments.sdhash;
						}						
					}
					else {
						vector<string> file = { to_string(singleEvent.arguments.size) ,singleEvent.arguments.magic ,singleEvent.arguments.sdhash };
						if (fileMap.size() > 100000) {
							fileMap.erase(fileMap.begin());
						}
						fileMap.insert(pair<string, vector<string>>{ singleEvent.arguments.OpenPath ,file });
						vector<int32> size = { singleEvent.arguments.size, singleEvent.arguments.size };
						Unit->file_size.push_back(size);
						file_c += 1;
						//Unit->file_magic_number_change += 1;
						Unit->file_similarity.push_back(100);
					}
				}
				else if (singleEvent.EventName == "FileIoCleanup") {
					vector<int32> eventint;
					Unit->eventToInt(eventint);
					Unit->setAction(eventint);
					Unit->apis.swap(Process->tempApis);
					if (Unit->action == "normal") {
						Process->tempunits.erase(singleEvent.arguments.FileObject);
						return;
					}
					Process->units.push_back(*Unit);
					Process->tempunits.erase(singleEvent.arguments.FileObject);
				}
			}
		}
		
	}
    else if (singleEvent.CallStack != "") {
        if (processTree.find(singleEvent.processID) != processTree.end())
        {
            pprocess Process = processTree[singleEvent.processID];
            Process->tempApis.push_back(singleEvent.CallStack);
            Process->apis.push_back(singleEvent.CallStack);
        }
    }

}

#include "stdafx.h"
#include "filter.h"
#include "get_device_drive_map.h"
#include "obtain_entry_address.h"
#include "tool_functions.h"
#include "init_collector.h"
#include <windows.h>
#include <winnt.h>
#include <psapi.h>
//#pragma comment(lib, "Psapi.lib")
#include <tlhelp32.h>

#include <stdio.h>
#include <fstream>

#include <ctype.h>
#include <algorithm>
#include <io.h>
#include <algorithm>

using namespace std;
wfstream ObtainEntryAddress::confict_file_("conflict_api.list");
btree ObtainEntryAddress::rva2FuncNameTree;
std::unordered_map<std::wstring, btree> ObtainEntryAddress::DLLmodualTree;
btree* ObtainEntryAddress::moduleAddressTree[Max_Process_ID];
GetDeviceDriveMap ObtainEntryAddress::drivemap;
std::unordered_map<std::wstring, btree*> ObtainEntryAddress::module_btree_map;
std::unordered_map<std::wstring, std::vector<dllAddress>> ObtainEntryAddress::dll_module_vector;
std::wstring ObtainEntryAddress::current_module_name_;
ULONG64 ObtainEntryAddress::current_module_size_;
std::unordered_map<DWORD, dllAddress> ObtainEntryAddress::exe_node_map;

ObtainEntryAddress::ObtainEntryAddress() {
	init();
}

ObtainEntryAddress::~ObtainEntryAddress() {
}


wstring getLastSplit(wstring path){
	return path.substr(path.find_last_of('\\'),path.length());
}

wstring ConvertCharToLPWSTR(const char * szString)
{
	wstring wstResult;
	int dwLen = (int)strlen(szString) + 1;
	int nwLen = MultiByteToWideChar(CP_ACP, 0, szString, dwLen, NULL, 0);//算出合适的长度
	LPWSTR lpszPath = new WCHAR[dwLen];
	MultiByteToWideChar(CP_ACP, 0, szString, dwLen, lpszPath, nwLen);
	wstResult = lpszPath;
	if (lpszPath)
	{
		delete[] lpszPath;
		lpszPath = NULL;
	}
	return wstResult;
}

int ObtainEntryAddress::init() {
	drivemap.getDeviceDriveMap();

	return 0;
}

int ObtainEntryAddress::stop() {
	printAllModuleRva();
	return 0;
}

int ObtainEntryAddress::addCommonModulesToSet(string folderPath){
	_finddata_t file;
	long flag;
	string fileName = folderPath + "\\*.dll";
	string fullPath;
	if ((flag = (long)_findfirst(fileName.c_str(), &file)) == -1) {
#ifdef OUTPUT_COMMAND_LINE
        cout << "There are no dll file in " << folderPath << endl;
#endif // OUTPUT_COMMAND_LINE;		
	}
	else {
		fullPath = folderPath + "\\" + file.name;
		//cout << fullPath << endl;
		moduleSet.insert(ConvertCharToLPWSTR(fullPath.c_str()));
		while (_findnext(flag, &file) == 0){
			fullPath = folderPath + "\\" + file.name;
			//cout << fullPath << endl;
			moduleSet.insert(ConvertCharToLPWSTR(fullPath.c_str()));
		}
	}

	return 0;
}

int ObtainEntryAddress::getModuleBaseAddress(DWORD processID) {
	HMODULE hMods[1024];

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (NULL == hProcess) return 1;

	DWORD cbNeeded;
	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded,LIST_MODULES_ALL)) {
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				//_tprintf(TEXT("\t%s(0x%08X)\n"), szModName, hMods[i]);
				//cout << hMods[i] << ":" << string(szModName) << endl;
				moduleName2BaseAddrMap[wstring(szModName)] = hMods[i];
				moduleSet.insert(wstring(szModName));
			}
		}
	}

	return 0;
}

int ObtainEntryAddress::printModuleBaseAddress(DWORD processID) {
	wofstream processModuleFile(CacheFilePath 
		+ "process2Module/" 
		+ to_string(processID) + ".process2Module");
#ifdef OUTPUT_COMMAND_LINE
	cout << //CacheFilePath + 
		"process2Module/" + to_string(processID) + ".process2Module" << endl;
#endif // OUTPUT_COMMAND_LINE;
	for (auto iter2 = moduleName2BaseAddrMap.begin(); iter2 != moduleName2BaseAddrMap.end(); iter2++) {
		processModuleFile << drivemap.formatFilePathDrive( iter2->first.c_str()) << ":" << iter2->second << endl;
	}
	processModuleFile.close();
	return 0;
}

void ObtainEntryAddress::getAllProcess() {
	DWORD processList[MAX_MODULE_LENGTH];
	DWORD cbNeeded;
	DWORD cProcesses;
	if (!EnumProcesses(processList, sizeof(processList), &cbNeeded)) {
#ifdef OUTPUT_COMMAND_LINE	
		cout << "Allocted space for processes list is too small!" << endl;
#endif // OUTPUT_COMMAND_LINE;
	}

	cProcesses = cbNeeded / sizeof(DWORD);
	TCHAR szProcessName[MAX_MODULE_LENGTH];
	for (DWORD i = 0; i < cProcesses; i++) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processList[i]);
		GetModuleBaseName(hProcess, NULL, szProcessName, MAX_MODULE_LENGTH);
		processID2ProcessNameMap[processList[i]] = szProcessName;
		CloseHandle(hProcess);
	}
#ifdef OUTPUT_COMMAND_LINE	
	cout << cProcesses << " processes' id to name map built!" << endl;
#endif // OUTPUT_COMMAND_LINE;
}

void ObtainEntryAddress::getFuncAddr(HMODULE hModule, HMODULE baseAddr) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	PDWORD pAddressName = PDWORD((PBYTE)hModule + pExportDirectory->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);
	PDWORD pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions);

	for (DWORD i = 0; i < (pExportDirectory->NumberOfNames); i++) {
		PCHAR pFunc = (PCHAR)((PBYTE)hModule + *pAddressName++);
		DWORD rva = (DWORD)((PBYTE)hModule + pAddresOfFunction[*pAddressOfNameOrdinals++]);
		//printf("%x:%s\n", rva + baseAddr, pFunc);
#ifdef OUTPUT_COMMAND_LINE
		cout << hex << baseAddr + rva << ":" << string(pFunc) << endl;
#endif // OUTPUT_COMMAND_LINE;	
		rva2FuncNameMap[baseAddr + rva] = ConvertCharToLPWSTR(pFunc);
	}
}

//int ObtainEntryAddress::addCommonModulesToSet(string folderPath){
//	_finddata_t file;
//	long flag;
//	string fileName = folderPath + "\\*.dll";
//
//	
//	return 0;
//}

btree* ObtainEntryAddress::getModuleRva(LPVOID hModule) {
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PDWORD pAddressName;
	PWORD pAddressOfNameOrdinals;
	PDWORD pAddresOfFunction;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		LoggerRecord::WriteLog(L"Not PE file: " + current_module_name_, DEBUG);
		return NULL;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		LoggerRecord::WriteLog(L"Not PE file-2: " + current_module_name_, DEBUG);
		return NULL;
	}
	if (pNtHeader->FileHeader.Machine == 0x014c) {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(((PIMAGE_NT_HEADERS32)pNtHeader)->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	}
	else {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);
	}
	
	pAddressName = PDWORD((PBYTE)hModule + pExportDirectory->AddressOfNames);
	pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);
	pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions);

	if (pExportDirectory->AddressOfFunctions + pExportDirectory->AddressOfNames == 0 || pExportDirectory->NumberOfNames == 0)
		return NULL;

	btree* rva_tree = new btree;

	std::vector<dllAddress> temp_DllAddress_vector;
	std::unordered_map<ULONG64,dllAddress> temp_DLLAddress_map;
	for (DWORD i = 0; i < (pExportDirectory->NumberOfNames) -1; i++) {
		if ((ULONG64)(pAddressName - (PDWORD)hModule) >= current_module_size_) {
			LoggerRecord::WriteLog(L"Error in" + current_module_name_, DEBUG);
			break;
		}
		if ((ULONG64)(pAddressOfNameOrdinals - (PWORD)hModule) >= current_module_size_){
			LoggerRecord::WriteLog(L"Error in" + current_module_name_, DEBUG);
			break;
		}
		PCHAR pFunc = (PCHAR)((PBYTE)hModule + *pAddressName++);
		DWORD rva =  pAddresOfFunction[*pAddressOfNameOrdinals];
		dllAddress tmpAddress;
		tmpAddress.FileName =  ToolFunctions::WStringToString(ConvertCharToLPWSTR(pFunc));
		tmpAddress.ImageBase = rva;
		//if (InitCollector::GetFlag() & ETW_Collector_Online_FullCallStack_Parse_Mode) {
		//	wstring temp = current_module_name_.substr(2) + L":" + tmpAddress.FileName;
		//	if (Filter::QueryUselessAPIList(temp)) {
		//		tmpAddress.useless = TRUE;
		//	}
		//}
		tmpAddress.rva_tree = NULL;
		temp_DLLAddress_map[rva] = tmpAddress;
		//(*rva_tree).insert(tmpAddress);
		pAddressOfNameOrdinals++;
	}
	for (auto iter = temp_DLLAddress_map.begin(); iter != temp_DLLAddress_map.end(); iter++) {
		temp_DllAddress_vector.push_back(iter->second);
	}
	// sort before set dll_end
	std::sort(temp_DllAddress_vector.begin(), temp_DllAddress_vector.end(),  DllAddress_compare);
	for (auto iter = temp_DllAddress_vector.begin(); iter != temp_DllAddress_vector.end(); iter++) {
		if (iter == temp_DllAddress_vector.end() - 1) {
			iter->ImageEnd = INT_MAX;
		}
		else {
			iter->ImageEnd = (iter + 1)->ImageBase;
		}
	}
	

	random_shuffle(temp_DllAddress_vector.begin(), temp_DllAddress_vector.end());
	dll_module_vector[current_module_name_] = temp_DllAddress_vector;
	for (auto iy = temp_DllAddress_vector.begin(); iy != temp_DllAddress_vector.end(); iy++) {
		//LoggerRecord::WriteLog(iy->FileName + L',' + std::to_wstring(iy->ImageBase) + L',' + std::to_wstring(iy->ImageEnd), DEBUG);
		rva_tree->insert(*iy);
	}

	return rva_tree;
}

btree* ObtainEntryAddress::getModuleRvaFromFileName(wstring moduleName) {
	if (module_btree_map.count(moduleName) != 0) {
		return module_btree_map[moduleName];
	}

	if ((!ToolFunctions::isEndWith((moduleName).c_str(), L".dll")) && (!ToolFunctions::isEndWith((moduleName).c_str(), L".DLL")) )//|| (moduleName.size()>70))
		return NULL;

	HANDLE hFile;
	HANDLE hMap;
	LPVOID hBase;

	hFile = CreateFile((LPWSTR)moduleName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LoggerRecord::WriteLog(L"Open file failed: " + moduleName, INFO);
		return NULL;
	}
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
	if (hMap == NULL) {
		LoggerRecord::WriteLog(L"Map file failed: " + moduleName, INFO);
		CloseHandle(hFile);
		return NULL;
	}
	hBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (hBase == NULL)
	{
		LoggerRecord::WriteLog(L"Map file failed-2: " + moduleName, INFO);
		CloseHandle(hFile);
		CloseHandle(hMap);
		return NULL;
	}

	current_module_name_ = moduleName;
	//LoggerRecord::WriteLog(L"Start parse dll:" + moduleName, INFO);
	btree* temp_tree = getModuleRva(hBase);
	
	if (temp_tree == NULL) {
		LoggerRecord::WriteLog(moduleName + L" failed!", INFO);
		//wcout << moduleName << L" failed!" << endl;
	}
	else {
		//LoggerRecord::WriteLog(moduleName + L" successful!", INFO);
		//wcout << moduleName << L" successful!" << endl;
	}

	module_btree_map[moduleName] = temp_tree;
	CloseHandle(hFile);
	CloseHandle(hMap);
	return temp_tree;
}

int ObtainEntryAddress::printModuleRva(wstring moduleName) {
	getModuleRvaFromFileName(moduleName);
	wofstream rva2FuncNameFile(//CacheFilePath + 
		L"rva2FuncName\\" + drivemap.formatFilePathDrive(moduleName.c_str()) + L".rva2FuncName");
	if (rva2FuncNameMap.empty())
		return 0;
	for (auto iter2 = rva2FuncNameMap.begin(); iter2 != rva2FuncNameMap.end(); iter2++) {
		rva2FuncNameFile << iter2->first << L":" << iter2->second << endl;
	}
	rva2FuncNameFile.close();
	return 0;
}
 
int ObtainEntryAddress::printAllModuleRva() {
	//addCommonModulesToSet("C:\\Windows\\System32");
	//addCommonModulesToSet("C:\\Windows\\SysWOW64");

	if (moduleSet.empty()) {
		return 0;
	}
	for (auto iter = moduleSet.begin(); iter != moduleSet.end(); iter++) {
		if (printModuleRva(*iter) == 1) {
			wcout << L"Module " << *iter << L"UnPrintable!" << endl;
		}
		//moduleSet.erase(iter);
	}

	return 0;
}

void ObtainEntryAddress::addTargetProcess(DWORD processID) {
	targetProcess.insert(processID);
}

DWORD ObtainEntryAddress::getParentProcessID(DWORD processID) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);
	DWORD parentsProcessID = 0;

	if (Process32First(h, &pe)) {
		do {
			if (pe.th32ProcessID == processID) {
#ifdef OUTPUT_COMMAND_LINE
				printf("PID: %i; PPID: %i\n", processID, pe.th32ParentProcessID);
#endif // OUTPUT_COMMAND_LINE;
				parentsProcessID = pe.th32ParentProcessID;
				break;
			}
		} while (Process32Next(h, &pe));
	}

	CloseHandle(h);
	return parentsProcessID;
}

set<DWORD> ObtainEntryAddress::listSubProcess() {
	DWORD processList[MAX_MODULE_LENGTH];
	DWORD cbNeeded;
	DWORD cProcesses;
	if (!EnumProcesses(processList, sizeof(processList), &cbNeeded)) {
#ifdef OUTPUT_COMMAND_LINE	
		cout << "Allocted space for processes list is too small!" << endl;
#endif // OUTPUT_COMMAND_LINE;
	}

	set<DWORD> subProcess;
	cProcesses = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < cProcesses; i++) {
		DWORD parentProcessID = getParentProcessID(processList[i]);
		if (targetProcess.count(parentProcessID) != 0) {
			subProcess.insert(parentProcessID);
			targetProcess.insert(parentProcessID);
		}
	}

	return subProcess;
}

std::string GenerateDllName(std::string temp)
{
	int position = (int)temp.find(".rva2FuncName");
	std::string ret;
	for (int i = 0; i != position; i++)
	{
		if (i == 0) {
			ret += temp[i];
			ret += ':';
		}else
		if (temp[i]=='.'&&temp[i+1]=='.') {
			ret += '\\';
			i++;
		}
		else ret += temp[i];
	}
	return ret;
}

bool compare_address(std::pair<unsigned int, std::string> tempA, std::pair<unsigned int, std::string> tempB)
{
	if (tempA.first < tempB.first) return true;
	return false;
}

void ObtainEntryAddress::ReadDLLmodualTree(string folder_path_)
{
	std::vector<std::string> file_path_vector_;
	std::vector<std::string> file_name_vector_;
	getFiles(folder_path_, file_path_vector_, file_name_vector_);
	for (auto i = 0; i != file_name_vector_.size(); i++) {
		file_name_vector_[i] = GenerateDllName(file_name_vector_[i]);
		string temp = file_name_vector_[i];
		transform(temp.begin(), temp.end(), file_name_vector_[i].begin(), ::tolower);
	}
	for (auto ix = 0; ix != file_path_vector_.size(); ix++) {
		fstream infile(file_path_vector_[ix],ios::in);
		string address_funcname;
		char temp_char;
		unsigned int i = 0, temp_address; //temp_pre_address; unused
		std::vector<std::pair<unsigned int, std::string>> temp_vector;
	
		while (infile >> hex >> temp_address >>temp_char>> address_funcname) {
			i++;
			temp_vector.push_back(std::pair<unsigned int, std::string>(temp_address, address_funcname));
		}
		i = 0;
		sort(temp_vector.begin(), temp_vector.end(),compare_address);

		std::vector<dllAddress> temp_DllAddress_vector;
		while (i!= temp_vector.size()) {
			if (i == temp_vector.size() - 1) {
				dllAddress tmpAddress;
				tmpAddress.ImageBase = temp_vector[i].first;
				tmpAddress.FileName = temp_vector[i].second;
				tmpAddress.ImageEnd = INT_MAX;

				temp_DllAddress_vector.push_back(tmpAddress);
				

			}
			else {
				dllAddress tmpAddress;
				tmpAddress.ImageBase = temp_vector[i].first;
				tmpAddress.FileName = temp_vector[i].second;
				tmpAddress.ImageEnd = temp_vector[i+1].first;

				temp_DllAddress_vector.push_back(tmpAddress);

			}
			i++;

		}
		dll_module_vector[ToolFunctions::StringToWString(file_name_vector_[ix])] = temp_DllAddress_vector;
		random_shuffle(temp_DllAddress_vector.begin(), temp_DllAddress_vector.end());

		for (auto iy = temp_DllAddress_vector.begin(); iy != temp_DllAddress_vector.end(); iy++) DLLmodualTree[ToolFunctions::StringToWString(file_name_vector_[ix])].insert(*iy);

		infile.close();
		infile.clear();
	}
}

bool DllAddress_compare(dllAddress a, dllAddress b) {
	if (a.ImageBase < b.ImageBase) return true;
	return false;
}
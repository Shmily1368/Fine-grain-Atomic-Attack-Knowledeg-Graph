#pragma once
/*********************************************************************************
*
* Description : To get file object have been open before collector start.
*
* Written by : Xiaoruan
* Create Time : 2018-11-16
* Last Upate : 2018-11-19
*
*********************************************************************************/

#pragma once

//#include "systemstruct.h"
//
// struct pair_hash {
// 	template <class T1, class T2>
// 	std::size_t operator () (const std::pair<T1, T2> &p) const{
// 		auto h1 = std::hash<T1>{}(p.first);
// 		auto h2 = std::hash<T2>{}(p.second);
// 		return h1 ^ h2;
// 	}
// };
// using ContextKey = std::pair<DWORD, ULONG64>;
// using Unordered_map = std::unordered_map<ContextKey, std::wstring, pair_hash>;
// 
// class SystemContext {
// public:
// 	SystemContext();
// 	~SystemContext();
// 	void GetFileContext(std::unordered_map<ULONG64, std::wstring> &filerelation);  // address:filename
// 	
// private:
// 
// 	HMODULE hNtDll; //load ntdll.dll 
// 	HANDLE dupHandle = NULL;  //NtDuplicateObject
// 	HANDLE processHandle = NULL; //return value for openprocess
// 
// 	_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
// 	_NtDuplicateObject NtDuplicateObject;
// 	_NtQueryObject NtQueryObject;
// 
// 	PSYSTEM_HANDLE_INFORMATION_EX pInfo;
// 	LPVOID pBuffer = NULL;
// 
// 	std::set<int> KeyTypeNumber;
// 	std::set<int> FileTypeNumber;
// 
// 	std::map<int, POBJECT_NAME_INFORMATION> code_relation;  //save ObjectTypeNumber-> type 
// 
// 	POBJECT_NAME_INFORMATION pNameInfo;
// 	POBJECT_NAME_INFORMATION pNameType;
// 
// 	char szType[128] = { 0 };
// 	
// 
// 
// 	LPVOID GetSystemProcessHandleInfo();
// 
// };


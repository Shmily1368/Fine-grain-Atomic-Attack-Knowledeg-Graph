#include "stdafx.h"
#include <process.h>
#include <fstream>
#include <exception>

#include "get_systemcontext.h"
// 
// #define NAMESPACE  1024
// #define NAMELENGTH 1000
// 
// _NtQueryObject NtQueryObject_thread;
// NTSTATUS ntStatus_thread;
// char szName[NAMESPACE] = { 0 };
// HANDLE g_Event = 0;
// HANDLE dupHandle = NULL;  //NtDuplicateObject
// HANDLE processHandle = NULL; //return value for openprocess
// 
// 
// SystemContext::SystemContext()
// {
// 	hNtDll = LoadLibrary(L"ntdll.dll");
// 	NtQuerySystemInformation = (_NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");
// 	NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hNtDll, "NtDuplicateObject");
// 	NtQueryObject = (_NtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
// 
// 	pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GetSystemProcessHandleInfo();
// 
// }
// 
// 
// SystemContext::~SystemContext()
// {
// 	FreeModule(hNtDll);
// 	free(pBuffer);
// }
// 
// 
// //
// //UINT WINAPI ZwThreadProc(PVOID lpParma) {
// //	memset(szName, 0, NAMESPACE);
// //	ntStatus_thread = NtQueryObject_thread(dupHandle, ObjectNameInformation, szName, NAMESPACE -sizeof(wchar_t), NULL);//maybe suspend 
// //
// //	SetEvent(g_Event);
// //	return 0;
// //}
// 
// 
// //void CheckBlockThreadFunc(void* param)
// //{
// //	/*BYTE buf[1024];
// //	IO_STATUS_BLOCK ioStatus;
// //	SystemContext::NtQueryInformationFile((HANDLE)param, &ioStatus, buf, NAMELENGTH,FileNameInformation);*/
// //
// //	HANDLE hFile = (HANDLE)param;
// //	GetFileType(hFile);
// //}
// //
// //BOOL IsBlockingHandle(HANDLE handle)
// //{
// //	HANDLE hThread = (HANDLE)_beginthread(CheckBlockThreadFunc, 0, (void*)handle);
// //	if (WaitForSingleObject(hThread, 100) != WAIT_TIMEOUT) {
// //		return FALSE;
// //	}
// //	bool status = TerminateThread(hThread, 0);
// //	std::cout << status << std::endl;
// //	//if(status ==0)
// //		//std::cout << "exist failed" << std::endl;
// //	return TRUE;
// //}
// 
// void SystemContext::GetFileContext(std::unordered_map<ULONG64, std::wstring> &filerelation) 
// {
// 	DWORD dwFlags = 0;
// 	//unused;
// 	//POBJECT_NAME_INFORMATION pNameInfo;
// 	POBJECT_NAME_INFORMATION pNameType;
// 	
// 
// 	for (DWORD i = 0; i < pInfo->NumberOfHandles; i++)
// 	{
// 		SYSTEM_HANDLE_INFORMATION handle = pInfo->Information[i];
// 
// 		//POBJECT_TYPE_INFORMATION objectTypeInfo;
// 		//PVOID objectNameInfo;
// 		//UNICODE_STRING objectName;
// 		//ULONG returnLength;
// 
// 		if (code_relation.find(pInfo->Information[i].ObjectTypeNumber) == code_relation.end()) 
// 		{
// 			if (pInfo->Information[i].ProcessId == GetCurrentProcessId())
// 				continue;
// 			processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pInfo->Information[i].ProcessId);
// 			if (processHandle == NULL)
// 				continue;
// 			NtDuplicateObject(processHandle,
// 				(HANDLE)pInfo->Information[i].Handle,
// 				GetCurrentProcess(),
// 				&dupHandle,
// 				0,   //DUPLICATE_SAME_ACCESS
// 				0,
// 				0
// 			);
// 
// 			if (dupHandle == NULL) 
// 			{
// 				CloseHandle(processHandle);
// 				continue;
// 			}
// 
// 			//NTSTATUS status1 = NtQueryObject(dupHandle, ObjectNameInformation, szName, 512, &dwFlags);
// 			NTSTATUS status2 = NtQueryObject(dupHandle, ObjectTypeInformation, szType, 128, &dwFlags);
// 
// 			if (strcmp(szType, "") && NT_SUCCESS(status2))
// 			{
// 				pNameType = (POBJECT_NAME_INFORMATION)szType;
// 				code_relation[pInfo->Information[i].ObjectTypeNumber] = pNameType;
// 				
// 				std::wstring wStrBuf((pNameType->Name).Buffer, (pNameType->Name).MaximumLength / sizeof(WCHAR) - 1);
// 				if (wStrBuf == L"File")
// 					FileTypeNumber.insert(pInfo->Information[i].ObjectTypeNumber);
// 			}
// 			CloseHandle(dupHandle);
// 			CloseHandle(processHandle);
// 		}
// 
// 		if (FileTypeNumber.count(pInfo->Information[i].ObjectTypeNumber) )
// 		{
// 			if (pInfo->Information[i].ProcessId == GetCurrentProcessId())
// 				continue;
// 			processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pInfo->Information[i].ProcessId);
// 			if (processHandle == NULL)
// 				continue;
// 			NtDuplicateObject(processHandle,
// 				(HANDLE)pInfo->Information[i].Handle,
// 				GetCurrentProcess(),
// 				&dupHandle,
// 				0,
// 				0,
// 				0
// 			);
// 
// 			if (dupHandle == NULL) {
// 				CloseHandle(processHandle);
// 				continue;
// 			}
// 
// 
// 			//if (dwSatu == WAIT_TIMEOUT) {
// 			//	//printf("happen1\n");
// 			//	HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, dwThread);
// 			//	if (!TerminateThread(hThread, 0)) {
// 			//		CloseHandle(hThread);
// 			//		CloseHandle(dupHandle);
// 			//		CloseHandle(processHandle);
// 			//		//ExitProcess(0);
// 			//		continue;
// 			//	}
// 
// 			//get file object may face suspend, need create thread and monitor it 
// 			//create thread may cause problem, use  GetFileType instead, 
// 			//The hang generally happens for non-disk files
// 
// 			int type = GetFileType(dupHandle);
// 
// 			if (type!= FILE_TYPE_DISK) {
// 				CloseHandle(processHandle);
// 				CloseHandle(dupHandle);
// 				continue;
// 			}
// 			else{
// 				NTSTATUS status3 = NtQueryObject(dupHandle, ObjectNameInformation, szName, NAMELENGTH, &dwFlags);
// 				////if (strcmp(szName, "") && ntStatus_thread!= 0xc0000008) 
// 				if (status3 != 0xc0000008 && NT_SUCCESS(status3))
// 				{
// 					std::wstring filepath;
// 					try {
// 						filepath = (WCHAR*)szName + 8;
// 					}
// 					catch (std::exception  e) {
// 						//printf("happen3\n");
// 						CloseHandle(dupHandle);
// 						CloseHandle(processHandle);
// 						continue;
// 					}
// 
// 
// 					if (filepath == L"") {
// 						//printf("happen4\n");
// 						CloseHandle(dupHandle);
// 						CloseHandle(processHandle);
// 						continue;
// 					}
// 
// 					//std::pair<DWORD, ULONG64> key((DWORD)pInfo->Information[i].ProcessId, (ULONG64)pInfo->Information[i].Object);
// 					if (filepath.find(L"Device") != std::wstring::npos)
// 					{
// 						filerelation[(ULONG64)pInfo->Information[i].Object] = filepath;
// 						/*fopen_s(&fp, "test.txt", "a+");
// 						fprintf(fp, "File %d %lu %llu %wZ \n", pInfo->Information[i].ObjectTypeNumber, pInfo->Information[i].ProcessId, pInfo->Information[i].Object, pNameInfo->Name);
// 						fflush(fp);
// 						fclose(fp);*/
// 
// 						//f << pInfo->Information[i].ProcessId << filepath << std::endl;
// 						//std::wcout << filepath << std::endl;
// 					}
// 				}
// 				CloseHandle(dupHandle);
// 				CloseHandle(processHandle);
// 			}
// 			
// 		}
// 	}
// }
// 
// LPVOID SystemContext::GetSystemProcessHandleInfo() {
// 	ULONG cbBuffer = 0x4000;
// 	NTSTATUS sts;
// 	do
// 	{
// 		pBuffer = malloc(cbBuffer);
// 		if (pBuffer == NULL)
// 		{
// 			std::cout << "error alloc memory:" << GetLastError() << std::endl;
// 			LoggerRecord::WriteLog(L"error alloc memory:" + std::to_wstring(GetLastError()), LogLevel::ERR);
// 			return NULL;
// 		}
// 		memset(pBuffer, 0, cbBuffer);
// 
// 		sts = NtQuerySystemInformation(SystemHandleInformation, pBuffer, cbBuffer, NULL);
// 		if (sts == STATUS_INFO_LENGTH_MISMATCH)
// 		{
// 			free(pBuffer);
// 			pBuffer = NULL;
// 			cbBuffer = cbBuffer + 0x4000; // 初始分配的空间不足+4000h
// 		}
// 
// 	} while (sts == STATUS_INFO_LENGTH_MISMATCH);
// 
// 	return pBuffer;
// }



#pragma once
#include <iostream>
#include <fstream>
#include <locale>
#include<string>
#include <Windows.h>
#include<vector>
#include"../tool_functions.h"
using namespace std;
//std::string wstr2str(std::wstring src)
//{
//	string dest;
//	setlocale(LC_CTYPE, "");
//
//	size_t const mbs_len = wcstombs(NULL, src.c_str(), 0);
//	std::vector<char> tmp(mbs_len + 1);
//	wcstombs(&tmp[0], src.c_str(), tmp.size());
//
//	dest.assign(tmp.begin(), tmp.end() - 1);
//
//	return dest;
//}
//
//
//// ��һ��stringת��Ϊwstring
//std::wstring str2wstr(std::string src)
//{
//	wstring dest;
//	//   std::setlocale(LC_CTYPE, "");
//	setlocale(LC_CTYPE, "zh_CN");
//
//	size_t const wcs_len = mbstowcs(NULL, src.c_str(), 0);
//	std::vector<wchar_t> tmp(wcs_len + 1);
//	mbstowcs(&tmp[0], src.c_str(), src.size());
//
//	dest.assign(tmp.begin(), tmp.end() - 1);
//
//	return dest;
//}
std::string ExeCmd(std::string cmd)
{
	wstring pszCmd = ToolFunctions::Str2Wstr(cmd);
	// ���������ܵ�
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hRead, hWrite;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return " ";
	}

	// ���������н���������Ϣ(�����ط�ʽ���������λ�������hWrite
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;

	// ����������
	PROCESS_INFORMATION pi;
	UINT errorMode = GetErrorMode();
	// ���γ��������ڣ�������exe��ָ�
	SetErrorMode(SetErrorMode(0) | SEM_NOGPFAULTERRORBOX);
	if (!CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		return ("Cannot create process");
	}
	//TODO����ж��߼� ������н����ر� ���û�� ���ȴ�300��ر�
	int index = 2000;


	DWORD ExitCode;

	ExitCode = STILL_ACTIVE;
	while (index--)
	{
		GetExitCodeProcess(pi.hProcess, &ExitCode);
		if (ExitCode != STILL_ACTIVE) {
			break;
		}
		Sleep(100);
	}
	//HANDLE h_process = NULL;
	//while (index--) {
	//	h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pi.dwProcessId);
	//	if (h_process == NULL)
	//	{
	//		break;
	//	}
	//	Sleep(100);
	//}
	//
	// �����ر�hWrite
	CloseHandle(hWrite);
	SetErrorMode(SetErrorMode(0) | errorMode);
	// ��ȡ�����з���ֵ
	std::string strRetTmp;
	//char *buff = (char *)malloc(10000);
	char buff[1024] = { 0 };
	DWORD dwRead = 0;
	strRetTmp = buff;
	while (ReadFile(hRead, buff, 1024, &dwRead, NULL))
	{
		strRetTmp += buff;
	}
	//wstring strRet = Str2Wstr(strRetTmp);
	CloseHandle(hRead);
	//LPCSTR pszSrc = strRetTmp.c_str();
	//int nLen = MultiByteToWideChar(CP_ACP, 0, buff, -1, NULL, 0);
	//if (nLen == 0)
	//	return std::wstring(L"");

	//wchar_t* pwszDst = new wchar_t[nLen];
	//if (!pwszDst)
	//	return std::wstring(L"");

	//MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
	//std::wstring strRet(pwszDst);
	//delete[] pwszDst;
	//pwszDst = NULL;

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return strRetTmp;
}

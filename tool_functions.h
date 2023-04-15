#pragma once
#include "stdafx.h"
#include <winsock.h>
#include <Windows.h>

class ToolFunctions
{
public:
	static String WStringToString(const std::wstring& ws);
	static std::wstring StringToWString(const String& str);
	static std::wstring DeleteDriverName(std::wstring);
	static std::wstring GetPresentTime();
	static String getTime();
	static int GetUnixTimestamp();
	static long long GetUnixTimestamp64();
	static void getFiles(const String& path, STRING_VECTOR& files, STRING_VECTOR& ownname);
	static bool isEndWith(const wchar_t * str, const wchar_t * end);
	static std::wstring Str2Wstr(const String& str);
	static EM_OsVersion GetSystemOs();
	static bool WindowIconic(HWND hwnd);
	static String DecryptStr(const String& str);
    static String DecryptStrEx(const String& str);
	static bool IsExecutableFile(std::wstring file_path);
	static void CleanCache();
	static String GetPEFileHash(const String& pe_file_path);
	static bool GetCpuName(String& cpu_name);
	static void ParseAutorunInfo(STRING_SET& autorun_info);
	static LSTATUS RegOpenKeyForce(HKEY root_key, std::wstring path, HKEY& ret_key);
	static LSTATUS RegQuerySetValue(HKEY root_key, std::wstring val_name, DWORD val_type, LPBYTE val_expected, DWORD val_size);

// add by zxw on 20191029 添加网络字节序转换函数
public:
	static String Net2Str(int uip);
    static std::string StringToUTF8(const std::string & str);
    static long get_file_ize(const char * filePath);
    static std::string UTF8_to_String(const std::string & str);
    static int GetScreenNumbers();
    static void GetScreenRect(long& width, long& height);
    static std::string GetUserPath();
    static bool JudgePath(std::string &srcPath, std::string & dstPath);
    //获取安装目录
    static wstring GetDirectoryfromPath(wstring strPath);
    // 获取模块当前目录 
    static std::wstring GetModuleDirectory();
    //杀死进程
    static bool KillProcess(DWORD process_id);
private:
	static bool _CheckAutorunReg();
	static void _FormatAutorunInfo(const String& file_name);

private:
	static EM_OsVersion os_version;
	static std::map<std::wstring, bool> _executable_file_cache;
};


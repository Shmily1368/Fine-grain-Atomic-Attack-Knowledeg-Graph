#include "stdafx.h"
#include "tool_functions.h"
#include "obtain_entry_address.h"
#include "on_leave_section_callback.h"
#include "setting.h"

#include <io.h>
#include <time.h>
#include <locale>
#include <codecvt>
#include <fstream>
#include <DbgHelp.h>
#include <chrono>
#include <algorithm>

#pragma warning( disable: 4996 )

EM_OsVersion ToolFunctions::os_version = EM_OsVersion::UNKNOWN_OS;
std::map<std::wstring, bool> ToolFunctions::_executable_file_cache;

String ToolFunctions::WStringToString(const std::wstring& ws)
{
	//wstringToUtf8
	static std::wstring_convert<std::codecvt_utf8<wchar_t> > strCnv;
	return strCnv.to_bytes(ws);
}

std::wstring ToolFunctions::StringToWString(const String &str)
{	
	std::wstring wstr;
	int nLen = (int)str.length();
	wstr.resize(nLen, L' ');

	int nResult = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)str.c_str(), nLen, (LPWSTR)wstr.c_str(), nLen);
	if (nResult == 0)
	{
		return L"";
	}

	return wstr;
}

wstring ToolFunctions::GetPresentTime()
{
	SYSTEMTIME time;
	GetLocalTime(&time);

	wchar_t wszTime[128];
	swprintf_s(wszTime, _T("%04d-%02d-%02d %02d-%02d-%02d"), time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

	return wstring(wszTime);
}

String ToolFunctions::getTime()
{
	time_t timep;
	time(&timep);
	char tmp[64];
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&timep));
	return tmp;
}

int ToolFunctions::GetUnixTimestamp()
{
	return (int)time(NULL);
}

long long ToolFunctions::GetUnixTimestamp64()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void ToolFunctions::getFiles(const String& path, STRING_VECTOR& files, STRING_VECTOR& ownname)
{
	intptr_t hFile = 0;
	struct _finddata_t fileinfo;
	String p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					getFiles(p.assign(path).append("\\").append(fileinfo.name), files, ownname);
			}
			else
			{
				files.push_back(p.assign(path).append("\\").append(fileinfo.name));
				ownname.push_back(fileinfo.name);
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

bool ToolFunctions::isEndWith(const wchar_t * str, const wchar_t * end)
{
	bool result = false;

	if (str != NULL && end != NULL) {
		size_t l1 = wcslen(str);
		size_t l2 = wcslen(end);
		if (l1 >= l2) {
			if (wcscmp(str + l1 - l2, end) == 0) {
				result = true;
			}
		}
	}

	return result;
}

std::wstring ToolFunctions::DeleteDriverName(std::wstring driver_name)
{
	if (driver_name.find(L":") == 1) driver_name.erase(0, 2);
	return driver_name;
}

//a tool to convert a string to wstring
std::wstring ToolFunctions::Str2Wstr(const String& str)
{
	if (str.length() == 0)
		return L"";

	std::wstring wstr;
	wstr.assign(str.begin(), str.end());
	return wstr;
}

EM_OsVersion ToolFunctions::GetSystemOs()
{
	// get os name according to version number
	if (os_version == EM_OsVersion::UNKNOWN_OS)
	{
// 		OSVERSIONINFO osver = { sizeof(OSVERSIONINFO) };
// 		GetVersionEx(&osver);
// 		std::string os_name;
// 		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)
// 		{
// 			os_version = EM_OsVersion::WIN7;
// 		}
// 		else if ((osver.dwMajorVersion == 10 && osver.dwMinorVersion == 0) || (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 4))
// 		{
// 			os_version = EM_OsVersion::WIN10;
// 		}

		//the above code maybe unavailable on the releases after Windows 8.1;
		//now use these instead;
		DEFINE_DLL_FUNCTION(RtlGetVersion, NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW), "ntdll.dll");
		if (RtlGetVersion)
		{
			OSVERSIONINFO ovi = { sizeof(OSVERSIONINFO) };
			if (RtlGetVersion(&ovi) == 0)
			{
				if (ovi.dwMajorVersion == 6 && ovi.dwMinorVersion == 1)
				{
					os_version = EM_OsVersion::WIN7;
				}
				else if ((ovi.dwMajorVersion == 10 && ovi.dwMinorVersion == 0) || 
						(ovi.dwMajorVersion == 6 && ovi.dwMinorVersion == 4))
				{
					os_version = EM_OsVersion::WIN10;
				}
				else if (ovi.dwMajorVersion == 6 && ovi.dwMinorVersion == 3)
				{
					os_version = EM_OsVersion::WS2012_R2;
				}
			}
		}
	}

	return os_version;
}

bool ToolFunctions::WindowIconic(HWND hwnd)
{
	DEFINE_DLL_FUNCTION(IsIconic, BOOL(WINAPI*)(HWND), "user32.dll");
	if (IsIconic)
	{
		return IsIconic(hwnd);
	}

	LoggerRecord::WriteLog(L"ToolFunctions::WindowIconic: cannot find IsIconic address", LogLevel::ERR);
	return false;
}

String ToolFunctions::DecryptStr(const String& str)
{
	static size_t key_len = FORMAT_SECRET_KEY.size();

	String ret;
	ret.resize(str.size());
	for (size_t i = 0; i < str.size(); ++i)
	{
		char ch = str[i] ^ FORMAT_SECRET_KEY[i % key_len];
		ret[i] = (ch != '\n' && ch != '\r') ? ch : str[i];
	}
	return ret;
}
String ToolFunctions::DecryptStrEx(const String& str)
{
    static size_t key_len = FORMAT_SECRET_KEY.size();

    String ret;
    ret.resize(str.size());
    for (size_t i = 0; i < str.size(); ++i)
    {
        if (str[i] == '\n' || str[i] == '\r')
        {
            continue;
        }
        char ch = str[i] ^ FORMAT_SECRET_KEY[i % key_len];
        ret[i] = (ch != '\n' && ch != '\r') ? ch : str[i];
    }
    return ret;
}
bool ToolFunctions::IsExecutableFile(std::wstring file_path)
{
	auto iter_f = _executable_file_cache.find(file_path);
	if (iter_f != _executable_file_cache.end())
	{
		return iter_f->second;
	}

	bool result = false;
	do 
	{
		if (isEndWith(file_path.c_str(), L".sys"))	break;
		if (isEndWith(file_path.c_str(), L".SYS"))	break;
		if (isEndWith(file_path.c_str(), L".drv"))	break;
		if (isEndWith(file_path.c_str(), L".DRV"))	break;

		HANDLE file_handle = CreateFile(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file_handle == INVALID_HANDLE_VALUE)	break;

		DECLARE_LEAVE_SECTION_CALLBACK([&] () { CloseHandle(file_handle); });

		IMAGE_DOS_HEADER dos_header;
		DWORD read_size;
		ReadFile(file_handle, &dos_header, sizeof(IMAGE_DOS_HEADER), &read_size, NULL);
		if (read_size != sizeof(IMAGE_DOS_HEADER))
		{
			break;
		}

		if (dos_header.e_magic == IMAGE_DOS_SIGNATURE)
		{
			IMAGE_NT_HEADERS nt_header;
			if (SetFilePointer(file_handle, dos_header.e_lfanew, NULL, FILE_BEGIN) != -1)
			{
				ReadFile(file_handle, &nt_header, sizeof(IMAGE_NT_HEADERS), &read_size, NULL);
				if (read_size == sizeof(IMAGE_NT_HEADERS))
				{
					result = (nt_header.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0;
				}
			}
		}

	} while (0);
	
	_executable_file_cache.insert(std::make_pair(file_path, result));
	return result;
}

void ToolFunctions::CleanCache()
{
	LoggerRecord::WriteLog(L"ToolFunctions::CleanCache: executable_file_cache size before clean = " + std::to_wstring(_executable_file_cache.size()), LogLevel::INFO);
	std::map<std::wstring, bool>().swap(_executable_file_cache);
}

bool ToolFunctions::GetCpuName(String& cpu_name)
{
	HKEY h_key;
	LSTATUS ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &h_key);
	if (ret != ERROR_SUCCESS)	return false;
	DECLARE_LEAVE_SECTION_CALLBACK([&] () { RegCloseKey(h_key); });
	
	WCHAR cpu_name_str[256] = { 0 };
	DWORD dw_size = sizeof(cpu_name_str);
	DWORD cpu_type = 0;
	ret = RegQueryValueExW(h_key, L"ProcessorNameString", NULL, &cpu_type, (BYTE*)cpu_name_str, &dw_size);
	if (ret != ERROR_SUCCESS)	return false;

	cpu_name = WStringToString(std::wstring(cpu_name_str));
	return true;
}

struct PEFileDebugInfo
{
	DWORD signature;
	BYTE guid[16];
	DWORD age;
	char* pdb_file_name;
};
String ToolFunctions::GetPEFileHash(const String& pe_file_path)
{
	std::wstring file_path_w = ToolFunctions::StringToWString(pe_file_path);
	HANDLE file_handle = CreateFile(file_path_w.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_handle == INVALID_HANDLE_VALUE)	return EMPTY_STRING;

	HANDLE map_handle = CreateFileMapping(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map_handle == INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return EMPTY_STRING;
	}

	PVOID map_addr = MapViewOfFileEx(map_handle, FILE_MAP_READ, 0, 0, 0, NULL);
	if (map_addr == NULL)
	{
		CloseHandle(map_handle);
		CloseHandle(file_handle);
	}

	DECLARE_LEAVE_SECTION_CALLBACK([&]()
	{
		UnmapViewOfFile(map_addr);
		CloseHandle(map_handle);
		CloseHandle(file_handle);
	});

	PIMAGE_NT_HEADERS nt_header = ImageNtHeader(map_addr);
	PIMAGE_DEBUG_DIRECTORY debug_dir = (PIMAGE_DEBUG_DIRECTORY)((PBYTE)map_addr + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

	for (DWORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER sec_header = IMAGE_FIRST_SECTION(nt_header) + i;
		if (strcmp((char*)sec_header->Name, ".rdata") != 0)	continue;

		String str = String((char*)map_addr + sec_header->PointerToRawData, sec_header->SizeOfRawData);
		PIMAGE_DEBUG_DIRECTORY debug_dir = (PIMAGE_DEBUG_DIRECTORY)((PBYTE)map_addr + sec_header->PointerToRawData + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress - sec_header->VirtualAddress);
		if (IMAGE_DEBUG_TYPE_CODEVIEW == debug_dir->Type)
		{
			PEFileDebugInfo* debug_info = (PEFileDebugInfo*)((PBYTE)map_addr + debug_dir->PointerToRawData);
			if (0 == memcmp(&debug_info->signature, "RSDS", 4))
			{
				OLECHAR* guid_cstr;
				StringFromCLSID(*((GUID*)debug_info->guid), &guid_cstr);
				String guid_str = ToolFunctions::WStringToString(std::wstring(guid_cstr));
				CoTaskMemFree(guid_cstr);

				if (guid_str.size() < 2)	return EMPTY_STRING;

				guid_str = guid_str.substr(1, guid_str.size() - 2);
				STRING_VECTOR guid_split;
				StringUtil::split(guid_str, '-', guid_split);
				guid_str = EMPTY_STRING;
				for (const String& str_t : guid_split)
				{
					guid_str += str_t;
				}

				return guid_str + std::to_string(debug_info->age);
			}
		}
	}

	return EMPTY_STRING;
}

void ToolFunctions::ParseAutorunInfo(STRING_SET& autorun_info)
{
	String autorun_info_file_simplified = Setting::GetInstance().autorun_info_file_simplified();
	String autorun_info_file_full = Setting::GetInstance().autorun_info_file_full();
	String autorun_info_file_input = "autorun_info_i";
	remove(autorun_info_file_simplified.c_str());
	remove(autorun_info_file_full.c_str());
	remove(autorun_info_file_input.c_str());

	if (!_CheckAutorunReg())
	{
		std::fstream fp;
		fp.open(autorun_info_file_simplified, ios::out);
		fp.close();
		fp.open(autorun_info_file_full, ios::out);
		fp.close();
		fp.open(autorun_info_file_input, ios::out);
		fp.close();

		return;
	}

	String command = String("autorunsc64.exe -c * > ") + autorun_info_file_simplified;
	system(command.c_str());
	_FormatAutorunInfo(autorun_info_file_simplified);

	command = String("autorunsc64.exe -a * -c > ") + autorun_info_file_full;
	system(command.c_str());
	_FormatAutorunInfo(autorun_info_file_full);

	command = String("PowerShell -Command \"& {get-content ") + autorun_info_file_full + " -encoding unicode | set-content " + autorun_info_file_input + " -encoding utf8}\"";
	system(command.c_str());

	std::fstream fp(autorun_info_file_input, ios::in);
	String read_buf;
	STRING_VECTOR read_parts;
	while (getline(fp, read_buf))
	{
		read_parts.clear();
		StringUtil::split(read_buf, ',', read_parts);
		if (read_parts.size() < 9 || read_parts[8].size() < 2)	continue;

		String autorun_name = read_parts[8].substr(1, read_parts[8].size() - 2);
		if (StringUtil::IsEndWith(autorun_name, "exe", true))
		{
			autorun_info.insert(autorun_name);
		}
	}
	fp.close();

	remove(autorun_info_file_input.c_str());
}

LSTATUS ToolFunctions::RegOpenKeyForce(HKEY root_key, std::wstring path, HKEY& ret_key)
{
	LSTATUS ret = RegOpenKey(root_key, path.data(), &ret_key);
	if (ret != ERROR_SUCCESS)
	{
		ret = RegCreateKey(root_key, path.data(), &ret_key);
	}

	return ret;
}

LSTATUS ToolFunctions::RegQuerySetValue(HKEY root_key, std::wstring val_name, DWORD val_type, LPBYTE val_expected, DWORD val_size)
{
	BYTE val_query[512] = { 0 };
	DWORD val_size_query = sizeof(val_query), val_type_query = 0;
	LSTATUS ret = RegQueryValueEx(root_key, val_name.data(), 0, &val_type_query, (LPBYTE)val_query, &val_size_query);
	if (ret != ERROR_SUCCESS || val_type != val_type_query || val_size != val_size_query || strcmp((const char*)val_query, (const char*)val_expected) != 0)
	{
		ret = RegSetValueEx(root_key, val_name.data(), 0, val_type, (LPBYTE)val_expected, val_size);
	}

	return ret;
}

String ToolFunctions::Net2Str(int uip)
{
	String str;
	struct in_addr addr1;
	memcpy(&addr1, &uip, 4);
	str =  inet_ntoa(addr1);
	return str;
}

std::string ToolFunctions::StringToUTF8(const std::string & str) 
{
    int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
    wchar_t * pwBuf = new wchar_t[nwLen + 1];
    ZeroMemory(pwBuf, nwLen * 2 + 2);
    ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
    int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
    char * pBuf = new char[nLen + 1];
    ZeroMemory(pBuf, nLen + 1);
    ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
    std::string retStr(pBuf);
    delete[]pwBuf;
    delete[]pBuf;
    pwBuf = NULL;
    pBuf = NULL;
    return retStr;
}

bool ToolFunctions::_CheckAutorunReg()
{
	HKEY hkey_autoruns;
	LSTATUS ret = RegOpenKey(HKEY_CURRENT_USER, L"Software\\Sysinternals\\AutoRuns", &hkey_autoruns);
	if (ret != ERROR_SUCCESS)
	{
		ret = RegCreateKey(HKEY_CURRENT_USER, L"Software\\Sysinternals\\AutoRuns", &hkey_autoruns);
		if (ret != ERROR_SUCCESS)
		{
			LoggerRecord::WriteLog(L"ToolFunctions::_CheckAutorunReg: RegCreateKey failed, ret = " + std::to_wstring(ret), LogLevel::ERR);
			return false;
		}
	}

	DWORD value = 0, value_type = REG_DWORD;
	LONG value_size = sizeof(value);
	ret = RegQueryValueEx(hkey_autoruns, L"EulaAccepted", 0, &value_type, (LPBYTE)(&value), &value_type);
	if (ret != ERROR_SUCCESS || value != 1)
	{
		value = 1;
		ret = RegSetValueEx(hkey_autoruns, L"EulaAccepted", 0, REG_DWORD, (LPBYTE)(&value), value_size);
		if (ret != ERROR_SUCCESS)
		{
			LoggerRecord::WriteLog(L"ToolFunctions::_CheckAutorunReg: RegSetValueEx failed, ret = " + std::to_wstring(ret), LogLevel::ERR);
			RegCloseKey(hkey_autoruns);
			return false;
		}
	}

	RegCloseKey(hkey_autoruns);
	return true;
}

void ToolFunctions::_FormatAutorunInfo(const String& file_name)
{
	String file_temp = file_name + "_tmp";
	String command = String("PowerShell -Command \"& {get-content ") + file_name + " -encoding unicode | set-content " + file_temp + " -encoding utf8}\"";
	system(command.c_str());

	StringList autorun_info_list;
	std::fstream fp(file_temp.c_str(), ios::in);

	String read_buf;
	STRING_VECTOR read_split;
	while (getline(fp, read_buf))
	{
		read_split.clear();
		StringUtil::split(read_buf, ',', read_split);
		if (read_split.size() != 11 || read_split[8].empty())
		{
			continue;
		}
		
		autorun_info_list.push_back(read_buf);
	}
	fp.close();

	fp.open(file_temp, ios::out);
	for (const String& buf : autorun_info_list)
	{
		fp << buf << std::endl;
	}
	fp.close();

	command = String("PowerShell -Command \"& {get-content ") + file_temp + " -encoding utf8 | set-content " + file_name + " -encoding unicode}\"";
	system(command.c_str());

	remove(file_temp.c_str());
}

long ToolFunctions::get_file_ize(const char * filePath) {
    struct _stat state;
    if (_stat(filePath, &state) != 0)              // 获取文件大小失败
        return -1;
    if ((state.st_mode & S_IFMT) == S_IFDIR)          // 路径为目录
        return -1;
    return state.st_size;
}

std::string ToolFunctions::UTF8_to_String(const std::string & str) {
    int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    wchar_t* pwBuf = new wchar_t[nwLen + 1];    //一定要加1，不然会出现尾巴 
    memset(pwBuf, 0, nwLen * 2 + 2);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
    int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
    char* pBuf = new char[nLen + 1];
    memset(pBuf, 0, nLen + 1);
    WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);

    std::string strRet = pBuf;

    delete[]pBuf;
    delete[]pwBuf;
    pBuf = NULL;
    pwBuf = NULL;

    return strRet;
}

int ToolFunctions::GetScreenNumbers() 
{
    // 找出显示器的总数量
    int  i;
    BOOL flag;
    DISPLAY_DEVICE dd;

    i = 0;
    flag = true;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    do {
        flag = EnumDisplayDevices(NULL, i, &dd, 0);
        if (flag) i += 1;
    } while (flag);

    return i;  // 总数量
}

void ToolFunctions::GetScreenRect(long & width, long & height)
{
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);

    auto scrNums = GetScreenNumbers();
    for (int i = 0; i < scrNums; i++)
    {
        BOOL flag;
        DISPLAY_DEVICE dd;

        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
        flag = EnumDisplayDevices(NULL, i, &dd, 0);

        if (!flag) return;

        DEVMODE dm;
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);
        flag = EnumDisplaySettings((wchar_t*)dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm);

        if (!flag) continue;

        if (width < dm.dmPelsWidth || height < dm.dmPelsHeight)
        {
            width = dm.dmPelsWidth;
            height = dm.dmPelsHeight;
        }        
    }
}

std::string ToolFunctions::GetUserPath() 
{
    std::string user_path;
    char homePath[1024] = { 0 };
    unsigned int pathSize = GetEnvironmentVariableA("USERPROFILE", homePath, 1024);
    if (pathSize == 0 || pathSize > 1024) {
        LoggerRecord::WriteLog(L"ToolFunctions::GetUserPath: GetEnvironmentVariableA failed, ret = " + std::to_wstring(GetLastError()), LogLevel::ERR);
    }
    else {
        user_path = string(homePath).substr(2);
		user_path = user_path.substr(0, user_path.rfind('\\') + 1);
		transform(user_path.begin(), user_path.end(), user_path.begin(), ::tolower);
    }
    return user_path;
}

bool ToolFunctions::JudgePath(std::string &srcPath, std::string & dstPath)
{
	transform(dstPath.begin(), dstPath.end(), dstPath.begin(), ::tolower);
    if (dstPath.find("program files") == string::npos && 
        (dstPath.find("desktop") != string::npos || dstPath.find(srcPath) == string::npos)) {
        return true;
    }
    else {
        return false;
    }

    return false;
}

std::wstring ToolFunctions::GetDirectoryfromPath(std::wstring strPath) {
    std::wstring strDir;
    size_t pos = strPath.find_last_of(L"\\/") + 1; // 寻找最右面的'\'或'/'
    strDir = strPath.substr(0, pos);
    return strDir;
}

std::wstring ToolFunctions::GetModuleDirectory() 
{
    WCHAR szFilePath[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    return GetDirectoryfromPath(szFilePath);
}

bool ToolFunctions::KillProcess(DWORD process_id)
{
    DWORD errcode = 0;
    if (process_id <= 0) {
        LoggerRecord::WriteLog(L"KillProcess " + std::to_wstring(process_id) + L" process not exist !", LogLevel::WARN);
        return false;
    }
    if (process_id == 4)
    {
        LoggerRecord::WriteLog(L"KillProcess process is system do not kill !", LogLevel::WARN);
        return false;
    }
 
    LoggerRecord::WriteLog(L"KillProcess Try to kill process, pid is: " + std::to_wstring(process_id), LogLevel::INFO);
    do {
        HANDLE hProcess = NULL;
        //打开目标进程       
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (hProcess == NULL) {
            errcode = GetLastError();
            LoggerRecord::WriteLog(L"KillProcess Open Process failed: " + std::to_wstring(errcode), LogLevel::ERR);
            break;
        }
        //结束目标进程
        DWORD ret = TerminateProcess(hProcess, 0);
        if (ret == 0) {
            errcode = GetLastError();
            LoggerRecord::WriteLog(L"KillProcess TerminateProcess failed: " + std::to_wstring(errcode), LogLevel::ERR);
            break;
        }
        //Mangerment::log_file << "Successful kill " << process_id << std::endl;
        LoggerRecord::WriteLog(L"KillProcess Successful kill", LogLevel::INFO);
        return true;
    } while (0);

    if (errcode == ERROR_ACCESS_DENIED) {
        std::string cmd = "cmd.exe /c taskkill /F /PID " + to_string(process_id);
        auto winret = WinExec(cmd.c_str(), SW_HIDE);
        if (winret > 31) {
            LoggerRecord::WriteLog(L"KillProcess taskkill process Successful", LogLevel::INFO);
            return true;
        }
        LoggerRecord::WriteLog(L"KillProcess taskkill failed: " + std::to_wstring(winret), LogLevel::ERR);
    }
    return false;
}


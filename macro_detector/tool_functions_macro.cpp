#include <iostream>
#include <fstream>
#include <locale>
#include "tool_functions_macro.h"
#include "../tool_functions.h"

using namespace std;


std::wstring ExeCmd(std::wstring pszCmd)
{
	// 创建匿名管道
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hRead, hWrite;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return TEXT(" ");
	}

	// 设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;

	// 启动命令行
	PROCESS_INFORMATION pi;
	UINT errorMode = GetErrorMode();
	// 屏蔽程序奔溃窗口，运行完exe后恢复
	SetErrorMode(SetErrorMode(0) | SEM_NOGPFAULTERRORBOX);
	if (!CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		return TEXT("Cannot create process");
	}

	// 立即关闭hWrite
	CloseHandle(hWrite);
	SetErrorMode(SetErrorMode(0) | errorMode);
	// 读取命令行返回值
	std::string strRetTmp;
	//char *buff = (char *)malloc(10000);
	char buff[1024] = { 0 };
	DWORD dwRead = 0;
	strRetTmp = buff;
	while (ReadFile(hRead, buff, 1024, &dwRead, NULL))
	{
		strRetTmp += buff;
	}
	wstring strRet = ToolFunctions::Str2Wstr(strRetTmp);
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
	return strRet;
}

std::string wstr2str(std::wstring src)
{
	string dest;
	setlocale(LC_CTYPE, "");

	size_t const mbs_len = wcstombs(NULL, src.c_str(), 0);
	std::vector<char> tmp(mbs_len + 1);
	wcstombs(&tmp[0], src.c_str(), tmp.size());

	dest.assign(tmp.begin(), tmp.end() - 1);

	return dest;
}


// 把一个string转化为wstring
std::wstring str2wstr(std::string src)
{
	wstring dest;
	//   std::setlocale(LC_CTYPE, "");
	setlocale(LC_CTYPE, "zh_CN");

	size_t const wcs_len = mbstowcs(NULL, src.c_str(), 0);
	std::vector<wchar_t> tmp(wcs_len + 1);
	mbstowcs(&tmp[0], src.c_str(), src.size());

	dest.assign(tmp.begin(), tmp.end() - 1);

	return dest;
}

bool includeChinese(string str) 
{
	for (int i = 0; i < str.length(); i++) {
		if (!((str[i] <= 'z' && str[i] >= 'a') || (str[i] <= 'Z' && str[i] >= 'A')  || (str[i]<='9' && str[i]>='0') || str[i] == '\\' || str[i] == '.' || str[i] == ':' || str[i] == '_' || str[i] == '-' || str[i]=='/')) {
			return true;
		}
	}
	return false;
}

std::wstring chineseStr2wstr(std::string src) 
{
	if (includeChinese(src)) {
		std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> decode(new std::codecvt<wchar_t, char, std::mbstate_t>("CHS"));
		return decode.from_bytes(src);
	}
	else {
		return str2wstr(src);
	}
}

string readFileData(const std::string& filename)
{
	std::ifstream t(ToolFunctions::StringToWString(filename));
	std::string str((std::istreambuf_iterator<char>(t)),
		std::istreambuf_iterator<char>());
	t.close();
	return str;
}

void GetAllFileNames(string path, vector<string>& files)
{

	intptr_t   hFile = 0;
	//文件信息  
	struct _finddata_t fileinfo;
	string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
				{
					string filename = p.assign(path).append("\\").append(fileinfo.name);
					files.push_back(filename);
					GetAllFileNames(filename, files);
				}
			}
			else
			{
				string filename = p.assign(path).append("\\").append(fileinfo.name);
				files.push_back(filename);
			}

		} while (_findnext(hFile, &fileinfo) == 0);

		_findclose(hFile);
	}

}

void GetAllFiles(string path, vector<string>& files)
{

	intptr_t   hFile = 0;
	//文件信息  
	struct _finddata_t fileinfo;
	string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
				{
					string filename = p.assign(path).append("\\").append(fileinfo.name);
					files.push_back(readFileData(filename));
					GetAllFiles(filename, files);
				}
			}
			else
			{
				string filename = p.assign(path).append("\\").append(fileinfo.name);
				files.push_back(readFileData(filename));
				remove(filename.c_str());
			}

		} while (_findnext(hFile, &fileinfo) == 0);

		_findclose(hFile);
	}

}

const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}


std::string base64_decode(std::string const& encoded_string) {
	int in_len = (int)encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=')) {
		if (!is_base64(encoded_string[in_])) {
			if (encoded_string[in_] == '\n') {
				in_++;
				continue;
			}
			else {
				break;
			}
		}
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = (unsigned char)base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = (unsigned char)base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}
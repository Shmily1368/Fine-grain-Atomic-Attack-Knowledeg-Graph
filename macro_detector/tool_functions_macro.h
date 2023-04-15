#pragma once
#include <iostream>
#include <string>
#include <io.h>
#include <locale.h>
#include <Windows.h>
#include <vector>

std::wstring ExeCmd(std::wstring pszCmd);
std::string wstr2str(std::wstring src);
std::wstring str2wstr(std::string src);
void GetAllFileNames(std::string path, std::vector<std::string>& files);
void GetAllFiles(std::string path, std::vector<std::string>& files);
std::string readFileData(const std::string& filename);
bool is_base64(unsigned char c);
std::string base64_decode(std::string const& encoded_string);
bool includeChinese(std::string str);
std::wstring chineseStr2wstr(std::string src);



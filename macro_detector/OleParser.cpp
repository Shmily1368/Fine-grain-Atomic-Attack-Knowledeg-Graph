#include <iostream>
#include <Windows.h>
#include <sstream> 
#include <map>
#include <algorithm>
#include "tool_functions_macro.h"
#include <vector>
using namespace std;

std::vector<std::string> split(const std::string& s, const std::string& delim)
{
	std::vector<std::string> elems;
	size_t pos = 0;
	size_t len = s.length();
	size_t delim_len = delim.length();
	if (delim_len == 0) return elems;
	while (pos < len)
	{
		size_t find_pos = s.find(delim, pos);
		if (find_pos == string::npos)
		{
			elems.push_back(s.substr(pos, len - pos));
			break;
		}
		elems.push_back(s.substr(pos, find_pos - pos));
		pos = find_pos + delim_len;
	}
	return elems;
}

void extract_vba(string data) 
{
	map<string, string> codeModules;
	std::istringstream f(data);
	std::string line;
	while (std::getline(f, line)) 
	{
		if (line.find_first_of("=") != string::npos) 
		{
			vector<string> tmp = split(line, "=");
			string name = tmp[0];
			string value = tmp[1];
			transform(
				value.begin(), value.end(),
				value.begin(),
				tolower
			);
			if (name == "Document") 
			{
				value = split(value, "/")[0];
				codeModules[value] = "CLASS_EXTENSION";
			}
			else if (name == "Module") 
			{
				codeModules[value] = "MODULE_EXTENSION";
			}
			else if (name == "Class") 
			{
				codeModules[value] = "CLASS_EXTENSION";
			}
			else if (name == "BaseClass") 
			{
				codeModules[value] = "FORM_EXTENSION";
			}
		}

	}
}

void test(string data) {
	//map<string, string> codeModules;
	//std::istringstream f(data);
	//std::string line;
	//char()
	//f.read()
}

void openStorage(IStorage* pStorage, wstring prefix) {
	IEnumSTATSTG *iEnum;
	HRESULT hResult = pStorage->EnumElements(0, NULL, 0, &iEnum);
	if (FAILED(hResult))
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout<<"Ã¶¾ÙÆ÷»ñÈ¡Ê§°Ü"<<endl;
#endif // OUTPUT_COMMAND_LINE;
		return;
	}
	STATSTG stg = { 0 };
	while (NOERROR == iEnum->Next(1, &stg, NULL))
	{
		
		if (STGTY_STREAM == stg.type)
		{
			wstring path = prefix + stg.pwcsName;
			if (wcscmp(stg.pwcsName, L"PROJECT")==0) {
				IStream* pStream;
				hResult = pStorage->OpenStream(stg.pwcsName, 0, STGM_DIRECT | STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream);
				if (FAILED(hResult))
				{
#ifdef OUTPUT_COMMAND_LINE      
					cout << "open stream failed" << endl;
#endif // OUTPUT_COMMAND_LINE;
					return;
				}
				ULONG readEd = 0;
				unsigned _int64 size = stg.cbSize.QuadPart;
				char *content = (char *)malloc(size);
				pStream->Read(content, (ULONG)size, &readEd);
				string str(content, content + size);
				extract_vba(str);
#ifdef OUTPUT_COMMAND_LINE      
				cout << str << endl;
				cout << 123 << endl;
#endif // OUTPUT_COMMAND_LINE;
				//int size = stg.cbSize;
				//char *content = (char *)malloc(size);
				//pStream->Read(content, stg.cbSize, &readEd);
				//char content[100000] = {0};

				//pStream->Read(content, 100000, &readEd);
				//wofstream out;
				//out.open("test2.txt", ios::out | ios::binary);
				//out << content << endl;
				//out.close();
				//string s(reinterpret_cast<char const*>(content));
				
				//ULONG lsize = 0;
				//char content[10000];
				//HRESULT hr = pStream->Read(&lsize, sizeof(int), NULL);
				//hr = pStream->Read(content, lsize, NULL);
				//content[lsize] = '\0';
				//cout << s << endl;
			}
			if (wcscmp(stg.pwcsName, L"dir") == 0) {
				IStream* pStream;
				hResult = pStorage->OpenStream(stg.pwcsName, 0, STGM_DIRECT | STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream);
				if (FAILED(hResult))
                {
#ifdef OUTPUT_COMMAND_LINE       
					cout << "open stream failed" << endl;
#endif // OUTPUT_COMMAND_LINE;
					return;
				}
				ULONG readEd = 0;
				unsigned _int64 size = stg.cbSize.QuadPart;
				char *content = (char *)malloc(size);
				pStream->Read(content, (ULONG)size, &readEd);
				string str(content, content + size);
				test(str);
#ifdef OUTPUT_COMMAND_LINE       
				cout << str << endl;
				cout << 222 << endl;
#endif // OUTPUT_COMMAND_LINE;
			}
		}
		else if (STGTY_STORAGE == stg.type)
		{
#ifdef OUTPUT_COMMAND_LINE       
			wcout << "storage: " << prefix << stg.pwcsName << endl;
#endif // OUTPUT_COMMAND_LINE;
			IStorage* pStorage2;
			pStorage->OpenStorage(stg.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &pStorage2);
			openStorage(pStorage2, prefix+stg.pwcsName+L"/");
		}
		
		//::CoTaskMemFree(stg.pwcsName);
	}
}

string readStream(string filename) {
	IStorage* pStorage ;
	HRESULT hResult = ::StgIsStorageFile(str2wstr(filename).c_str());
	if (FAILED(hResult))
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "not ole" << endl;
#endif // OUTPUT_COMMAND_LINE;
		return 0;
	}
	HRESULT hr;
	hr = StgOpenStorage(str2wstr(filename).c_str(), NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &pStorage);
	openStorage(pStorage, L"");
	//IEnumSTATSTG *iEnum;
	//hResult = pStorage->EnumElements(0, NULL, 0, &iEnum);
	//STATSTG stg = { 0 };
	//while (NOERROR == iEnum->Next(1, &stg, NULL))
	//{
	//	if (STGTY_STREAM == stg.type)
	//	{
	//		int a = 0;
	//		a++;

	//	}
	//	else if (STGTY_STORAGE == stg.type)
	//	{
	//		cout << "one Storage" << endl;
	//		//MessageBox(L"STORAGE", 0, 0);
	//	}
	//	wcout << stg.pwcsName << endl;
	//	//::CoTaskMemFree(stg.pwcsName);
	//}
	//IStorage* pStorage2 = NULL;
	//pStorage->OpenStorage(L"Macros", NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &pStorage2);
	//hResult = pStorage2->EnumElements(0, NULL, 0, &iEnum);
	//stg = { 0 };
	//cout << "11111111" << endl;
	//while (NOERROR == iEnum->Next(1, &stg, NULL))
	//{
	//	if (STGTY_STREAM == stg.type)
	//	{
	//		int a = 0;
	//		a++;

	//	}
	//	else if (STGTY_STORAGE == stg.type)
	//	{
	//		cout << "one Storage" << endl;
	//		//MessageBox(L"STORAGE", 0, 0);
	//	}
	//	wcout << stg.pwcsName << endl;
	//	//::CoTaskMemFree(stg.pwcsName);
	//}
}
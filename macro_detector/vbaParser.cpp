#include <iostream>
#include <fstream>
#include <algorithm>
#include <regex>
#include <direct.h>
#include <Windows.h>
#include <locale.h>
#include <cstdio>
#include "tool_functions_macro.h"
#include "vbaParser.h"
#include "zip/unzip.h"
#include "zip/zip.h"
#include "zlib/zlib.h"
#include "pugixml/pugixml.hpp"
#include "../tool_functions.h"

#include "mime2.h"

using namespace std;

extern "C" {
	char **vba_dump(const char *filename, int *vbacode_num);
}

const string tmpPath = "macro_detector\\TEMP\\";

int VbaParser::isOleFile(const std::string& filename)
{
	unsigned char OLE_MAGIC[8] = { 0xD0, 0xCF, 0X11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
	ifstream in;
	unsigned char magic[8];
	std::wstring w_filename = ToolFunctions::StringToWString(filename);
	in.open(w_filename.c_str(), ios::in | ios::binary);
	if (!in)
	{
		LoggerRecord::WriteLog(L"VbaParser::isOleFile: open file failed, path = " + ToolFunctions::StringToWString(filename), LogLevel::INFO);
		return 0;
	}
	in.read((char*)magic, 8);
	if (memcmp(magic, OLE_MAGIC, 8) == 0)
	{
		in.close();
		return 1;
	}
	in.close();
	return 0;
}

vector<string> Split(string &str, string a)
{
	vector<string> strvec;

	string::size_type pos1, pos2;
	pos2 = str.find(a);
	pos1 = 0;
	while (string::npos != pos2)
	{
		strvec.push_back(str.substr(pos1, pos2 - pos1));

		pos1 = pos2 + 1;
		pos2 = str.find(a, pos1);
	}
	strvec.push_back(str.substr(pos1));
	return strvec;
}

vector<string> VbaParser::getVbaFilesUseDll(vector<string> &filepaths) {
	vector<string> vba_codes;
	//if (_chdir(tmpPath.c_str())) {
	//	return vbaFiles;
	//};
	for (string filepath : filepaths) {
		string tmpFilepath = filepath;
		if (tmpFilepath.find(":") == string::npos) {
			tmpFilepath = tmpPath + "\\" + tmpFilepath;
		}

		int code_num = 0;
		char **codes = NULL;
		codes = vba_dump(tmpFilepath.c_str(), &code_num);
		if (codes != NULL) {
			for (int i = 0; i < code_num; i++) {
				string tmp(codes[i]);
				vba_codes.push_back(tmp);
				free(codes[i]);
			}
			free(codes);
		}
		

	}
	//if (_chdir("..\\..")) {
	//	cout << "chdir failed" << endl;
	//};
	return vba_codes;
}

vector<string> VbaParser::getVbaFilesUseSigtool(vector<string> &filepaths) {
	vector<string> vbaFiles;
	if (_chdir(tmpPath.c_str())) {
		return vbaFiles;
	};
	wstring sigToolPath = L"SigTool\\sigtool.exe";
	for (string filepath : filepaths) {
		string tmpFilepath = filepath;
		bool hasChinese = false;
		if (includeChinese(tmpFilepath)) {
			tmpFilepath = "tmp";
			CopyFile(ToolFunctions::StringToWString(filepath).c_str(), ToolFunctions::StringToWString(tmpFilepath).c_str(), false);
			GetLastError();
			hasChinese = true;
		}
		wstring cmd(sigToolPath + L" --vba=" + ToolFunctions::Str2Wstr(tmpFilepath));
		wstring exeRes = ExeCmd(cmd);
		vector<string> tmpVbaFiles = Split(ToolFunctions::WStringToString(exeRes), "-------------- end of code ------------------");
		vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
		if (hasChinese) {
			if (remove(tmpFilepath.c_str()) != 0) {
			};
		}
	}
	if (_chdir("..\\..")) {
#ifdef OUTPUT_COMMAND_LINE       
		cout << "chdir failed" << endl;
#endif // OUTPUT_COMMAND_LINE;
	};
	return vbaFiles;
}

vector<string> VbaParser::getVbaFiles(vector<string>& filepaths) {
	vector<string> vbaFiles;
	//string tmpPath = "macro_detector\\TEMP\\";
	if (_chdir(tmpPath.c_str())) {
		return vbaFiles;
	};
	string officeMalScannerPath = "OfficeMalScanner\\OfficeMalScanner.exe";
	for (string filepath : filepaths) {
		string tmpFilepath = filepath;
		bool hasChinese = false;
		if (includeChinese(tmpFilepath)) {
			tmpFilepath = "tmp";
			CopyFile(ToolFunctions::StringToWString(filepath).c_str(), ToolFunctions::StringToWString(tmpFilepath).c_str(), false);
			GetLastError();
			hasChinese = true;
		}
		string cmd(officeMalScannerPath + " " + tmpFilepath + " info");
		size_t pos = tmpFilepath.find_last_of("/");
		string vbaPath;
		if (pos == string::npos) {
			size_t pos2 = tmpFilepath.find_last_of("\\");
			if (pos2 == wstring::npos)
			{
				vbaPath = tmpFilepath;
			}
			else
			{
				vbaPath = tmpFilepath.substr(pos2 + 1);
			}
		}
		else {
			vbaPath = tmpFilepath.substr(pos + 1);
		}
		transform(vbaPath.begin(), vbaPath.end(), vbaPath.begin(), ::toupper);
		vbaPath += "-Macros";
		wstring exeRes = ExeCmd(str2wstr(cmd));
		string tmpPath2 = vbaPath;
		GetAllFiles(tmpPath2, vbaFiles);
		if (_rmdir(vbaPath.c_str())!=0) {
		};
		if (hasChinese) {
			if (remove(tmpFilepath.c_str()) != 0) {
			};
		}

		//RemoveDirectory(str2wstr(vbaPath).c_str());
	}
	if (_chdir("..\\..")) {
#ifdef OUTPUT_COMMAND_LINE       
		cout << "chdir failed" << endl;
#endif // OUTPUT_COMMAND_LINE;
	};
	return vbaFiles;
}

vector<string> search(string s, string pattern) {
	vector<string> res;
	regex re(pattern, regex::icase);
	smatch m;
	regex_search(s, m, re);
	for (auto x = m.begin(); x != m.end(); x++) {
		res.push_back(x->str());
	}
	return res;
}

bool VbaParser::isVbaCodeMalicious(std::string data) {
	string autoExecPattern = "(?:Auto(?:Exec|_?Open|_?Close|Exit|New)|Document(?:_?Open|_Close|_?BeforeClose|Change|_New)|NewDocument|Workbook(?:_Open|_Activate|_Close)|\w+_(?:Painted|Painting|GotFocus|LostFocus|MouseHover|Layout|Click|Change|Resize|BeforeNavigate2|BeforeScriptExecute|DocumentComplete|DownloadBegin|DownloadComplete|FileDownload|NavigateComplete2|NavigateError|ProgressChange|PropertyChange|SetSecureLockIcon|StatusTextChange|TitleChange|MouseMove|MouseEnter|MouseLeave|))";
	string writePattern = "(?:FileCopy|CopyFile|Kill|CreateTextFile|VirtualAlloc|RtlMoveMemory|URLDownloadToFileA?|AltStartupPath|ADODB\.Stream|WriteText|SaveToFile|SaveAs|SaveAsRTF|FileSaveAs|MkDir|RmDir|SaveSetting|SetAttr)|(?:\bOpen\b[^\n]+\b(?:Write|Append|Binary|Output|Random))";
	string executePattern = "(?:Shell|CreateObject|GetObject|SendKeys|MacScript|FollowHyperlink|CreateThread|ShellExecute)|(?:\bDeclare\b[^\n]+\bLib\b)";

	vector<string> autoExecMatch = search(data, autoExecPattern);
	vector<string> writeMatch = search(data, writePattern);
	vector<string> executeMatch = search(data, executePattern);
	if (autoExecMatch.size() != 0 && (writeMatch.size() != 0 || executeMatch.size() != 0)) {
		return TRUE;
	}
	return false;
}

bool VbaParser::isFileMalicious() {
	bool isMalicious = false;
	for (string vbaFile : vbaFiles) {
		if (isVbaCodeMalicious(vbaFile)) {
			isMalicious = true;
			break;
		}
	}
	vbaFiles.clear();
	return isMalicious;
}

void VbaParser::ListVbaFiles(std::vector<std::string>& file_list)
{
	std::copy(vbaFiles.begin(), vbaFiles.end(), std::back_inserter(file_list));
}

bool VbaParser::isZipFile(const std::string& filename) {
	wstring wfilename = ToolFunctions::StringToWString(filename);
	HZIP hz = OpenZip(wfilename.c_str(), 0);
	if (IsZipHandleU(hz)) {
		CloseZip(hz);
		return true;
	}
	CloseZip(hz);
	return false;
}

std::vector<std::string> VbaParser::openXml(std::string filename) {
	vector<string> res;
	wstring unzipPath = ToolFunctions::StringToWString(tmpPath);
	wstring oleFilePath = L"OLE_FILE\\";
	unsigned char OLE_MAGIC[8] = { 0xD0, 0xCF, 0X11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
	HZIP hz = OpenZip(ToolFunctions::StringToWString(filename).c_str(), 0);
	if (hz == NULL)
	{
		return res;
	}

	SetUnzipBaseDir(hz, unzipPath.c_str());

	ZIPENTRY ze;
	GetZipItem(hz, -1, &ze);


	// µ›πÈΩ‚—π
	int numitems = ze.index;
	//char *c_cwd = _getcwd(NULL, 0);
	//wchar_t *w_cwd = (wchar_t *)malloc(sizeof(wchar_t));
	//mbstowcs(w_cwd, c_cwd, strlen(c_cwd)*sizeof(char));
	//wstring cwd(w_cwd);
	for (int zi = 0; zi < numitems; zi++)
	{
		unsigned char magic[8];
		UnzipItem(hz, zi, magic, 8);
		if (memcmp(magic, OLE_MAGIC, 8) == 0) {
			GetZipItem(hz, zi, &ze);
			wstring subfilename = ze.name;
			wstring filepath = oleFilePath + subfilename;
			const int size = ze.unc_size;
			//unsigned char *buff = (unsigned char *)malloc(size);
			//UnzipItem(hz, zi, buff, size);
			//string str(buff, buff+size);
			//res.push_back(str);
			UnzipItem(hz, zi, filepath.c_str());
			res.push_back(ToolFunctions::WStringToString(filepath));
			//remove(wstr2str(filepath).c_str());
		}

	}
	CloseZip(hz);
	return res;
}

string extractFile(string data, string fname,  int start) {
	string unzipPath = "macro_detector\\TEMP\\";
	size_t size = data.size();
	unsigned char * buf = (unsigned char *)malloc(size - start);
	memcpy_s(buf, size - start, data.substr(start).c_str(), size - start);
	unsigned char * strDst = (unsigned char *)malloc(100000);
	//unsigned char strDst[100000] = { 0 };
	unsigned long dstLen = 100000*sizeof(unsigned char);
	uncompress(strDst, &dstLen, buf, (uLong)(size - start));
	//string str(strDst, strDst + dstLen);
	//return str;
	ofstream out;
	string fileName = unzipPath + fname;
	out.open(fileName, ios::out | ios::binary);
	out.write((char *)strDst, dstLen);
	out.close();
	free(buf);
	free(strDst);
	return fname;
}

string extractMsoFile(string data, string fname) {
	vector<unsigned char> msoFile;
	int offsets[3] = { 0, 0X32, 0X22A };
	int offset = data[0X1E] + 46;
	offsets[0] = offset;
	for (int start : offsets) {
		try {
			return extractFile(data, fname, start);
		}
		catch (...) {
			continue;
		}
	}

	string flag = "x";
	int position = 0;
	while ((position = (int)data.find_first_of(flag, position)) != string::npos) {
		try {
			int start = position;
			return extractFile(data, fname, start);
		}
		catch (...) {
			position++;
			continue;
		}
	}
	return "";
}

vector<string> VbaParser::openWord2003Xml(string filename) {
	pugi::xml_document xmlDoc;
	xmlDoc.load_file(filename.c_str());
	vector<string> oleFiles;
	pugi::xpath_node_set nodes = xmlDoc.select_nodes("//w:binData");
	
	for (auto& node : nodes)
	{
		string data = node.node().child_value();
		string fname = node.node().attribute("w:name").value();
		if (fname == "") {
			fname = "noname.mso";
		}
		string res = base64_decode(data);
		if (res.find_first_of("ActiveMime") == 0) {
			string msoFileName = extractMsoFile(res, fname);
			oleFiles.push_back(msoFileName);
			//std::vector<std::string> tmpVbaFiles = getVbaFiles(oleFiles);
			//vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
			//VBA_Parser vba_parser(filename);
			//vbaFiles.insert(vbaFiles.begin(), vba_parser.vbaFiles.begin(), vba_parser.vbaFiles.end());

		}
	}
	return oleFiles;
}

vector<string> VbaParser::openMht(string filename) {
	vector<string> oleFiles;
	ifstream in;
	in.open(filename);
	std::string str((std::istreambuf_iterator<char>(in)),
		std::istreambuf_iterator<char>());
	MIME2::CONTENT c;
	if (c.Parse(str.c_str()) != MIME2::MIMEERR::OK)
		return oleFiles;

	auto a1 = c.hval("Content-Type", "boundary");
	if (a1.empty())
		return oleFiles;

	vector<MIME2::CONTENT> contents;
	
	MIME2::ParseMultipleContent2(str.c_str(), str.length(), a1.c_str(), contents);
	int num = 0;
	for (MIME2::CONTENT content : contents) {
		vector<char> dataVector = content.GetData();
		string data(dataVector.begin(), dataVector.end());
		data = base64_decode(data);
		
		if (data.find_first_of("ActiveMime") == 0) {
			string fname = "tmp" + to_string(num++)+".mso";
			string msoFileName = extractMsoFile(data, fname);
			oleFiles.push_back(msoFileName);
			//wstring filename = extractMsoFile(data);
			//VBA_Parser vba_parser(filename);
			//vbaFiles.insert(vbaFiles.begin(), vba_parser.vbaFiles.begin(), vba_parser.vbaFiles.end());
		}
	}
	in.close();
	return oleFiles;
}

VbaParser::VbaParser(const std::string& filename)
{
	LoggerRecord::WriteLog(L"VbaParser::VbaParser: start detect macro, file_name = " + ToolFunctions::StringToWString(filename), LogLevel::INFO);

	if (isOleFile(filename)) {
		vector<string> oleFiles;
		oleFiles.push_back(filename);
		std::vector<std::string> tmpVbaFiles = getVbaFilesUseDll(oleFiles);
		vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
		oleFiles.clear();
		tmpVbaFiles.clear();

		LoggerRecord::WriteLog(L"VbaParser::VbaParser: is ole file, vba_file_size = " + std::to_wstring(vbaFiles.size()), LogLevel::INFO);
	}
	else if (isZipFile(filename)) {
		vector<string> oleFiles = openXml(filename);
		std::vector<std::string> tmpVbaFiles = getVbaFilesUseDll(oleFiles);
		vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
		for (string f : oleFiles) {
			for (int i = 0; i < 10; i++) {
				if (remove(("macro_detector\\TEMP\\" + f).c_str()) == 0)
				{
					break;
				}
			}
		}
		oleFiles.clear();
		tmpVbaFiles.clear();

		LoggerRecord::WriteLog(L"VbaParser::VbaParser: is zip file, vba_file_size = " + std::to_wstring(vbaFiles.size()), LogLevel::INFO);
	}
	else {
		string data = readFileData(filename);
		string dataLowercase = data;
		transform(
			dataLowercase.begin(), dataLowercase.end(),
			dataLowercase.begin(),
			tolower
		);
		if (data.find("http://schemas.microsoft.com/office/word/2003/wordml") != string::npos) {
			vector<string> oleFiles = openWord2003Xml(filename);
			std::vector<std::string> tmpVbaFiles = getVbaFilesUseDll(oleFiles);
			vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
			for (string f : oleFiles) {
				for (int i = 0; i < 10; i++) {
					if (remove(("macro_detector\\TEMP\\" + f).c_str()) == 0)
					{
						break;
					}
				}
			}
			oleFiles.clear();
			tmpVbaFiles.clear();
		}
		else if (dataLowercase.find("mime") != string::npos && dataLowercase.find("version") != string::npos && dataLowercase.find("multipart") != string::npos) {
			vector<string> oleFiles = openMht(filename);
			std::vector<std::string> tmpVbaFiles = getVbaFilesUseDll(oleFiles);
			vbaFiles.insert(vbaFiles.begin(), tmpVbaFiles.begin(), tmpVbaFiles.end());
			for (string f : oleFiles) {
				for (int i = 0; i < 10; i++) {
					if (remove(("macro_detector\\TEMP\\" + f).c_str()) == 0)
					{
						break;
					}
				}
			}
			oleFiles.clear();
			tmpVbaFiles.clear();
		}
	}
}
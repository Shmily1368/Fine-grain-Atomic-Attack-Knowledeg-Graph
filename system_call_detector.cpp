#include "stdafx.h"
#include "system_call_detector.h"
#include "tool_functions.h"
#include "on_leave_section_callback.h"

#include <io.h>
#include <direct.h>
#include <winternl.h>

#define SYMBOL_CONFIGURATION_DIR "syscall_configuration"

#define MAXIMUM_FILENAME_LENGTH 256
typedef struct _SYSTEM_MODULE
{
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG				ModulesCount;
	SYSTEM_MODULE		Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _SYMBOL_CONFIGURATION
{
	String system_file_name;
	String system_file_path;
	String symbol_file_name;
	DWORD image_base;
} SYMBOL_CONFIGURATION;
using SymbolConfigurationMap = std::map<String, SYMBOL_CONFIGURATION>;
SymbolConfigurationMap symbol_configuration_map;

SystemCallDetector::SystemCallDetector()
{

}

SystemCallDetector::~SystemCallDetector()
{

}

bool SystemCallDetector::Init()
{
	//std::fstream fp;
	//fp.open("syscall_configuration\\symbol_file_configuration", ios::in);
	//String read_buf;
	//while (getline(fp, read_buf))
	//{
	//	if (read_buf[0] == '#')	continue;

	//	STRING_VECTOR read_split;
	//	StringUtil::split(read_buf, '|', read_split);
	//	if (read_split.size() >= 3)
	//	{
	//		SYMBOL_CONFIGURATION symbol_config;
	//		symbol_config.system_file_name = read_split[0];
	//		symbol_config.system_file_path = read_split[1];
	//		symbol_config.symbol_file_name = read_split[2];
	//		symbol_config.image_base = 0;
	//		symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));
	//	}
	//}
	//fp.close();

	//switch (ToolFunctions::GetSystemOs()) {
	//	case EM_OsVersion::WIN7:
	//	case EM_OsVersion::WS2012_R2:
	//	{
	//		SYMBOL_CONFIGURATION symbol_config;
	//		symbol_config.system_file_name = "win32k.sys";
	//		symbol_config.system_file_path = "C:\Windows\System32\win32k.sys";
	//		symbol_config.symbol_file_name = "win32k.pdb";
	//		symbol_config.image_base = 0;
	//		symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	//		symbol_config.system_file_name = "ntoskrnl.exe";
	//		symbol_config.system_file_path = "C:\Windows\System32\ntoskrnl.exe";
	//		symbol_config.symbol_file_name = "ntkrnlmp.pdb";
	//		symbol_config.image_base = 0;
	//		symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	//		break;
	//	}
	//	case EM_OsVersion::WIN10:
	//	{
	//		SYMBOL_CONFIGURATION symbol_config;
	//		symbol_config.system_file_name = "win32kfull.sys";
	//		symbol_config.system_file_path = "C:\Windows\System32\win32kfull.sys";
	//		symbol_config.symbol_file_name = "win32k.pdb";  //for server do not need handle particularly
	//		symbol_config.image_base = 0;
	//		symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	//		symbol_config.system_file_name = "ntoskrnl.exe";
	//		symbol_config.system_file_path = "C:\Windows\System32\ntoskrnl.exe";
	//		symbol_config.symbol_file_name = "ntkrnlmp.pdb";
	//		symbol_config.image_base = 0;
	//		symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	//		break;
	//	}
	//}


	SYMBOL_CONFIGURATION symbol_config;
	symbol_config.system_file_name = "win32k.sys";
	symbol_config.system_file_path = "C:\\Windows\\System32\\win32k.sys";
	symbol_config.symbol_file_name = "win32k.pdb";
	symbol_config.image_base = 0;
	symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	symbol_config.system_file_name = "ntoskrnl.exe";
	symbol_config.system_file_path = "C:\\Windows\\System32\\ntoskrnl.exe";
	symbol_config.symbol_file_name = "ntkrnlmp.pdb";
	symbol_config.image_base = 0;
	symbol_configuration_map.insert(std::make_pair(symbol_config.system_file_name, symbol_config));

	DEFINE_DLL_FUNCTION(NtQuerySystemInformation, NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG), "ntdll.dll");
	PSYSTEM_MODULE_INFORMATION system_info;
	DWORD dw_buffer_size;
	NTSTATUS ret = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &dw_buffer_size);
	system_info = (PSYSTEM_MODULE_INFORMATION)malloc(dw_buffer_size);
	ret = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, system_info, dw_buffer_size, 0);

	int_32 match_cnt = 0;
	for (DWORD i = 0; i <= system_info->ModulesCount; i++)
	{
		String module_path = system_info->Modules[i].FullPathName;
		LoggerRecord::WriteLog(L"SystemCallDetector::Init: module path = " + ToolFunctions::StringToWString(module_path), LogLevel::INFO);
		for (auto& pair : symbol_configuration_map)
		{
			if (module_path.find(pair.second.system_file_name) != String::npos)
			{
				pair.second.image_base = (DWORD)system_info->Modules[i].ImageBase;
				match_cnt++;
				LoggerRecord::WriteLog(L"SystemCallDetector::_CheckSymbol: symbol_file_name = " + ToolFunctions::StringToWString(module_path) + L" ImageBase: "+ ToolFunctions::StringToWString(std::to_string((DWORD)system_info->Modules[i].ImageBase)), LogLevel::INFO);
				break;
			}
		}
		
		if (match_cnt == symbol_configuration_map.size())	break;
	}
	

	for (auto pair : symbol_configuration_map)
	{
		_LoadSymbol(pair.second.system_file_path, pair.second.symbol_file_name, pair.second.image_base);
	}

	return true;
}

String SystemCallDetector::ParseApi(ULONG64 address)
{
	auto iter = _address_api_map.find(address);
	return iter != _address_api_map.end() ? iter->second : EMPTY_STRING;
}

bool SystemCallDetector::_LoadSymbol(const String& system_file_path, const String& symbol_file_name, DWORD image_base)
{
	String symbol_path = String(SYMBOL_CONFIGURATION_DIR) + "\\" + symbol_file_name + ".mapping";
	if (_access(symbol_path.c_str(), 0) != 0)
	{
		//LoggerRecord::WriteLog(L"SystemCallDetector::_CheckSymbol: symbol file missing, symbol_file_name = " + ToolFunctions::StringToWString(symbol_file_name) +
			//L", symbol_file_uuid = " + ToolFunctions::StringToWString(ToolFunctions::GetPEFileHash(system_file_path)), LogLevel::ERR);
		LoggerRecord::WriteLog(L"SystemCallDetector::_CheckSymbol: symbol file missing, symbol_file_name = " + ToolFunctions::StringToWString(system_file_path), LogLevel::ERR);
		return false;
	}

	std::fstream fp(symbol_path);
	String read_buf;
	while (getline(fp, read_buf))
	{
		STRING_VECTOR read_split;
		StringUtil::split(read_buf, ':', read_split);
		if (read_split.size() >= 2)
		{
			_address_api_map.insert(std::make_pair((DWORD)(atoi(read_split[1].c_str())) + image_base, read_split[0]));
		}
	}

	return true;
}

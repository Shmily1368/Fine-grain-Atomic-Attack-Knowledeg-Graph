#pragma once
#include <windows.h>
#include <dia_sdk/dia2.h>

class SystemCallDetector
{
	SINGLETON_DEFINITION(SystemCallDetector);
	DISABLE_COPY(SystemCallDetector);

public:
	SystemCallDetector();
	~SystemCallDetector();

	bool Init();
	String ParseApi(ULONG64 address);

private:
 	bool _LoadSymbol(const String& system_file_path, const String& symbol_file_name, DWORD image_base);

private:
	std::unordered_map<DWORD, String> _address_api_map;
};
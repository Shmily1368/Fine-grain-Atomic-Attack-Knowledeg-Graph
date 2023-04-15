#pragma once
#include <windows.h>
class public_xml_interface
{
	SINGLETON_DEFINITION(public_xml_interface);

public:
	bool ParseSecurityAudit(String szxml, std::unordered_map<String, String>& mdata);
    bool ParseTaskContent(String szxml, std::unordered_map<String, String>& mdata);
    bool ParseSysmon(String szxml, std::unordered_map<String, String>& mdata);
private:
	public_xml_interface(void) {};
	~public_xml_interface(void) {};
};


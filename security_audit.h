#pragma once
#include <windows.h>
class security_audit
{
	SINGLETON_DEFINITION(security_audit);

public:
	void Init();

	String MakeSecurityAudit(std::unordered_map<String, String>& mdata, long& pid, long& tid);

private:
	security_audit(void) {};
	~security_audit(void) {};
};


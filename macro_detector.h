/*********************************************************************************
*
* Description : This project is written to call Python script
* in C++.
*
* Written by : Chunlin
* Create Time : 2018-09-11
* Last Upate : 2018-09-12
*
*********************************************************************************/

#pragma once

class MacroDetector
{
	SINGLETON_DEFINITION(MacroDetector)

public:
	void Init();
	bool IsMacroEnableApp(const String& app_name);

	EM_MarcoDetectResult DetectMacro(const std::wstring& file_path, STRING_VECTOR& macro_contents);

private:
	STRING_SET _macro_enable_apps;
};

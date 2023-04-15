//#include"stdafx.h"
#include "powershell_detector.h"
#include"file_deal.h"
#include<windows.h>
#include"cmdExec.h"
#include<iostream>
#include <time.h>
#include"../tool_functions.h"
#include"../logger_record.h"
#include "../init_collector.h"
#include<algorithm>
#include<regex>
#include"../event_record_manager.h"
#define POWERSHELL_DETECTOR_EXE "D:\\code\\PowershellDeobfuscation2.0\\bin\\x64\\Release\\PowershellDeobfuscation.exe "
using namespace std;
powershell_Result powershell_Result::dealResult(string& result, int pid, int tid) {
	powershell_Result ret;
	int beginindex = 0;
	if ((beginindex = result.find("-------------------------------------------------")) == -1) {
		return ret;
	}
	int scorebegin = result.find("score:", beginindex);
	int verdictbegin = result.find("verdict:");
	int waledatabegin = result.find("data:");
	if (scorebegin == -1 || verdictbegin == -1 || waledatabegin == -1) {
		return ret;
	}
	scorebegin = scorebegin + 6;
	verdictbegin = verdictbegin + 8;
	waledatabegin = waledatabegin + 5;

	int scoreend = result.find("\r\n", scorebegin);
	int verdictend = result.find("\n", verdictbegin);
	int waledataend = result.find("\r\n", waledatabegin);
	string score = result.substr(scorebegin, scoreend - scorebegin);
	string verdic = result.substr(verdictbegin, verdictend - verdictbegin);
	string waledata = result.substr(waledatabegin, waledataend - waledatabegin);
	ret.score = atoi(score.c_str());
	ret.verdict = verdic;
	ret.content = waledata;
	ret.pid = pid;
	ret.tid = tid;
	//ret.command = command;
	return ret;
}
ostream& operator<< (ostream& os, const powershell_Result& a) {

	return os << "powershell detector Result:score:" << a.score << " pid:" << a.pid << " tid:" << a.tid << "content:" << a.content << "command:" << a.command;

}
string powershell_Result::stringouput() {
	return string("powershell detector Result:score:") + to_string(this->score) + " pid:" + to_string(this->pid) + " tid:" +
		to_string(this->tid) + "content:" + this->content + "command:" + this->command;
}
powershell_detector::powershell_detector() {
	runable = 1;
	/*int ret = file_deal::removeDir("powershellData");
	cout << "removedir result: " << ret << endl;
	_mkdir("powershellData");

	cout << "has dir: " << file_deal::hasDir("powershellData") << endl;*/
	Init();
	t_detector = std::thread(&powershell_detector::Thread_run, this);

}
powershell_detector::~powershell_detector() {
	this->stop();
	if (t_detector.joinable()) {
		t_detector.join();
	}
}

int  powershell_detector::Init() {
	// Behaviors which are generally only seen in Malware.
	scoreValues.insert({ "Code Injection", 10.0 });
	scoreValues.insert({ "Key Logging", 3.0 });
	scoreValues.insert({ "Screen Scraping", 2.0 });
	scoreValues.insert({ "AppLocker Bypass", 2.0 });
	scoreValues.insert({ "AMSI Bypass", 2.0 });
	scoreValues.insert({ "Clear Logs", 2.0 });
	scoreValues.insert({ "Coin Miner", 6.0 });
	scoreValues.insert({ "Embedded File", 4.0 });
	scoreValues.insert({ "Abnormal Size", 2.0 });
	scoreValues.insert({ "Ransomware", 10.0 });
	scoreValues.insert({ "DNS C2", 2.0 });
	scoreValues.insert({ "Disabled Protections", 4.0 });
	scoreValues.insert({ "Negative Context", 10.0 });
	scoreValues.insert({ "Malicious Behavior Combo", 6.0 });
	scoreValues.insert({ "Known Malware", 10.0 });

	// Neutral
	// Behaviors which require more context to infer intent.
	scoreValues.insert({ "Downloader", 1.5 });
	scoreValues.insert({ "Starts Process", 1.5 });
	scoreValues.insert({ "Script Execution", 1.5 });
	scoreValues.insert({ "Compression", 1.5 });
	scoreValues.insert({ "Hidden Window", 0.5 });
	scoreValues.insert({ "Custom Web Fields", 1.0 });
	scoreValues.insert({ "Persistence", 1.0 });
	scoreValues.insert({ "Sleeps", 0.5 });
	scoreValues.insert({ "Uninstalls Apps", 0.5 });
	scoreValues.insert({ "Obfuscation", 1.0 });
	scoreValues.insert({ "Crypto", 2.0 });
	scoreValues.insert({ "Enumeration", 0.5 });
	scoreValues.insert({ "Registry", 0.5 });
	scoreValues.insert({ "Sends Data", 1.0 });
	scoreValues.insert({ "Byte Usage", 1.0 });
	scoreValues.insert({ "SysInternals", 1.5 });
	scoreValues.insert({ "One Liner", 2.0 });
	scoreValues.insert({ "Variable Extension", 2.0 });

	// Benign
	// Behaviors which are generally only seen in Benign scripts - subtracts from score.
	scoreValues.insert({ "Script Logging", -1.0 });
	scoreValues.insert({ "License", -2.0 });
	scoreValues.insert({ "Function Body", -2.0 });
	scoreValues.insert({ "Positive Context", -3.0 });

	behaviorCombos.push_back({ "Downloader", "One Liner", "Variable Extension" });
	behaviorCombos.push_back({ "Downloader", "Script Execution", "Crypto", "Enumeration" });
	behaviorCombos.push_back({ "Downloader", "Script Execution", "Persistence", "Enumeration" });
	behaviorCombos.push_back({ "Downloader", "Script Execution", "Starts Process", "Enumeration" });
	behaviorCombos.push_back({ "Script Execution", "One Liner", "Variable Extension" });
	behaviorCombos.push_back({ "Script Execution", "Starts Process", "Downloader", "One Liner" });
	behaviorCombos.push_back({ "Script Execution", "Downloader", "Custom Web Fields" });
	behaviorCombos.push_back({ "Script Execution", "Hidden Window", "Downloader" });
	behaviorCombos.push_back({ "Script Execution", "Crypto", "Obfuscation" });
	behaviorCombos.push_back({ "Hidden Window", "Persistence", "Downloader" });

	vector<vector<string>> behavior;
	behavior.clear();
	behavior.push_back({ "read","write","6","reflection.assembly","entrypoint.invoke", });
	behaviorCol.insert({ "Code Injection", behavior });

	behavior.clear();
	behavior.push_back({ "convert","frombase64string","text.encoding", });
	behavior.push_back({ "io.compression.gzipstream", });
	behavior.push_back({ "compression.compressionmode]::decompress", });
	behavior.push_back({ "io.compression.deflatestream", });
	behavior.push_back({ "io.memorystream", });
	behaviorCol.insert({ "Compression", behavior });

	behavior.clear();
	behavior.push_back({ "getasynckeystate","windows.forms.keys", });
	behavior.push_back({ "lshiftkey","rshiftkey","lcontrolkey","rcontrolkey", });
	behaviorCol.insert({ "Key Logging", behavior });

	behavior.clear();
	behavior.push_back({ "invoke-expression", });
	behavior.push_back({ "invoke-command", });
	behavior.push_back({ "invokecommand", });
	behavior.push_back({ "invoke-script", });
	behavior.push_back({ "invokescript", });
	behavior.push_back({ ".invoke(", });
	behavior.push_back({ "iex(", });
	behavior.push_back({ "wscript.run", });
	behavior.push_back({ "wscript.shell", });
	behavior.push_back({ "activexobject","shellexecute", });
	behavior.push_back({ "$executioncontext|get-member)[6].name", });
	behavior.push_back({ "shellexecute", });
	behaviorCol.insert({ "Script Execution", behavior });

	behavior.clear();
	behavior.push_back({ "uploaddata","post", });
	behaviorCol.insert({ "Sends Data", behavior });

	behavior.clear();
	behavior.push_back({ "environment]::userdomainname", });
	behavior.push_back({ "environment]::username", });
	behavior.push_back({ "$env:username", });
	behavior.push_back({ "environment]::machinename", });
	behavior.push_back({ "environment]::getfolderpath", });
	behavior.push_back({ "io.path]::gettemppath", });
	behavior.push_back({ "$env:windir", });
	behavior.push_back({ "win32_networkadapterconfiguration", });
	behavior.push_back({ "win32_operatingsystem", });
	behavior.push_back({ "win32_computersystem", });
	behavior.push_back({ "principal.windowsidentity]::getcurrent", });
	behavior.push_back({ "principal.windowsbuiltinrole]","administrator", });
	behavior.push_back({ "diagnostics.process]::getcurrentprocess", });
	behavior.push_back({ "psversiontable.psversion", });
	behavior.push_back({ "diagnostics.processstartinfo", });
	behavior.push_back({ "win32_computersystemproduct", });
	behavior.push_back({ "get-process -id", });
	behavior.push_back({ "$env:userprofile", });
	behavior.push_back({ "forms.systeminformation]::virtualscreen", });
	behavior.push_back({ "ipconfig", });
	behavior.push_back({ "win32_processor","addresswidth", });
	behavior.push_back({ "gethostaddresses", });
	behavior.push_back({ "ipaddresstostring", });
	behavior.push_back({ "get-date", });
	behavior.push_back({ "hnetcfg.fwpolicy", });
	behavior.push_back({ "gettokeninformation", });
	behaviorCol.insert({ "Enumeration", behavior });

	behavior.clear();
	behavior.push_back({ ".synopsis",".description",".example", });
	behavior.push_back({ ".version",".author",".credits", });
	behaviorCol.insert({ "Function Body", behavior });

	behavior.clear();
	behavior.push_back({ "start-process", });
	behavior.push_back({ "new-object","io.memorystream","io.streamreader", });
	behavior.push_back({ "diagnostics.process]::start", });
	behavior.push_back({ "redirectstandardinput","useshellexecute", });
	behavior.push_back({ "invoke-item", });
	behavior.push_back({ "wscript.shell","activexobject","run", });
	behavior.push_back({ "start","$env:appdata","exe","http", });
	behaviorCol.insert({ "Starts Process", behavior });

	behavior.clear();
	behavior.push_back({ "procdump","sysinternals", });
	behavior.push_back({ "psexec","sysinternals", });
	behaviorCol.insert({ "SysInternals", behavior });

	behavior.clear();
	behaviorCol.insert({ "One Liner", behavior });

	behavior.clear();
	behavior.push_back({ "regsvr32","/i:http","scrobj.dll", });
	behaviorCol.insert({ "AppLocker Bypass", behavior });

	behavior.clear();
	behavior.push_back({ "new-object","-comobject","schedule.service", });
	behavior.push_back({ "schtasks", });
	behaviorCol.insert({ "Persistence", behavior });

	behavior.clear();
	behavior.push_back({ "createbutton", });
	behavior.push_back({ "tooltip", });
	behavior.push_back({ "deferral", });
	behavior.push_back({ "start-autolab", });
	behavior.push_back({ "failed to download", });
	behavior.push_back({ "forensics snapshot", });
	behavior.push_back({ "choclatey", });
	behavior.push_back({ "chocolatey", });
	behavior.push_back({ "chef-client","chef.msi", });
	behavior.push_back({ "node.js","nodejs.org", });
	behavior.push_back({ "sqlavengers", });
	behavior.push_back({ "spyadblocker.lnk", });
	behavior.push_back({ "readme.md", });
	behavior.push_back({ "remote forensic snapshot", });
	behavior.push_back({ "function write-log", });
	behavior.push_back({ "remote forensic snapshot", });
	behaviorCol.insert({ "Positive Context", behavior });

	behavior.clear();
	behavior.push_back({ "headers.add", });
	behavior.push_back({ "sessionkey","sessiodid", });
	behavior.push_back({ "method","contenttype","useragent","webrequest]::create", });
	behaviorCol.insert({ "Custom Web Fields", behavior });

	behavior.clear();
	behavior.push_back({ "reg_dword","disableantispyware", });
	behavior.push_back({ "reg_dword","disableantivirus", });
	behavior.push_back({ "reg_dword","disablescanonrealtimeenable", });
	behavior.push_back({ "reg_dword","disableblockatfirstseen", });
	behaviorCol.insert({ "Disabled Protections", behavior });

	behavior.clear();
	behavior.push_back({ "downloadfile", });
	behavior.push_back({ "downloadstring", });
	behavior.push_back({ "downloaddata", });
	behavior.push_back({ "webproxy","net.credentialcache", });
	behavior.push_back({ "start-bitstransfer", });
	behavior.push_back({ "bitsadmin", });
	behavior.push_back({ "sockets.tcpclient","getstream", });
	behavior.push_back({ "$env:localappdata", });
	behavior.push_back({ "invoke-webrequest", });
	behavior.push_back({ "net.webrequest", });
	behavior.push_back({ "wget", });
	behavior.push_back({ "send","open","responsebody", });
	behavior.push_back({ "httpwebrequest","getresponse", });
	behavior.push_back({ "internetexplorer.application","navigate", });
	behavior.push_back({ "excel.workbooks.open('http", });
	behavior.push_back({ "notepad","sendkeys","foreach-object","clipboard","http", });
	behavior.push_back({ "excel.workbooks.open","http","releasecomobject","sheets","item","range","row", });
	behaviorCol.insert({ "Downloader", behavior });

	behavior.clear();
	behavior.push_back({ "invoke-shellcode", });
	behavior.push_back({ "meterpreter", });
	behavior.push_back({ "metasploit", });
	behavior.push_back({ "hackertools", });
	behavior.push_back({ "eval(function(p,a,c,k,e,d)", });
	behavior.push_back({ "download_execute", });
	behavior.push_back({ "exetotext", });
	behavior.push_back({ "postexploit", });
	behavior.push_back({ "pebytes32","pebytes64", });
	behavior.push_back({ "invoke-mypass", });
	behavior.push_back({ "powershell","bypass","hidden","webclient","downloadfile","exe","start-process","appdata", });
	behavior.push_back({ "certutil.exe","begin certificate", });
	behavior.push_back({ "invoke-bloodhound", });
	behavior.push_back({ "keylogging", });
	behavior.push_back({ "auto-attack", });
	behavior.push_back({ "pastebin.com/raw/", });
	behavior.push_back({ "shellcode","payload", });
	behavior.push_back({ "$forward_port","$forward_path","$myinvocation.mycommand.path","${global:","-namespace kernel32", });
	behavior.push_back({ "currentdomain.getassemblies()","getprocaddress').invoke","setimplementationflags", });
	behavior.push_back({ "return $win32types","return $win32constants", });
	behavior.push_back({ "get-random -count 16","win32_networkadapterconfiguration","whoami","post", });
	behavior.push_back({ "get-random -minimum","system.buffer]::blockcopy","getresponsestream()","post", });
	behavior.push_back({ "*.vbs","*.lnk","dllopen","dllcall", });
	behavior.push_back({ "start-process  -windowstyle hidden -filepath taskkill.exe -argumentlist", });
	behavior.push_back({ "$xorkey","xorddata", });
	behavior.push_back({ "powershell_payloads", });
	behavior.push_back({ "attackcode", });
	behavior.push_back({ "namespace pingcastle", });
	behavior.push_back({ "br.bat","breach.exe","syspull.ps1", });
	behavior.push_back({ "exploit","vulnerbility","cve-", });
	behavior.push_back({ "privilege escalation", });
	behavior.push_back({ "khr0x40sh", });
	behavior.push_back({ "harmj0y", });
	behavior.push_back({ "mattifestation", });
	behavior.push_back({ "fuzzysec", });
	behaviorCol.insert({ "Negative Context", behavior });

	behavior.clear();
	behaviorCol.insert({ "Variable Extension", behavior });

	behavior.clear();
	behavior.push_back({ "nslookup","querytype=txt","8.8.8.8", });
	behaviorCol.insert({ "DNS C2", behavior });

	behavior.clear();
	behaviorCol.insert({ "Abnormal Size", behavior });

	behavior.clear();
	behavior.push_back({ "hkcu:\\", });
	behavior.push_back({ "hklm:\\", });
	behavior.push_back({ "new-itemproperty","-path","-name","-propertytype","-value", });
	behavior.push_back({ "reg add","reg delete", });
	behaviorCol.insert({ "Registry", behavior });

	behavior.clear();
	behavior.push_back({ "appdomain]::currentdomain.getassemblies()","globalassemblycache", });
	behavior.push_back({ "[byte[]] $buf", });
	behavior.push_back({ "io.file","writeallbytes", });
	behaviorCol.insert({ "Byte Usage", behavior });

	behavior.clear();
	behavior.push_back({ "management.automation.amsiutils","amsiinitfailed", });
	behavior.push_back({ "expect100continue", });
	behaviorCol.insert({ "AMSI Bypass", behavior });

	behavior.clear();
	behavior.push_back({ "mz","this program cannot be run in dos mode", });
	behavior.push_back({ "tvqqaamaaaa", });
	behaviorCol.insert({ "Embedded File", behavior });

	behavior.clear();
	behavior.push_back({ "# copyright","# licensed under the", });
	behavior.push_back({ "copyright (c)", });
	behavior.push_back({ "permission is hereby granted", });
	behavior.push_back({ "the software is provided \"as is\"", });
	behavior.push_back({ "begin signature block", });
	behaviorCol.insert({ "License", behavior });

	behavior.clear();
	behavior.push_back({ "windowstyle","hidden", });
	behavior.push_back({ "createnowindow=$true", });
	behavior.push_back({ "window.resizeto 0, 0", });
	behaviorCol.insert({ "Hidden Window", behavior });

	behavior.clear();
	behavior.push_back({ "security.cryptography.aescryptoserviceprovider","mode","key","iv", });
	behavior.push_back({ "createencryptor().transformfinalblock", });
	behavior.push_back({ "createdecryptor().transformfinalblock", });
	behavior.push_back({ "security.cryptography.cryptostream", });
	behavior.push_back({ "createaesmanagedobject","mode","padding", });
	behavior.push_back({ "convertto-securestring","-key", });
	behaviorCol.insert({ "Crypto", behavior });

	behavior.clear();
	behavior.push_back({ "drawing.bitmap","width","height","screen", });
	behavior.push_back({ "drawing.graphics","fromimage","screen", });
	behavior.push_back({ "copyfromscreen","size", });
	behaviorCol.insert({ "Screen Scraping", behavior });

	behavior.clear();
	behavior.push_back({ "-join","[int]","-as","[char]", });
	behavior.push_back({ "-bxor", });
	behavior.push_back({ "ptrtostringansi", });
	behaviorCol.insert({ "Obfuscation", behavior });

	behavior.clear();
	behavior.push_back({ "miner_path","miner_url", });
	behavior.push_back({ "minername","miner path", });
	behavior.push_back({ "rainbowminer", });
	behavior.push_back({ "get-bestminers", });
	behavior.push_back({ "xmrig.exe", });
	behaviorCol.insert({ "Coin Miner", behavior });

	behavior.clear();
	behavior.push_back({ "start-sleep", });
	behavior.push_back({ "sleep -s", });
	behaviorCol.insert({ "Sleeps", behavior });

	behavior.clear();
	behavior.push_back({ "readme-encrypted-files.html", });
	behavior.push_back({ "!!! your personal identification id:", });
	behavior.push_back({ "decrypt_instructions.html", });
	behavior.push_back({ "binarywriter","cryptography","readwrite","add-content","html", });
	behaviorCol.insert({ "Ransomware", behavior });

	behavior.clear();
	behavior.push_back({ "logmsg","logerr", });
	behavior.push_back({ "write-debug", });
	behavior.push_back({ "write-log", });
	behavior.push_back({ "write-host", });
	behavior.push_back({ "exception.message", });
	behavior.push_back({ "write-output", });
	behavior.push_back({ "write-warning", });
	behaviorCol.insert({ "Script Logging", behavior });

	behavior.clear();
	behavior.push_back({ "foreach","uninstallstring", });
	behaviorCol.insert({ "Uninstalls Apps", behavior });

	behavior.clear();
	behavior.push_back({ "globalsession.clearlog", });
	behavior.push_back({ "clear-eventlog","windows powershell", });
	behavior.push_back({ "clear-eventlog","applicatipn", });
	behavior.push_back({ "clear-eventlog","system", });
	behavior.push_back({ "clearmytracksbyprocess", });
	behaviorCol.insert({ "Clear Logs", behavior });



	//map<string, list<string>> behaviorCol;
	////vector<vector<string>> behaviorCombos;

	vector<string> tc1 = { "VirtualAlloc", "NtAllocateVirtualMemory",
		"ZwAllocateVirtualMemory", "HeapAlloc", "calloc" };
	// Move to memory
	vector<string>  tc2 = { "RtlMoveMemory", "WriteProcessMemory", "memset", "Runtime.InteropServices.Marshal]::Copy",
		"Runtime.InteropServices.Marshal]::WriteByte" };
	// Execute in memory
	vector<string>  tc3 = { "CallWindowProcA", "CallWindowProcW", "DialogBoxIndirectParamA", "DialogBoxIndirectParamW",
		"EnumCalendarInfoA", "EnumCalendarInfoW", "EnumDateFormatsA", "EnumDateFormatsW", "EnumDesktopWindows",
		"EnumDesktopsA", "EnumDesktopsW", "EnumLanguageGroupLocalesA", "EnumLanguageGroupLocalesW", "EnumPropsExA",
		"EnumPropsExW", "EnumPwrSchemes", "EnumResourceTypesA", "EnumResourceTypesW", "EnumResourceTypesExA",
		"EnumResourceTypesExW", "EnumSystemCodePagesA", "EnumSystemCodePagesW", "EnumSystemLanguageGroupsA",
		"EnumSystemLanguageGroupsW", "EnumSystemLocalesA", "EnumSystemLocalesW", "EnumThreadWindows",
		"EnumTimeFormatsA", "EnumTimeFormatsW", "EnumUILanguagesA", "EnumUILanguagesW", "EnumWindowStationsA",
		"EnumWindowStationsW", "EnumWindows", "EnumerateLoadedModules", "EnumerateLoadedModulesEx",
		"EnumerateLoadedModulesExW", "GrayStringA", "GrayStringW", "NotifyIpInterfaceChange",
		"NotifyTeredoPortChange", "NotifyUnicastIpAddressChange", "SHCreateThread", "SHCreateThreadWithHandle",
		"SendMessageCallbackA", "SendMessageCallbackW", "SetWinEventHook", "SetWindowsHookExA", "SetWindowsHookExW",
		"CreateThread", "Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer", "DeviceIoControl" };
	c1.swap(tc1);
	c2.swap(tc2);
	c3.swap(tc3);
	return 0;
}


void powershell_detector::AddScript(string& script, int pid, int tid) {
	if (script.length() < 8) {
		return;
	}
	//string filename = string("powershellData/") + get_random_filename(18);
	//int rusult_file = file_deal::writeTofile(filename, temp);
	powershell_Input input = powershell_Input(pid, tid, script);
	{
		lock_guard<mutex> lock(m);
		powershell_fileList.push(input);
	}

}
string powershell_detector::vectorToString(vector<string>& behaviorTag) {
	string ret = "[";
	for (string& behavior : behaviorTag)
	{
		ret.append(behavior);
		ret.append(",");
	}
	ret.resize(ret.length() - 1);
	ret.append("]");
	return ret;

}
powershell_Result powershell_detector::Check_code(string& code) {
	powershell_Result ret;
	vector<string> behaviorTags = profileBehaviors(code, code);
	double retscore = 0.0;
	string verdict;
	vector<string> behaviorData;

	for (string& behavior : behaviorTags)
	{

		string kehaviorkey = behavior;
		if (behavior.find("Known Malware:") != string::npos) {
			string  temp = behavior.substr(14, behavior.length() - 14);
			behaviorData.push_back("Known Malware:" + temp + " Known Malware");
			kehaviorkey = "Known Malware";
		}
		else if (behavior.find("Obfuscation:") != string::npos) {
			string  temp = behavior.substr(12, behavior.length() - 12);
			behaviorData.push_back("Obfuscation:" + temp + " Obfuscation");
			kehaviorkey = "Obfuscation";
		}
		else
		{
			string _score = to_string(scoreValues[kehaviorkey]);
			behaviorData.push_back(kehaviorkey + "-" + _score.substr(0, _score.size() - 5));
		}
		retscore += scoreValues[kehaviorkey];
	}
	if (retscore < 0.0)
	{
		retscore = 0.0;

	}
	ret.score = retscore;
	ret.content = vectorToString(behaviorData);
	ret.command = code;
	//DetectorResult result = new DetectorResult(retscore, verdict, behaviorData);
	//return result;

	return ret;

}

static int countChar(string data, char value)
{
	int ret = 0;
	for (char key : data)
	{
		if (key == value)
		{
			ret++;
		}
	}
	return ret;
}
static int get_regsize(regex regstr, string content) {
	int ret = 0;
	std::sregex_iterator iter(content.begin(), content.end(), regstr);
	std::sregex_iterator end;
	while (iter != end)
	{
		ret++;
		//for (unsigned i = 0; i < iter->size(); ++i)
		//{
		//    std::cout << "the " << i + 1 << "th match" << ": " << (*iter)[i] << std::endl;
		//}
		++iter;
	}
	return ret;
}
vector<string> powershell_detector::profileBehaviors(string& originalData, string& alternativeDataold) {
	vector<string> behaviorTags;
	//transform(alternativeData.begin(), alternativeData.end(), alternativeData.begin(), ::tolower);
	string alternativeData = this->strTolower(alternativeDataold);


	string obfType = "";
	//map<string, vector<vector<string>>> behaviorCol;
	//vector<vector<string>> behaviorCombos;
	for (auto& behavior : behaviorCol) {
		string behaviorkey = behavior.first;
		vector < vector<string>> behavior_value = behavior.second;
		for (vector<string>& commands : behavior_value) {
			bool bhflag = true;
			for (string value : commands) {
				//有一个关键词没有找到就说明不是这种行为
				if (bhflag && alternativeData.find(value) == string::npos)
				{
					bhflag = false;
					break;
				}
			}
			if (bhflag)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}
				//TODO add debug output
				printf("debug:add %s for reason:", behaviorkey.c_str());
				for (string value : commands) {
					printf("%s\n", value.c_str());
				}
			}
		}
		if (behaviorkey == "Obfuscation")
		{
			// Character Frequency Analysis (Original Script only).
			if (countChar(originalData, 'w') >= 500 || countChar(originalData, '4') >= 250
				|| countChar(originalData, '_') >= 250 || countChar(originalData, 'D') >= 250
				|| countChar(originalData, 'C') >= 200 || countChar(originalData, 'K') >= 200
				|| countChar(originalData, ':') >= 100 || countChar(originalData, ';') >= 100
				|| countChar(originalData, ',') >= 100 || (countChar(originalData, '(') >= 50 && countChar(originalData, ')') >= 50)
				|| (countChar(originalData, '[') >= 50 && countChar(originalData, ']') >= 50)
				|| (countChar(originalData, '{') >= 50 && countChar(originalData, '}') >= 50)
				&& get_regsize(regex("(\\n|\\r\\n)"), originalData) <= 50)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
					obfType = "Char Frequency";
				}
			}
			// Check Symbol Usage.
			if (get_regsize(regex("\\\_+/"), originalData) >= 50)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
					obfType = "High Symbol";
				}
			}
			// Check unique high variable declaration (includes JavaScript).
			//未做去重
			if (get_regsize(regex("var [^ ]+ ?="), alternativeData) >= 40
				|| get_regsize(regex("\\$\\w+?(?:\\s*)="), alternativeData) >= 40)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
					obfType = "High Variable";
				}
			}
		}

		if (behaviorkey == "Byte Usage")
		{

			if (get_regsize(regex("0x[A-F0-9a-f][A-F0-9a-f],"), alternativeData) >= 100)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}

			}
		}

		if (behaviorkey == "One Liner")
		{

			if (get_regsize(regex("(\\n|\\r\\n)"), originalData) == 0)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}

			}
		}


		if (behaviorkey == "Abnormal Size")
		{

			if (originalData.length() >= 1000000 || get_regsize(regex("(\\n|\\r\\n)"), originalData) >= 5000)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}

			}
		}

		if (behaviorkey == "Variable Extension")
		{

			int shortVars = get_regsize(regex("(Set-Item Variable|SI Variable|Get-ChildItem Variable|LS Variable|Get-Item Variable|ChildItem Variable|Set-Variable|Get-Variable|DIR Variable|GetCommandName|(\.Value\|Member|\.Value\.Name))", regex::icase), originalData);
			int asterikVars = get_regsize(regex("[A-Za-z0-9]\*[A-Za-z0-9]", regex::icase), originalData);
			if (shortVars + asterikVars >= 10)
			{
				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}

			}
		}



		if (behaviorkey == "Code Injection")
		{
			bool cf1 = false;
			bool cf2 = false;
			bool cf33 = false;

			for (string& c1key : c1)
			{
				if (cf1 || alternativeData.find(this->strTolower(c1key)) != string::npos)
				{
					cf1 = true;
					break;
				}
			}
			for (string& c2key : c2)
			{
				if (cf2 || alternativeData.find(this->strTolower(c2key)) != string::npos)
				{
					cf2 = true;
					break;
				}
			}

			for (string& c3key : c3)
			{
				//string _temp = ;
				if (cf33 || alternativeData.find(this->strTolower(c3key)) != string::npos)
				{
					cf33 = true;
					break;
				}
			}

			if (cf33 && cf1 && cf2)
			{

				if (std::find(behaviorTags.begin(), behaviorTags.end(), behaviorkey) == behaviorTags.end()) {
					behaviorTags.push_back(behaviorkey);
				}
			}
		}
	}


	// Tries to catch download cradle PowerShell scripts where the obfuscation isn't identified.
	// Examples are heavy variable command usage for chaining/parsing.
	if (behaviorTags.size() == 2 && std::find(behaviorTags.begin(), behaviorTags.end(), "One Liner") != behaviorTags.end()
		&& (alternativeData.find("http://") != string::npos || alternativeData.find("https://") != string::npos)
		&& (std::find(behaviorTags.begin(), behaviorTags.end(), "Starts Process") != behaviorTags.end()
			|| std::find(behaviorTags.begin(), behaviorTags.end(), "Script Execution") != behaviorTags.end()
			))
	{
		behaviorTags.push_back("Downloader");
		behaviorTags.push_back("Obfuscation");
		obfType = "Hidden Commands";
	}


	if (obfType != "")
	{
		vector<string>::iterator iter = std::find(behaviorTags.begin(), behaviorTags.end(), string("Obfuscation"));
		if (iter != behaviorTags.end()) {
			behaviorTags[std::distance(std::begin(behaviorTags), iter)] = string("Obfuscation:") + obfType;
		}
	}

	for (vector<string>& comborow : behaviorCombos) {
		int foundflag = 1;
		if (comborow.size() > behaviorTags.size())
		{
			foundflag = 0;
		}
		else
		{

			for (string behave : comborow)
			{
				if (foundflag == 1 && std::find(behaviorTags.begin(), behaviorTags.end(), behave) == behaviorTags.end())
				{
					foundflag = 0;
				}
			}

		}
		string _temp = "Malicious Behavior Combo";
		if (foundflag == 1 && std::find(behaviorTags.begin(), behaviorTags.end(), _temp) == behaviorTags.end())
		{
			behaviorTags.push_back(_temp);
		}
	}


	return behaviorTags;
}
int powershell_detector::Thread_run() {
	while (this->runable)
	{
		if (this->powershell_fileList.size() > 0) {
			powershell_Input fileinput;
			{
				lock_guard<mutex> lock(m);
				fileinput = powershell_fileList.front();
				powershell_fileList.pop();
			}
			//TODO deal file
			powershell_Result powershell_ret = Check_code(fileinput.scriptcontent);
			powershell_ret.pid = fileinput.pid;
			powershell_ret.tid = fileinput.tid;
			cout << powershell_ret << endl;

			//powershell_Result powershell_ret = powershell_Result::dealResult(ret, fileinput.pid, fileinput.tid);

			EventRecord* event_record = EventRecordManager::GetInstance().ParsePowershellCheckEvent(powershell_ret);
			if (event_record)
			{
				LoggerRecord::WriteLog(L"testFeature detect feature: " + ToolFunctions::StringToWString(powershell_ret.stringouput()), LogLevel::INFO);
				InitCollector::GetCollector()->PushSendRecord(event_record);
			}
			// 考虑解析完后删除文件 也可以不删除
			//file_deal::removeFile(fileinput.filename);
		}
		else {
			Sleep(500);
		}
	}

	return 0;
}
string powershell_detector::get_random_filename(int len) {
	string ret;
	ret.resize(len + 1);
	srand(time(NULL));
	int i;
	for (i = 0; i < len; ++i)
	{
		switch ((rand() % 3))
		{
		case 1:
			ret[i] = 'A' + rand() % 26;
			break;
		case 2:
			ret[i] = 'a' + rand() % 26;
			break;
		default:
			ret[i] = '0' + rand() % 10;
			break;
		}
	}
	//ret[len] = '\0';
	return ret;
}
string powershell_detector::strTolower(string& temp) {
	string lower = temp;

	transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
	return lower;
}
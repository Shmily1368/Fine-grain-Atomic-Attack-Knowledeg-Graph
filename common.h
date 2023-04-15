/********************************************************************
	Created:		2019-01-02
	Author:			chips;
	Version:		1.0.0(version);
	Description:	define constant quantity;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/01/02 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/
#pragma once

#include <vector>
using namespace std;
// add by zxw on 20191225 output command line
//#define OUTPUT_COMMAND_LINE 1 

#define EMPTY_STRING ""

const String CONFIG_FILE_NAME = "user_configuration.ini";
const char OFFLINE_COLLECT_MODE_STR = 'n';
const char OFFLINE_PARSE_MODE_STR = 'p';
const char ONLINE_PARSE_MODE_STR = 'f';
const String FORMAT_SECRET_KEY = "jsdf4jiwe^jpjpwaor448&(fjaljfeaf";

//ms time
const int MS_ONE_HOUR = 3600000;  //ms, clear macro map 
const int MS_TEN_MILLSECOND = 10;
const int MS_ONE_SECOND = 1000;
const int MS_TEN_SECOND = 10000;

//ns time
const long long NS_TEN_SECOND = 10000000000;
const long long NS_SIX_SECOND =  6000000000;

// max phf length 200KB
const int MAX_PHF_SIZE = 200*1024;
// max mem set size 120MB
const int MAX_MEM_SET_SIZE = 120;

// ADD BY ZXW ON 20191029 特权进程名
constexpr auto PRIVILEGE_PROCESS = "clientscheduler.exe";
// ADD BY ZXW ON 20191122 explorer进程名
constexpr auto EXPLORER_PROCESS = "explorer.exe";
// ADD BY ZXW ON 20200724 autorunsc64.exe
constexpr auto AUTORUNSC64_PROCESS = "autorunsc64.exe";

#define EPOCHFILETIME   (116444736000000000UL)

#define ETWFileIo			0x90cbdc39
#define ETWThread			0x3d6fa8d1
#define ETWProcess			0x3d6fa8d0
#define ETWImage			0x2cb15d1d
#define ETWRegistry			0xae53722e
#define ETWALPC				0x45d8cccd
#define ETWDiskIo			0x3d6fa8d4
#define ETWPerfInfo			0xce1dbfb4
#define ETWTcpIp			0x9a280ac0
#define ETWUdpIp			0xbf3a50c5
#define ETWSysConfig		0x01853a65
#define ETWStackWalk		0xdef2fe46
#define ETWVisibleWindow	0x90cbdc00
#define ETWMouse			0x90cbdc01
#define ETWKeyBoard			0x90cbdc02
#define ETWAddtionData		0x90cbdc03
#define ETWDNSData			0x1c95126e
#define ETWPowerShell		0xa0c1853b
#define EVTSecurity			0x54849625
#define EVTSysmon			0x5770385F

//marco detect 
const vector<wstring> office_process = {
	L"word.exe",
	L"excel.exe",
	L"powerpoint.exe",
	L"powerprnt.exe",
	L"winword.exe",
	L"wps.exe"
};

const vector<wstring> filetypes = {
		L"docm",
		L"xlsm",
		L"pptm",
		L"doc",
		L"docx",
		L"xls",
		L"xlsx",
		L"ppt",
		L"pptx",
};
// add by zxw on 20210111

const set<String> g_parameter_string =
{
    "FileName",
    "KeyName",
    "OpenPath",
    "ProcessName",
    "ImageFileName",
    "CommandLine",
    "SystemCall",
    "UserSID",
    "NewFileName",
    "CheckID",
    "MacroContent",
    "QueryDomainName",
    "ExtraInfo",
    "RootPath",
    "VolumeName",
    "FileSystem",
    "HostUrl",
    "ReferrerUrl",
    "EventName",
    "ParentProcessName",
    "MD5",
    "SignatureStatus",
    "SignatureType",
    "PUUID"
};


//pipe proc;
#define PIPE_PROC_HEALTH_CHECK				"HEALTH_CHECK"				//异常检查;
#define PIPE_PROC_INIT_TRUST_LIST			"INIT_TRUST_LIST"			//初始化超级白名单;
#define PIPE_PROC_ADD_TRUST_LIST			"ADD_TRUST_LIST"			//增加超级白名单;
#define PIPE_PROC_REMOVE_TRUST_LIST			"REMOVE_TRUST_LIST"			//移除超级白名单;
#define PIPE_PROC_CHANGE_TRUST_LIST			"CHANGE_TRUST_LIST"			//修改超级白名单;
#define PIPE_PROC_CHANGE_GEAR				"CHANGE_GEAR"				//更换挡位;
#define PIPE_PROC_PARSE_AUTORUN_INFO		"PARSE_AUTORUN_INFO"		//获取自启动项;
// add by zxw on 20191030 update local ip
#define PIPE_PROC_UPDATE_CLIENT_IP			"UPDATE_CLIENT_IP"			//更新本机IP;
// add by zxw on 20191206 add suffix for ransom
#define PIPE_PROC_RANSOM_SUFFIX_WHITE_LIST	"RANSOM_SUFFIX_WHITE_LIST"	//勒索后缀白名单;
// add by zxw on 20201019
#define PIPE_PROC_UPDATE_CUSTOM_RULE		"UPDATE_CUSTOM_RULE"		//更新匹配规则;
#define PIPE_PROC_RULE_MATCH_SWITCH		    "Rule_Match_Switch"		    //匹配规则开关切换;
#define PIPE_PROC_CERTIFICATE_WHITE_LIST    "CERTIFICATE_WHITE_LIST"    //企业证书白名单


//security audit;
#define SECURITY_LOG_CLEARED				1102						//清除windows 安全日志;
#define SECURITY_ACCOUNT_LOGGED_ON			4624						//帐户已成功登录;
#define SECURITY_ACCOUNT_LOGGED_OFF			4634						//帐户已注销;
#define SECURITY_ACCOUNT_CREATED			4720						//新用户创建;
#define SECURITY_ACCOUNT_CHANGE_PASSWORD	4723						//用户更改登录密码;
#define SECURITY_ACCOUNT_CHANGED			4738						//用户帐户已更改;
#define SECURITY_RESET_ACCOUNT_PASSWORD		4724						//尝试reset其他账户的登录密码;
#define SECURITY_ACCOUNT_LOGGED_FAILED		4625						//用户尝试登录失败;
#define SECURITY_ACCOUNT_DELETED			4726						//用户被删除;
#define SECURITY_ACCOUNT_LOCKED				4740						//用户锁定;
#define SECURITY_DSRM_CHANGE_PASSWORD		4794						//DSRM密码更改;
#define SECURITY_SERVICE_INSTALLED			4697						//新服务在系统上运行;
#define SECURITY_REGISTRY_MODIFIED 			4657						//注册表中的键对应的值被修改;
#define SECURITY_SCHEDULED_CREATED			4698						//计划任务被创建;
#define SECURITY_FIREWALL_STOPPED			5025						//Windows防火墙被关闭;

//sysmon;
#define SYSMON_Drive_Loaded			        6						    // 驱动加载;
#define SYSMON_Process_Access				10						    // 进程注入;

// add by zxw on 20210511
#define CODEMSG( _number ) CTL_CODE( FILE_DEVICE_UNKNOWN,_number , METHOD_BUFFERED,\
	FILE_READ_DATA | FILE_WRITE_DATA )       
#define GET_PROCESS_SKU 2055

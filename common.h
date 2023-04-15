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

// ADD BY ZXW ON 20191029 ��Ȩ������
constexpr auto PRIVILEGE_PROCESS = "clientscheduler.exe";
// ADD BY ZXW ON 20191122 explorer������
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
#define PIPE_PROC_HEALTH_CHECK				"HEALTH_CHECK"				//�쳣���;
#define PIPE_PROC_INIT_TRUST_LIST			"INIT_TRUST_LIST"			//��ʼ������������;
#define PIPE_PROC_ADD_TRUST_LIST			"ADD_TRUST_LIST"			//���ӳ���������;
#define PIPE_PROC_REMOVE_TRUST_LIST			"REMOVE_TRUST_LIST"			//�Ƴ�����������;
#define PIPE_PROC_CHANGE_TRUST_LIST			"CHANGE_TRUST_LIST"			//�޸ĳ���������;
#define PIPE_PROC_CHANGE_GEAR				"CHANGE_GEAR"				//������λ;
#define PIPE_PROC_PARSE_AUTORUN_INFO		"PARSE_AUTORUN_INFO"		//��ȡ��������;
// add by zxw on 20191030 update local ip
#define PIPE_PROC_UPDATE_CLIENT_IP			"UPDATE_CLIENT_IP"			//���±���IP;
// add by zxw on 20191206 add suffix for ransom
#define PIPE_PROC_RANSOM_SUFFIX_WHITE_LIST	"RANSOM_SUFFIX_WHITE_LIST"	//������׺������;
// add by zxw on 20201019
#define PIPE_PROC_UPDATE_CUSTOM_RULE		"UPDATE_CUSTOM_RULE"		//����ƥ�����;
#define PIPE_PROC_RULE_MATCH_SWITCH		    "Rule_Match_Switch"		    //ƥ����򿪹��л�;
#define PIPE_PROC_CERTIFICATE_WHITE_LIST    "CERTIFICATE_WHITE_LIST"    //��ҵ֤�������


//security audit;
#define SECURITY_LOG_CLEARED				1102						//���windows ��ȫ��־;
#define SECURITY_ACCOUNT_LOGGED_ON			4624						//�ʻ��ѳɹ���¼;
#define SECURITY_ACCOUNT_LOGGED_OFF			4634						//�ʻ���ע��;
#define SECURITY_ACCOUNT_CREATED			4720						//���û�����;
#define SECURITY_ACCOUNT_CHANGE_PASSWORD	4723						//�û����ĵ�¼����;
#define SECURITY_ACCOUNT_CHANGED			4738						//�û��ʻ��Ѹ���;
#define SECURITY_RESET_ACCOUNT_PASSWORD		4724						//����reset�����˻��ĵ�¼����;
#define SECURITY_ACCOUNT_LOGGED_FAILED		4625						//�û����Ե�¼ʧ��;
#define SECURITY_ACCOUNT_DELETED			4726						//�û���ɾ��;
#define SECURITY_ACCOUNT_LOCKED				4740						//�û�����;
#define SECURITY_DSRM_CHANGE_PASSWORD		4794						//DSRM�������;
#define SECURITY_SERVICE_INSTALLED			4697						//�·�����ϵͳ������;
#define SECURITY_REGISTRY_MODIFIED 			4657						//ע����еļ���Ӧ��ֵ���޸�;
#define SECURITY_SCHEDULED_CREATED			4698						//�ƻ����񱻴���;
#define SECURITY_FIREWALL_STOPPED			5025						//Windows����ǽ���ر�;

//sysmon;
#define SYSMON_Drive_Loaded			        6						    // ��������;
#define SYSMON_Process_Access				10						    // ����ע��;

// add by zxw on 20210511
#define CODEMSG( _number ) CTL_CODE( FILE_DEVICE_UNKNOWN,_number , METHOD_BUFFERED,\
	FILE_READ_DATA | FILE_WRITE_DATA )       
#define GET_PROCESS_SKU 2055

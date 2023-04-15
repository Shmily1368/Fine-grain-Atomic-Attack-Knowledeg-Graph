/*****************************************************************************                                   *
*  @file     global_enum_def.h                                                     *
*  @brief    ȫ�ֵĺ궨��														 *
*                                                                            *
*  @author   jiehao.meng                                                     *
*  @version  1.0.0.0(�汾��)                                                  *
*  @date     2018/12/28		                                                 *
*                                                                            *
*----------------------------------------------------------------------------*
*  Remark         :			                                                 *
*----------------------------------------------------------------------------*
*  Change History :                                                          *
*  <Date>     | <Version> | <Author>       | <Description>                   *
*----------------------------------------------------------------------------*
*  2018/12/28 | 1.0.0.0   | jiehao.meng    | Create file                     *
*----------------------------------------------------------------------------*
*  2018/01/03 | 1.0.0.1   | chips    | add EM_InitCollectorMode,EM_ThreadTaskMode *
*----------------------------------------------------------------------------*
*                                                                            *
*****************************************************************************/
#pragma once

/**
 * @brief EventRecordThread event
 */
enum EM_ThreadEventOPC
{
	ThreadStart = 1,		/*!< thread start */
	ThreadEnd = 2,			/*!< thread dc start (which means the thread is already exsited when ETW session started)In these two cases, the relationships between threads and processes should be updated in(added into) thread_id2process_id_map_ */
	ThreadDCStart = 3,		/*!< thread end In this case, the relationships should be removed from the map */
	ThreadContextSwitch = 36/*!< context switch	This event is used to update the processor status: which thread is now using the processor. This information is used to correlate thread id to some other events. */
};

/**
 * @brief ETW Process events
 */
enum EM_ProcessEventOPC
{
	ProcessStart = 1,		/*!< process start */
	ProcessEnd = 2,			/*!< process dc start (which means the process is already exsited when ETW session started)	In these two cases, the relationships between process ids and process names should be update in process_id2process_name_map_ */
	ProcessDCStart = 3,		/*!< process end */
	ProcessDCEnd = 4,		/* process dc end */
};

/**
 * @brief ETW Registry events
 */
enum EM_RegistryEventOPC
{
	RegistryCreate = 10,					/*!< RegistryCreate	 Key handle means it parent path, add keyname means what is actually create. status means whether open success.0 represent success.In this event, we can not get key handle of new open key. */
	RegistryOpen = 11,						/*!< RegistryOpen	 Key handle means it parent path, add keyname means what is actually open. status means whether open success.0 represent success. In this event, we can not get key handle of new open key. */
	RegistryQuery = 13,						/*!< RegistryQuery	Key name always been None, but is contains key handle of new open key. Often follow RegistryOpen event , we can use this event to upodate key_handle2key_name_map. */
	RegistryRegistrySetValuee = 14,	/*!< RegistrySetValue same as RegistryOpen */
	RegistryQueryValue = 16,				/*!< RegistryQueryValue	Have key name, same as RegistryOpen, key handle point parent path.Often follow RegistryOpen event , we can use this event to upodate key_handle2key_name_map.*/
	RegistrySetInformation = 20,			/*!< RegSetInformation This events are often emited by some embedded system operations. We keep this event alone according to Liheng's research.Keyname also always been empty.*/
	RegistryKCBCreate = 22,					/*!< RegistryKCBCreate  Update keyhandle-- Keyname map*/
	RegistryKCBDelete = 23,					/*!< Do not update it.Key Control Block,for faster search propose.Key Name is absolute path and key handle corresponding it.*/
    RegistryDelete = 12,
    RegistryDeleteValue = 15,
    RegistryClose = 27						/*!< RegistryClose yet I have not meet this registry, may need further change */
};

/**
*  @brief ETW Registry events
*  When parsing other fileio events, we do it like this:
*  1.get filename from file_key2file_name_map by fileKey
*  2.or get filename from file_object2file_name_map by fileObject
*  3.or the file name is unkown.
*
*  According to Liheng's test, the filenames gotten from these two maps
*  are the same most of the time. Sometimes there is only one of fileKey
*  and fileObject.
*/
enum EM_FileioEventOPC
{
	FileioNameEvent = 0,			/*!< fileio name, name event */
	FileioFileCreateEvent = 32,			/*!< fileio name, create event In these two cases, update file_key2file_name_map*/
	FileioCreateEvent = 64,		/*!< ileio file create event In this case, file_object2file_name_map */
	FileIoCleanup = 65,				/*!< fileIocleanup add by zxw 20191111*/
	FileioClose = 66,				/*!< fileioclose */
	FileIoRead = 67,				/*!< FileIoRead */
	FileIoWirte = 68,				/*!< fileIo wirte */
	FileIoDelete = 70,				/*!< fileIo delete */ //whԤ��;
	FileioRenameEvent = 71,			/*!< fileio rename event */
	FileioDirEnumerationEvent = 72,	/*!< Directory enumeration event Update both map, according to Liheng's research.only filename,not file path,although it seems can be completed,when too many unkown file, we can think about to fix it.Remaining work,and yet remove it from format.txt */
	FileIoRenamePath = 80			/*!< FileIoRenamePath only have win10 */
};

/**
* @brief ETW Alpc events
* Find which process sent this message by looking up in the list.
* generate an extra 33 event when parsing it, so the sender would
* know who get this message.
* Return if there is no corresponding record in the list.
*/
enum EM_AlpcEventOPC
{
	AlpcSendEvent = 33,				/*!< alpc send event */
	ApcReceiveEvent = 34			/*!< alpc receive event */
};

/**
 * @brief ETW Registry events
 */
enum EM_ImageEventOPC
{
	ImageDCStart	= 3,
	ImageLoad		= 10,
	ImageUnload		= 2,
};

/**
 * @brief ETW TcpIp events
 */
enum EM_TcpIpEventOPC
{
	TcpIpSendIPV4	= 10,
	TcpIpRecvIPV4	= 11,
};

/**
 * @brief ETW UdpIp events
 */
enum EM_UdpIpEventOPC
{
	UdpIpSendIPV4 = 10,
	UdpIpRecvIPV4 = 11,
};

/**
 * @brief ETW AdditionData events
 */
enum EM_AdditionDataEventOPC
{
	PowerShellCheck		= 11,
	FileMacroCheck		= 12,
	IpconfigInfo		= 13,
	DeviceRemoveAble	= 14,
	HealthCheck			= 15,
	InitSignal			= 16,
	AutorunInfo			= 17,
	RansomCheck			= 18,
    ZoneIdentifier      = 19,
    RuleIdentifier      = 20,
    HashInfo            = 21,
	PowershellResult	= 22,
};

enum EM_DNSDataEventOPC
{
	DNSQueryRequest		= 3006,
	DNSQueryResult		= 3020,
};

enum EM_PowerShellEventOPC
{
	PowerShellScript	= 4104,
};

enum EM_PerfInfoEventOPC
{
	SyscallEnter		= 51,
};

/**
 * @brief initCollector mode type
 */
enum EM_InitCollectorMode
{
	ONLINE_PARSE_MODE = 0,
	OFFLINE_PARSE_MODE = 1,
	OFFLINE_COLLECT_MODE = 2
};

enum EM_ThreadTaskMode
{
	GET_VISIBLE_WINDOW_TASK_MODE	= 0,
	HOOK_KEY_MOUSE_TASK_MODE		= 1,
	CERTIFICATE_IMAGE_TASK_MODE		= 2,
	GET_THREAD_END_EVENT_TASK_MODE	= 3,
	TIMER_TASK_MODE					= 4,
	OUTPUT_RECORD_TASK_MODE			= 5,
	GET_IPCONFIG_TASK_MODE			= 6,
	MONITOR_TASK_MODE				= 7,
	PIPE_READ_TASK_MODE				= 8,
	PARSE_EVENT_TASK_MODE			= 9,
    GET_DEVICE_ARRIVAL_TASK_MODE    = 10,
    RULE_MATCHER_TASK_MODE          = 11,
    GEE_HASH_TASK_MODE              = 12,
};

enum EM_OsVersion
{
	UNKNOWN_OS		= 0,
	WIN7			= 1,
	WIN10			= 2,
	WS2012_R2		= 3
};

enum EM_MarcoDetectResult
{
	NORMAL = 1,
	isMalicious = 20,
};

enum EM_CertificateResult
{
	CERTIFICATE_RESULT__MALICIOUS		= 0,
	CERTIFICATE_RESULT__NORMAL			= 1,
	CERTIFICATE_RESULT__UNDETERMINED	= 2,
    CERTIFICATE_RESULT__EXPIRED         = 3,
    CERTIFICATE_RESULT__NOTTRUSTED      = 4,
    CERTIFICATE_RESULT__DOCTORED        = 5,
    CERTIFICATE_RESULT_REVOKED          = 6,
};

enum EM_MonitorObjectInfoType
{
	CONSTRUCTION_TYPE = 0,
	DESTRUCTION_TYPE = 1,
};

enum PipeErrCode
{
	PIPE_ERR_SUCCESS				= 0,				//SUCCESS;
	PIPE_ERR_PROC_NOT_FOUND			= -1,				//�Ҳ���Э��;
};

enum CollectorGear
{
	COLLECTOR_GEAR__1				= 1,				//all function;
	COLLECTOR_GEAR__2				= 2,				//disable certificate process;
	COLLECTOR_GEAR__3				= 3,				//disable callstack/syscall & visible window;
	COLLECTOR_GEAR__4				= 4,				//disable file io;
	COLLECTOR_GEAR__5				= 5,				//;
};

enum LocalDetectorMode
{
	LOCAL_DETECTOR_MODE__CALLSTACK	= 1,
	LOCAL_DETECTOR_MODE__SYSCALL	= 2,
};
// add by zxw on 20201026
enum EM_SysmonEventOPC {
    Drive_Loaded = 6,
    Process_Access = 10,
};
#include "stdafx.h"
#include "thread_task_get_devicearrival.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "filter.h"
#include "init_collector_online_parse.h"

#include <Windows.h>
#include <windef.h>
#include <Dbt.h>

GetDeviceArrivalThreadTask::GetDeviceArrivalThreadTask()
	: BaseThreadTask(GET_DEVICE_ARRIVAL_TASK_MODE)
{
	
}

GetDeviceArrivalThreadTask::~GetDeviceArrivalThreadTask()
{

}

// ��ȡ���ƶ��豸��Ϣ
void GetVolumeSerial(char dir)
{
    char szVolumeNameBuf[MAX_PATH] = { 0 };
    DWORD dwVolumeSerialNum;
    DWORD dwMaxComponentLength;
    DWORD dwSysFlags;
    char szFileSystemBuf[MAX_PATH] = { 0 };
    DWORD dwFileSystemBuf = MAX_PATH;
    char szRootPath[MAX_PATH] = { 0 };
    sprintf_s(szRootPath, "%c:\\", dir);

    BOOL bGet = GetVolumeInformationA(szRootPath,
        szVolumeNameBuf,
        MAX_PATH,
        &dwVolumeSerialNum,
        &dwMaxComponentLength,
        &dwSysFlags,
        szFileSystemBuf,
        MAX_PATH);
    if (bGet)
    {
        LoggerRecord::WriteLog(L"GetVolumeSerial dwVolumeSerialNum " + to_wstring(dwVolumeSerialNum), LogLevel::DEBUG);
        // �����¼�
        EventRecord* event_record = EventRecordManager::GetInstance().ParseRemoveableDeviceEvent(
            dwVolumeSerialNum,
            ToolFunctions::StringToWString(szRootPath),
            ToolFunctions::StringToWString(ToolFunctions::StringToUTF8(szVolumeNameBuf)),
            ToolFunctions::StringToWString(szFileSystemBuf));
        if (event_record && InitCollector::GetCollector())
            InitCollector::GetCollector()->PushSendRecord(event_record);
    }
}

char FirstDriveFromMask(ULONG unitmask) {
    char i;
    for (i = 0; i < 26; ++i) {
        if (unitmask & 0x1)
            break;
        unitmask = unitmask >> 1;
    }
    return(i + 'A');
}

//ˢ��״̬
void UpdateDevice(PDEV_BROADCAST_VOLUME  pDevInf, WPARAM wParam) 
{
    auto dri = FirstDriveFromMask(pDevInf->dbcv_unitmask);
    if (DBT_DEVICEARRIVAL == wParam) 
    {       
        LoggerRecord::WriteLog(L"insert removable device " + to_wstring(dri), LogLevel::DEBUG);
        GetVolumeSerial(dri);
    }
    else {          
        LoggerRecord::WriteLog(L"remove removable device " + to_wstring(dri), LogLevel::DEBUG);      
    }
}

//����
LRESULT DeviceChange(UINT message, WPARAM wParam, LPARAM lParam)
{
    try
    {   
        // �豸�������Ƴ�����һ��״̬������״̬
        PDEV_BROADCAST_HDR pdr = (PDEV_BROADCAST_HDR)lParam;
        if ((DBT_DEVICEARRIVAL == wParam
            || DBT_DEVICEREMOVECOMPLETE == wParam)
            && DBT_DEVTYP_VOLUME == pdr->dbch_devicetype) 
        {
            UpdateDevice((PDEV_BROADCAST_VOLUME)pdr, wParam);
        }
    }
    catch (...) {
        LoggerRecord::WriteLog(L"DeviceChange catch exception", LogLevel::WARN);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)//��Ϣ�Ĵ������
{
    if (message == WM_DEVICECHANGE)         
        DeviceChange(message, wParam, lParam);

    return DefWindowProc(hwnd, message, wParam, lParam);
}

void GetDriveRemoveable() {
    wchar_t lpTargetPath[1000] = L"";
    wchar_t lpTargetPath_copy[1000] = L"";  
    wstring Removeable_Device = L"";
    try
    {  
        wcscpy(lpTargetPath_copy, lpTargetPath);
        wchar_t lpDeviceName[3] = L"C:";
        for (wchar_t device = L'A'; device <= L'Z'; device++) {
            lpDeviceName[0] = device;
            if (ERROR_INSUFFICIENT_BUFFER == QueryDosDeviceW(lpDeviceName, lpTargetPath, 1000)) {
    #ifdef OUTPUT_COMMAND_LINE
                cout << "lpTargetPath is not large enougth!" << endl;
    #endif // OUTPUT_COMMAND_LINE;
            }
            if (_wcsicmp(lpTargetPath_copy, lpTargetPath))
            {
                wcscpy(lpTargetPath_copy, lpTargetPath);
                //DRIVE_FIXED |  DRIVE_REMOVABLE
                UINT nRes = ::GetDriveType(lpDeviceName);
                if (DRIVE_REMOVABLE == nRes) {
                    GetVolumeSerial(device);
                }          
            }
        }
    }
    catch (...) {
        LoggerRecord::WriteLog(L"GetDriveRemoveable catch exception", LogLevel::WARN);
    }
}

void GetDeviceArrivalThreadTask::_Excute()
{
    Sleep(5000);

    // �ȱ���һ�δ�����Ϣ
    GetDriveRemoveable();

    static TCHAR szAppName[] = TEXT("HelloCollect"); // ������
    MSG msg;    //��Ϣ��
    WNDCLASS wndclass;
    wndclass.style = CS_HREDRAW | CS_VREDRAW; //��ʽ
    wndclass.cbClsExtra = 0;
    wndclass.cbWndExtra = 0;
    wndclass.hInstance = GetModuleHandle(nullptr);  // ���ڽ��̵�ʵ�����
    wndclass.lpfnWndProc = WndProc;                 // ���ô������windws��Ϣ����
    wndclass.lpszClassName = szAppName;             // ��������
    if (!RegisterClass(&wndclass))                  // ע�ᴰ����
    {
        LoggerRecord::WriteLog(L"GetDeviceArrivalThreadTask::_Excute RegisterClass failed " + to_wstring(GetLastError()), LogLevel::WARN);
        //MessageBox(NULL, TEXT("This program requires Windows NT!"), szAppName, MB_ICONERROR);
        return ;
    };

    _hwnd = CreateWindow(szAppName, NULL,
        WS_DISABLED,
        0, 0,
        0, 0,
        NULL, NULL, GetModuleHandle(nullptr), NULL);
    if (_hwnd == nullptr)
    {
        LoggerRecord::WriteLog(L"GetDeviceArrivalThreadTask::_Excute CreateWindow failed " + to_wstring(GetLastError()), LogLevel::WARN);
        return;
    }

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);//������Ϣ�����͵�windows��Ϣ����
        DispatchMessage(&msg);//������Ϣ
    }
}


void GetDeviceArrivalThreadTask::Log()
{
	//LoggerRecord::WriteLog(L"VisibleWindowProcessCount: " + std::to_wstring(_vw_process_set.size()), INFO);
}

void GetDeviceArrivalThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitGetDeviceArrival", INFO);
}

void GetDeviceArrivalThreadTask::Stop()
{
    _stop_flag = true;
    _thread.detach();
}
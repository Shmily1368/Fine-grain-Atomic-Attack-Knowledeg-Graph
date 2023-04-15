#include "stdafx.h"
#include "get_device_drive_map.h"
#include "tool_functions.h"
#include <fstream>
#include <windows.h>
#include <io.h>
#include "init_collector.h"

using namespace std;

void GetDeviceDriveMap::getDeviceDriveMap() 
{
	DeviceDriveMap.clear();

	wchar_t lpTargetPath[1000] = L"";
	wchar_t lpTargetPath_copy[1000] = L"";
	DeviceDriveMapItem item;
	wstring Removeable_Device = L"";

	wcscpy(lpTargetPath_copy, lpTargetPath);
	wchar_t lpDeviceName[3] = L"C:";
	for (wchar_t device = L'A'; device <= L'Z'; device++) {
		lpDeviceName[0] = device;
		if (ERROR_INSUFFICIENT_BUFFER == QueryDosDeviceW(lpDeviceName, lpTargetPath, 1000)) {
#ifdef OUTPUT_COMMAND_LINE
			cout << "lpTargetPath is not large enougth!" << endl;
#endif // OUTPUT_COMMAND_LINE;
		}
		if (_wcsicmp(lpTargetPath_copy, lpTargetPath)) {
			wcscpy(lpTargetPath_copy, lpTargetPath);

			item.device = lpTargetPath;
			item.drive = lpDeviceName;

			//DRIVE_FIXED |  DRIVE_REMOVABLE
			UINT nRes = ::GetDriveType(lpDeviceName);
			if (DRIVE_REMOVABLE == nRes)
			{
				Removeable_Device += wstring(lpDeviceName);
			}
            // add by zxw on 20200708 transform tolower
            transform(item.device.begin(), item.device.end(), item.device.begin(), ::tolower);
			DeviceDriveMap.push_back(item);
			//LoggerRecord::WriteLog(L"DeviceDriveMap:" + item.device + L"-"+ item.drive, INFO);
			//wcout << item.device << "  " << item.drive;
		}
	}
	if (DeviceDriveMap.empty())
	{
		LoggerRecord::WriteLog(L"Get Device to Drive Map Failed!,errcode:" + to_wstring(GetLastError()), ERR);
	}

	//identify if have Removeable Device
	//comment code by chips 0219, detector no need
	//if (Removeable_Device != L"") {
	//	EventRecord* event_record = InitCollector::event_struct->ParseRemoveableDeviceEvent(Removeable_Device);
	//	InitCollector::wait_send_dataqueue.push(event_record);
	//}

}

void GetDeviceDriveMap::storeMap2File(string fileName) {
	wofstream mapFile(fileName);

	for (int i = 0; i < DeviceDriveMap.size(); i++) {
		mapFile << DeviceDriveMap[i].device;
		mapFile << ' ';
		mapFile << DeviceDriveMap[i].drive << endl;
	}

	mapFile.close();
}

void GetDeviceDriveMap::readMapFromFile(string fileName) {
	wifstream mapFile(fileName);
	DeviceDriveMapItem item;

	DeviceDriveMap.clear();
	while (mapFile >> item.drive) {
		mapFile >> item.device;
		DeviceDriveMap.push_back(item);
	}

	mapFile.close();
}

wstring GetDeviceDriveMap::formatFilePathDevice(const wchar_t* path) {
	wstring pathS(path);
	size_t temp;

	for (int i = 0; i < DeviceDriveMap.size(); i++) {
		temp = pathS.find(DeviceDriveMap[i].device);
		if (temp != string::npos) {
			pathS.replace(temp, DeviceDriveMap[i].device.size(), DeviceDriveMap[i].drive);
			break;
		}
	}

	return formatFilePathDrive(pathS.c_str());
}

wstring GetDeviceDriveMap::formatFilePathDrive(const wchar_t* path) {
	wstring pathS(path);

	size_t temp;
	temp = pathS.find(L":");
	if (temp == string::npos) return L"";

	pathS.replace(temp, 1, L"");

	temp = pathS.find(L"\\");
	while (temp != string::npos) {
		pathS.replace(temp, 1, L".");
		pathS.insert(temp,L".");
		temp = pathS.find(L"\\");
	}

	return pathS;
}

bool GetDeviceDriveMap::ConvertDeviceFormat2DriveFormat(const std::wstring& path, std::wstring& ret_path, bool force_convert)
{
	ret_path = path;    
	size_t temp;

	// "SystemRoot\\..."
	if (ret_path[1] == 0x0053 || ret_path[1] == 115)
	{
		ret_path.replace(0, 13, L"C:\\Windows\\S");
		return true;
	}

	temp = path.find(L":");
	if (temp != std::wstring::npos && temp > 1)
	{
		ret_path = ret_path.substr(temp - 1, ret_path.size() - temp);
		return true;
	}
    // add by zxw on 2020708 tolower
    auto low_path = path;
    std::transform(low_path.begin(), low_path.end(), low_path.begin(), ::tolower);
	for (int i = 0; i < DeviceDriveMap.size(); i++)
	{
		temp = low_path.find(DeviceDriveMap[i].device + L"\\");    //L"\\Device\\HarddiskVolume4"
		if (temp != string::npos)
		{
			ret_path.replace(temp, DeviceDriveMap[i].device.size(), DeviceDriveMap[i].drive);
			return true;
		}
		else
		{
			temp = low_path.find(DeviceDriveMap[i].device);
			if (temp != string::npos && DeviceDriveMap[i].device.size() == ret_path.size())
			{
				ret_path.replace(temp, DeviceDriveMap[i].device.size(), DeviceDriveMap[i].drive);
				return true;
			}
		}
	}

	//Path do not have any HarddiskVolume info,such as \\Microsoft VS Code\\Code.exe, we can not replace it as "C:\" directly

	//traversal all drive to get absolute path,but if path exist both in two drive, will have problem --12.13
	if (low_path.find(L"harddiskvolume") == wstring::npos)
	{
        if (!force_convert)
        {
            //LoggerRecord::WriteLog(L"GetDeviceDriveMap::convertDeviceFormat2DriveFormat: exception harddisk info, path = " + ret_path, LogLevel::ERR);
            return false;
        }

		std::wstring temp_path;
		for (int i = 0; i < DeviceDriveMap.size(); i++)
		{
			if (DeviceDriveMap[i].device.find(L"harddiskvolume") != string::npos)
			{
				temp_path = DeviceDriveMap[i].drive + path;
				if (_waccess(temp_path.c_str(), 0) == 0)
				{
					ret_path = temp_path;
					return true;
				}
			}
		}
        LoggerRecord::WriteLog(L"GetDeviceDriveMap::convertDeviceFormat2DriveFormat: exception harddisk info, path = " + ret_path, LogLevel::ERR);
	}
	else
	{
		getDeviceDriveMap();
		for (int i = 0; i < DeviceDriveMap.size(); i++)
		{
			temp = low_path.find(DeviceDriveMap[i].device + L"\\");    //L"\\Device\\HarddiskVolume4"
			if (temp != string::npos)
			{
				ret_path.replace(temp, DeviceDriveMap[i].device.size(), DeviceDriveMap[i].drive);
				return true;
			}
			else 
			{
				temp = low_path.find(DeviceDriveMap[i].device);
				if (temp != string::npos && DeviceDriveMap[i].device.size() == ret_path.size())
				{
					ret_path.replace(temp, DeviceDriveMap[i].device.size(), DeviceDriveMap[i].drive);
					return true;
				}
			}

		}
	}

	//if U Disk enter,we not have DeviceDriveMap,just send HarddiskVolume path info to identify it
	//12.13 change policy,identify whether device is removable

	return true;
}

wstring GetDeviceDriveMap::convertDriveFormat2DeviceFormat(wstring path) {
	return L"";
}

wstring convertStringTOWstring(string str) {
	wstring wstr(str.begin(), str.end());
	return wstr;
}

void GetDeviceDriveMap::GetDeviceDriveMapFromFile(std::string file_path_)
{
	wfstream infile(file_path_);
	if (!infile)
	{
		std::wstring temp = ToolFunctions::StringToWString(file_path_) + L" is not exists\n";
		LoggerRecord::WriteLog(temp, ERR);
	}
	DeviceDriveMapItem temp_DeviceDriveMapItem;
	while (infile >> temp_DeviceDriveMapItem .drive>> temp_DeviceDriveMapItem.device)
	{
		//transform(temp_DeviceDriveMapItem.device.begin(), temp_DeviceDriveMapItem.device.end(), temp_DeviceDriveMapItem.device.begin(), ::tolower);
		//transform(temp_DeviceDriveMapItem.drive.begin(), temp_DeviceDriveMapItem.drive.end(), temp_DeviceDriveMapItem.drive.begin(), ::tolower);
		DeviceDriveMap.push_back(temp_DeviceDriveMapItem);
	}
}

//int main() {
//	GetDeviceDriveMap map;
//
//	// collecter
//	map.getDeviceDriveMap();
//	map.storeMap2File("C:\\Users\\lzy\\Desktop\\DeviceDriveMap.txt");
//
//	// parser
//	map.readMapFromFile("C:\\Users\\lzy\\Desktop\\DeviceDriveMap.txt");
//
//	wchar_t path1[100] = L"\\Device\\HarddiskVolume2\\Users\\admin\\Desktop\\Dark Comet";
//	wchar_t path2[100] = L"C:\\\\Users\\\\admin\\\\Desktop\\\\Dark Comet";
//
//	wcout << map.formatFilePathDrive(path2) << endl;
//	wcout << map.formatFilePathDevice(path1) << endl;
//
//	return 0;
//}
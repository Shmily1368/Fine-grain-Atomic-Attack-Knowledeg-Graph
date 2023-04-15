#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-1
// Updated 2018-4-16

#include <vector>


class GetDeviceDriveMap{
public:
	void getDeviceDriveMap();

	// help store map into file, would not be used in realtime version
	void storeMap2File(std::string fileName);
	void readMapFromFile(std::string fileName);
	// input: L"\\Device\\HarddiskVolume2\\Users\\admin\\Desktop\\Dark Comet"
	// output: L"C..Users..admin..Desktop..Dark Comet"
	std::wstring formatFilePathDevice(const wchar_t* path);
	std::wstring formatFilePathDrive(const wchar_t* path);
	void GetDeviceDriveMapFromFile(std::string);

	// for realtime version
	// **** key operation ******
	bool ConvertDeviceFormat2DriveFormat(const std::wstring& path, std::wstring& ret_path, bool force_convert);
	// leave empty.
	std::wstring convertDriveFormat2DeviceFormat(std::wstring path);

private:
	class DeviceDriveMapItem {
	public:
		std::wstring device;
		std::wstring drive;
	};
	std::vector<DeviceDriveMapItem> DeviceDriveMap;
};

std::wstring convertStringTOWstring(std::string str);
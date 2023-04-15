#include "stdafx.h"
#include "thread_task_get_visiblewindow.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "filter.h"
#include "init_collector_online_parse.h"

#include <Windows.h>
#include <windef.h>

GetVisibleWindowThreadTask::GetVisibleWindowThreadTask()
	: BaseThreadTask(GET_VISIBLE_WINDOW_TASK_MODE)
	, _desktop_width(0)
	, _desktop_height(0)
{
	_cout_times = 0;
	//_interval_time = Setting::GetInstance().GetInt("get_visiblewindow_task_interval");
	_interval_time = Setting::GetInstance().visible_window_task_interval();
}

GetVisibleWindowThreadTask::~GetVisibleWindowThreadTask()
{

}

BOOL CALLBACK GetVisibleWindowThreadTask::_StaticEnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	GetVisibleWindowThreadTask *pThis = reinterpret_cast<GetVisibleWindowThreadTask*>(lParam);
	return pThis->_EnumWindowsProc(hwnd);
}

BOOL GetVisibleWindowThreadTask::_EnumWindowsProc(HWND hwnd)
{
	DWORD process_id = 0, thread_id = 0;
	thread_id = GetWindowThreadProcessId(hwnd, &process_id);
	if (Filter::GetInstance().IsSuperWhiteListProcessEx(process_id))	return TRUE;
	if (process_id == InitCollectorOnlineParse::application_frame_host_pid)
	{
		EnumChildWindows(hwnd, _StaticEnumChildWindowsProc, reinterpret_cast<LPARAM>(this));
		return TRUE;
	}

	if (QueryVisiblebyProcessId(process_id))
	{
		return TRUE;
	}

	RECT rect;
	DWORD visible, toolbar;
	if (!_WindowVisible(hwnd, rect, visible, toolbar))
	{
		return TRUE;
	}

	_OnWindowVisible(hwnd, process_id, thread_id, rect, visible, toolbar);
	return TRUE;
}

BOOL CALLBACK GetVisibleWindowThreadTask::_StaticEnumChildWindowsProc(HWND hwnd, LPARAM lParam)
{
	GetVisibleWindowThreadTask *pThis = reinterpret_cast<GetVisibleWindowThreadTask*>(lParam);
	return pThis->_EnumChildWindowsProc(hwnd);
}

BOOL GetVisibleWindowThreadTask::_EnumChildWindowsProc(HWND hwnd)
{
	DWORD process_id = 0, thread_id = 0;
	thread_id = GetWindowThreadProcessId(hwnd, &process_id);
	if (Filter::GetInstance().IsSuperWhiteListProcess(process_id))	return TRUE;
	if (process_id == InitCollectorOnlineParse::application_frame_host_pid)	return TRUE;

    if (QueryVisiblebyProcessId(process_id))
	{
		return TRUE;
	}

	RECT rect;
	DWORD visible, toolbar;
	if (!_WindowVisible(hwnd, rect, visible, toolbar))
	{
		return TRUE;
	}

	_OnWindowVisible(hwnd, process_id, thread_id, rect, visible, toolbar);
	return TRUE;
}

void GetVisibleWindowThreadTask::_Excute()
{
    // add by zxw on 20210111 wait 10s 否则无法获取UUID
    Sleep(MS_TEN_SECOND);

	while (!_stop_flag) 
	{
		//get system resolution radio
		if (_desktop_width == 0 && _desktop_height == 0)
		{
			//_desktop_width = GetSystemMetrics(SM_CXSCREEN);
			//_desktop_height = GetSystemMetrics(SM_CYSCREEN);
            ToolFunctions::GetScreenRect(_desktop_width, _desktop_height);

			EventRecord* event_record = EventRecordManager::GetInstance().ParseVisibleWindowStruct(0, 0, 0, 0, 0, _desktop_width, _desktop_height, 0, 0);
			InitCollector::GetCollector()->PushSendRecord((EventRecord*)event_record);
		}

		/*
		Enumerates all top-level windows on the screen by passing the handle to each window,
		in turn, to an application-defined callback function. EnumWindows continues
		until the last top-level window is enumerated or the callback function returns FALSE.
		*/
		std::copy(_vw_handle_buf_next.begin(), _vw_handle_buf_next.end(), std::inserter(_vw_handle_buf_prev, _vw_handle_buf_prev.begin()));
		_vw_handle_buf_next.clear();
		{
			//AutoLock lock(_lock);
			EnumWindows(_StaticEnumWindowsProc, reinterpret_cast<LPARAM>(this));
		}
		_vw_handle_buf_prev.clear();

		Sleep(_interval_time);
		_cout_times++;

		if (_cout_times % 1000 == 0) 
		{
			_cout_times = 0;
			LoggerRecord::WriteLog(L"GetVisibleWindowThreadTask::_Excute: vw_process_set = " + std::to_wstring(_vw_process_set.size()), INFO);
		}
	}
}

bool GetVisibleWindowThreadTask::_WindowInScreen(const RECT& rect)
	{
	//这样我们认为是被最小化的window;
	if (rect.bottom < 0 && rect.right < 0)
	{
		return true;
	}

	if ((rect.right - rect.left) <= 2 || (rect.bottom - rect.top) <= 2)
	{
		return false;
	}

	if (rect.top >= _desktop_height || rect.bottom <= 0 ||
		rect.left >= _desktop_width || rect.right <= 0)
	{
		return false;
	}

	//取屏幕内部分判断长宽;
	LONG actual_left = max((LONG)0, rect.left);
	LONG actual_right = min(_desktop_width, rect.right);
	LONG actual_top = max((LONG)0, rect.top);
	LONG actual_bottom = min(_desktop_height, rect.bottom);
	if ((actual_right - actual_left) <= 2 || (actual_bottom - actual_top) <= 2)
	{
		return false;
	}

	return true;
}

bool GetVisibleWindowThreadTask::_WindowVisible(HWND hwnd, RECT& rect, DWORD& visible, DWORD& toolbar)
{
	LONG style = GetWindowLong(hwnd, GWL_STYLE);
	LONG ex_style = GetWindowLong(hwnd, GWL_EXSTYLE);

	if (style == 0)
	{
		return false;
	}

	visible = (style & WS_VISIBLE) != 0 ? 1 : 0;
	toolbar = ToolFunctions::WindowIconic(hwnd) ? 1 : 0;
	DWORD layered = (ex_style & WS_EX_LAYERED) != 0 ? 1 : 0;

	if (visible == 0 && toolbar == 0)
	{
		return false;
	}

	if (layered != 0)
	{
		BYTE alpha = 0;
		DWORD dw_flag = 0;
		GetLayeredWindowAttributes(hwnd, NULL, &alpha, &dw_flag);
		if (((dw_flag & LWA_ALPHA) != 0) && alpha == 0)	//the window is completely transparent;
		{
			return false;
		}
	}

	HWND owner_hwnd = GetWindow(hwnd, GW_OWNER);
	if (owner_hwnd != 0)
	{
		LONG owner_style = GetWindowLong(owner_hwnd, GWL_STYLE);
		DWORD owner_visible = (owner_style & WS_VISIBLE) != 0 ? 1 : 0;
		DWORD owner_toolbar = ToolFunctions::WindowIconic(owner_hwnd) ? 1 : 0;
		if (owner_visible == 0 && owner_toolbar == 0)
		{
			return false;
		}
	}

	GetWindowRect(hwnd, &rect);
	if (!_WindowInScreen(rect))
	{
		return false;
	}

	return true;
}

void GetVisibleWindowThreadTask::_OnWindowVisible(HWND hwnd, DWORD pid, DWORD tid, RECT rect, DWORD visible, DWORD toolbar)
{
	if (_vw_handle_buf_prev.find(hwnd) != _vw_handle_buf_prev.end())
	{
		pair<DWORD, LLONG> key(pid, (LLONG)hwnd);
		EventRecord* event_record = EventRecordManager::GetInstance().ParseVisibleWindowStruct(pid, tid, (LLONG)hwnd, rect.left, rect.top, rect.right, rect.bottom, visible, toolbar);
		InitCollector::GetCollector()->PushSendRecord(event_record);

		//_vw_process_set.insert(pid);
        InsertVisibleSet(pid);
	}
	else
	{
		_vw_handle_buf_next.insert(hwnd);
	}
}

bool GetVisibleWindowThreadTask::InsertVisibleSet(DWORD pid) 
{
    AutoLock lock(_lock);
    auto iter_f = _vw_process_set.find(pid);
    if (iter_f == _vw_process_set.end()) {
        _vw_process_set.insert(pid);
    }   
    return true;
}

bool GetVisibleWindowThreadTask::EraseVisibleSet(DWORD pid) 
{
    AutoLock lock(_lock);
    auto iter_f = _vw_process_set.find(pid);
    if (iter_f != _vw_process_set.end()) {
        _vw_process_set.erase(iter_f);
    }
    return true;
}

bool GetVisibleWindowThreadTask::QueryVisiblebyProcessId(DWORD pid) 
{
    AutoLock lock(_lock);
    auto iter_f = _vw_process_set.find(pid);
    if (iter_f != _vw_process_set.end()) {
        return true;
    }
    return false;
}

void GetVisibleWindowThreadTask::Log()
{
	LoggerRecord::WriteLog(L"VisibleWindowProcessCount: " + std::to_wstring(_vw_process_set.size()), INFO);
}

void GetVisibleWindowThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitVisibleWindowRecord", INFO);
}

void GetVisibleWindowThreadTask::AddData(EventRecord* record)
{
	const EventIdentifier& identifier = record->get_event_identifier_();
	if (identifier.provider_id() != ETWProcess || identifier.opcode() != EM_ProcessEventOPC::ProcessEnd)
	{
		return;
	}

    EraseVisibleSet(record->get_process_id_());
}

/********************************************************************
	Created:		2019-01-09
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to get visible window;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/01/09 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"

#include <windows.h>
#include <windef.h>

class GetVisibleWindowThreadTask : public BaseThreadTask
{
private:
	int _cout_times;
	int _interval_time;
	LONG _desktop_width;
	LONG _desktop_height;

	Mutex _lock;

	std::set<DWORD> _vw_process_set;
	std::set<HANDLE> _vw_handle_buf_next;
	std::set<HANDLE> _vw_handle_buf_prev;

	//please read article about how to make a callback function a member of class?: https://blogs.msdn.microsoft.com/oldnewthing/20140127-00/?p=1963
	static BOOL CALLBACK _StaticEnumWindowsProc(HWND hwnd, LPARAM lParam);
	BOOL _EnumWindowsProc(HWND hwnd);

	static BOOL CALLBACK _StaticEnumChildWindowsProc(HWND hwnd, LPARAM lParam);
	BOOL _EnumChildWindowsProc(HWND hwnd);

	virtual void _Excute();

	bool _WindowInScreen(const RECT& rect);
	bool _WindowVisible(HWND hwnd, RECT& rect, DWORD& visible, DWORD& toolbar);
	void _OnWindowVisible(HWND hwnd, DWORD pid, DWORD tid, RECT rect, DWORD visible, DWORD toolbar);
public:
    bool InsertVisibleSet(DWORD pid);
    bool EraseVisibleSet(DWORD pid);
    bool QueryVisiblebyProcessId(DWORD pid);
public:
	GetVisibleWindowThreadTask();
	~GetVisibleWindowThreadTask();

	virtual void Log();
	virtual void Init();
	virtual void AddData(EventRecord* record) override;
};
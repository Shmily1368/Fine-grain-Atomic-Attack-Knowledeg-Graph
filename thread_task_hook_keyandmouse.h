/********************************************************************
	Created:		2019-01-14
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to hook key and mouse;
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
#include "windef.h"

//class HookKeyAndMouseThreadTask : public BaseThreadTask
//{
//private:
//	bool _capsLock;
//	INT_WSTRING_MAP _key_translate_map;
//private:
//	static HHOOK _hLLKeyboardHook;
//	static HHOOK _hLLMouseHook;
//
//	void _InitKeyNameMap();
//	LRESULT _LowLevelMouseProc(INT nCode, WPARAM wParam);
//	LRESULT _LowLevelKeyboardProc(INT nCode, WPARAM wParam);
//public:
//	HookKeyAndMouseThreadTask();
//	~HookKeyAndMouseThreadTask();
//
//	static BOOL CtrlHandlerForExit(DWORD fdwCtrlType);  // to handler exit info,thus we can remove hook
//	static LRESULT CALLBACK _StaticLowLevelMouseProc(INT nCode, WPARAM wParam, LPARAM lParam);
//	static LRESULT CALLBACK _StaticLowLevelKeyboardProc(INT nCode, WPARAM wParam, LPARAM lParam);
//
//	virtual void Excute();
//	virtual void Log();
//	virtual void Init();
//};

class HookKeyAndMouseThreadTask : public BaseThreadTask
{
private:
	static bool _capsLock;
	static INT_WSTRING_MAP _key_translate_map;
	static HHOOK _hLLKeyboardHook;
	static HHOOK _hLLMouseHook;

	void _InitKeyNameMap();
	virtual void _Excute();
public:
	HookKeyAndMouseThreadTask();
	~HookKeyAndMouseThreadTask();

	static BOOL CtrlHandlerForExit(DWORD fdwCtrlType);  // to handler exit info,thus we can remove hook
	static LRESULT CALLBACK StaticLowLevelMouseProc(INT nCode, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK StaticLowLevelKeyboardProc(INT nCode, WPARAM wParam, LPARAM lParam);

	virtual void Log();
	virtual void Init();
};


#pragma once
#include <functional>

#define DECLARE_LEAVE_SECTION_CALLBACK(func)	DECLARE_LEAVE_SECTION_CALLBACK_IMPL(func, __LINE__)
#define DECLARE_LEAVE_SECTION_CALLBACK_IMPL(func, line) DECLARE_LEAVE_SECTION_CALLBACK_IMPL_2(func, line)
#define DECLARE_LEAVE_SECTION_CALLBACK_IMPL_2(func, line)	OnLeaveSectionCallback __on_leave_section_callback_##line##__(func)

class OnLeaveSectionCallback
{
	DISABLE_COPY(OnLeaveSectionCallback);

public:
	OnLeaveSectionCallback(std::function<void()> callback) : _callback(callback) {}
	~OnLeaveSectionCallback() { if (_callback) { _callback(); } }

private:
	std::function<void()> _callback;
};
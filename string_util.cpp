/********************************************************************
	Created:		2019-03-19
	Author:			chips;
	Version:		1.0.0(version);
	Description:	string util function;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/03/19 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#include "stdafx.h"
#include "string_util.h"

void StringUtil::split(const string& str, char ch, STRING_VECTOR& str_vec)
{
	if (str.empty())
	{
		return;
	}

	size_t start = 0;
	size_t pos = 0;
	do 
	{
		pos = str.find_first_of(ch, start);
		if (pos == string::npos)
		{
			str_vec.push_back(str.substr(start));
			break;
		}

		str_vec.push_back(str.substr(start, pos - start));
		start = pos + 1;

	} while (pos != string::npos);
}

String StringUtil::Join(const STRING_VECTOR& str_vec, int_32 start_pos, const String& delims)
{
	String temp = "";
	String ret;
	for (uint_32 i = start_pos; i < str_vec.size(); ++i)
	{
		ret.append(temp.append(str_vec[i]));
		temp = delims;
	}
	return ret;
}

String StringUtil::ToLowerCase(const String& source_str)
{
	String ret(source_str);
	std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
	return ret;
}

String StringUtil::ToUpperCase(const String& source_str)
{
	String ret(source_str);
	std::transform(ret.begin(), ret.end(), ret.begin(), ::toupper);
	return ret;
}

bool StringUtil::IsStartWith(const String& source_str, const String& compare_str, bool ignore_case /*= false*/)
{
	size_t source_str_len = source_str.size();
	size_t compare_str_len = compare_str.size();
	if (source_str_len < compare_str_len || compare_str_len == 0)	return false;

	String source_str_need = source_str.substr(0, compare_str_len);
	String compare_str_copy(compare_str);
	if (ignore_case)
	{
		source_str_need = ToLowerCase(source_str_need);
		compare_str_copy = ToLowerCase(compare_str_copy);
	}

	return source_str_need.compare(compare_str_copy) == 0;
}

bool StringUtil::IsEndWith(const String& source_str, const String& compare_str, bool ignore_case /*= false*/)
{
	size_t source_str_len = source_str.size();
	size_t compare_str_len = compare_str.size();
	if (source_str_len < compare_str_len || compare_str_len == 0)	return false;

	String source_str_need = source_str.substr(source_str_len - compare_str_len, compare_str_len);
	String compare_str_copy(compare_str);
	if (ignore_case)
	{
		source_str_need = ToLowerCase(source_str_need);
		compare_str_copy = ToLowerCase(compare_str_copy);
	}

	return source_str_need.compare(compare_str_copy) == 0;
}

bool StringUtil::ParseBool(const String& val)
{
	return (IsStartWith(val, "true") || IsStartWith(val, "yes") || IsStartWith(val, "1"));
}

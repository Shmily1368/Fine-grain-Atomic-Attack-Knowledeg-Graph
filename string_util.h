#pragma once

class StringUtil
{
public:
	static void split(const string& str, char ch, STRING_VECTOR& str_vec);
	static String Join(const STRING_VECTOR& str_vec, int_32 start_pos, const String& delims);

	static String ToLowerCase(const String& source_str);
	static String ToUpperCase(const String& source_str);

	static bool IsStartWith(const String& source_str, const String& compare_str, bool ignore_case = false);
	static bool IsEndWith(const String& source_str, const String& compare_str, bool ignore_case = false);

	static bool ParseBool(const String& val);
	static int_32 ParseInt32(const String& val) { return parseT<int_32>(val); }
	static uint_32 ParseUInt32(const String& val) { return parseT<uint_32>(val); }
	static int_64 ParseInt64(const String& val) { return parseT<int_64>(val); }
	static uint_64 ParseUInt64(const String& val) { return parseT<uint_64>(val); }
	template<class T>
	static T parseT(const String& val)
	{
		std::istringstream str_in(val);
		T ret;
		str_in >> ret;

		return ret;
	}
};
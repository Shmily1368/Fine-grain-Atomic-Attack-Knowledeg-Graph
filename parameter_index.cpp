#include "stdafx.h"
#include "parameter_index.h"
#include <algorithm>

#undef _GENERATE_PARAMETER_INDEX
#define _GENERATE_PARAMETER_INDEX(param)	#param
const char* parameter_string_list[] =
{
	GENERATE_PARAMETER_INDEX
};
const char* json_parameter_name_list[] =
{
	GENERATE_PARAMETER_INDEX
};

ParameterIndex::ParameterIndex()
{
	for (int_32 i = 0; i < KParametesStringListSize; ++i)
	{
		parameter_string_vector.push_back(parameter_string_list[i]);
	}
}

ParameterIndex::~ParameterIndex()
{
}

parameter_index_enum ParameterIndex::get_parameter_string_vector(std::string parameter_name)
{
	std::vector<std::string>::iterator ix = find(parameter_string_vector.begin(), parameter_string_vector.end(), parameter_name);
	if (ix == parameter_string_vector.end()) return None;
	return (parameter_index_enum)(int)std::distance(parameter_string_vector.begin(), ix);
}

std::string ParameterIndex::parameter_index_enum_to_string(parameter_index_enum index)
{
	if (index < KParametesStringListSize) return parameter_string_list[index];
	return "";
}

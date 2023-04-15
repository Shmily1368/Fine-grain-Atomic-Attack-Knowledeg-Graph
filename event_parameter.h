#pragma once

#include <stdio.h>
#include <string>
#include "parameter_index.h"

class EventParameter
{
public:
	EventParameter(parameter_index_enum,int,int);
	EventParameter();
	~EventParameter();
	parameter_index_enum name;
	int offset;
	int length;

	EventParameter operator =(const EventParameter& right_operant){
		length = right_operant.length;
		offset = right_operant.offset;
		name = right_operant.name;
	}
};


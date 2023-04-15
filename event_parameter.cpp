#include "stdafx.h"
#include "event_parameter.h"

EventParameter::EventParameter() :name(None), offset(-1), length(-1)
{
}

EventParameter::EventParameter(parameter_index_enum name, int offset, int length) :name(name), offset(offset), length(length)
{
}


EventParameter::~EventParameter()
{
}

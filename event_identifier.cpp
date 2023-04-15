#include "stdafx.h"
#include "event_identifier.h"

EventIdentifier::EventIdentifier(uint_32 provider_id, int_32 opcode)
	: m_provider_id(provider_id), m_opcode(opcode)
{

}

EventIdentifier::EventIdentifier() : m_provider_id(0), m_opcode(0)
{

}

EventIdentifier::~EventIdentifier(){

}

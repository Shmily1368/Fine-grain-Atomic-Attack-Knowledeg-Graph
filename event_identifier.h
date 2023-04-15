#pragma once

#include <string>

class EventIdentifier
{
public:
	EventIdentifier(uint_32 provider_id, int_32 opcode);
	EventIdentifier();
	~EventIdentifier();

	inline bool operator<(const EventIdentifier& rhs) const
	{
		if (m_provider_id < rhs.m_provider_id) return true;
		if (m_provider_id == rhs.m_provider_id && m_opcode < rhs.m_opcode) return true;
		return false;
	}

	inline bool operator==(const EventIdentifier& rhs) const
	{
		if (m_provider_id == rhs.m_provider_id && m_opcode == rhs.m_opcode) return true;
		return false;
	}

	inline bool operator!=(const EventIdentifier& rhs) const
	{
		return !(*this == rhs);
	}

	inline void operator=(const EventIdentifier& rhs)
	{
		m_provider_id = rhs.m_provider_id;
		m_opcode = rhs.m_opcode;
		m_event_name = rhs.m_event_name;
	}

private:
	DEFINE_PROPERTY(uint_32, provider_id);
	DEFINE_PROPERTY(int_32, opcode);
	DEFINE_PROPERTY_REF(String, event_name);
};

namespace std {
    template <>
    struct hash<EventIdentifier> {
        std::size_t operator()(const EventIdentifier &key) const {
            using std::size_t;
            using std::hash;

            return (hash<uint_32>()(key.provider_id()) ^
                (hash<uint_16>()(key.opcode()) << 1));
        }
    };
}
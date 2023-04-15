

#ifndef MARPLE_RECORDS_UUID_GENERATOR_H_
#define MARPLE_RECORDS_UUID_GENERATOR_H_
#include <windows.h>
#include <boost/array.hpp>
#include <iostream>
//#include <cstdlib>
//#include <cstdint>
//#include <set>
//#include "etw_cdm.h"
//#include "records/uuid.h"
//
//using namespace etw_cdm;
//	class UUIDGenerator {
//	public:
//		static ULONG64 UUIDL_event;
//		static ULONG64 UUIDH_event;
//		static ULONG64 UUIDL_other;
//		static set<ULONG64> usedUUIDSet;
//
//		ULONG64 convertUUIDtoULONG64(boost::array<uint8_t, UUID_LENGTH> uuid)
//		{
//			ULONG64 result =  0;
//			ULONG64 index = 1;
//			for (int i = UUID_LENGTH - 1; i >= 0 ; i--)
//			{
//				result += index * uuid[i];
//				index *= 128;
//			}
//			return result;
//		}
//		inline boost::array<uint8_t, UUID_LENGTH>
//			getRandomUuid() {
//			boost::array<uint8_t, UUID_LENGTH> uuid;
//			for (int i = UUID_LENGTH -1 ; i >= 0; i--)
//				uuid[i] = (uint8_t)(rand() % UUID_BIT_LENGTH);
//			return uuid;
//		};
//
//		inline boost::array<uint8_t, UUID_LENGTH>
//			getNextUuid_other() {
//			boost::array<uint8_t, UUID_LENGTH> uuid;
//			ULONG64 tmpUUIDL = UUIDL_other;
//			ULONG64 index = 128;
//			for (int i = UUID_LENGTH - 1; i >= 8; i--)
//			{
////				std::cout << uuid[i] << endl;
//				uuid[i] = tmpUUIDL % index;
//				tmpUUIDL /= ULONG64(128);
//			}
//			for (int i = 0; i < 8; i++)
//				uuid[i] = 0;
//
//
//			UUIDL_other++;
//			// find UUIDs which are used.
//			while (usedUUIDSet.count(UUIDL_other) != 0)
//			{
//				UUIDL_other++;
//				if (UUIDL_other == 0)
//				{
//					for (auto i = etw_cdm::subject_process_map.begin(); i != etw_cdm::subject_process_map.end(); i++)
//					{
//						usedUUIDSet.insert(convertUUIDtoULONG64(i->second.datum.get_Subject().uuid));
//					}
//
//					for (auto i = etw_cdm::subject_thread_map.begin(); i != etw_cdm::subject_thread_map.end(); i++)
//					{
//						usedUUIDSet.insert(convertUUIDtoULONG64(i->second.datum.get_Subject().uuid));
//					}
//
//					// get used registry object, network flow object, file object
//					for (auto i = etw_cdm::object_map.begin(); i != etw_cdm::object_map.end(); i++)
//					{
//						//					usedUUIDSet.insert(convertUUIDtoULONG64(i->second.datum.get().uuid));
//					}
//				}
//			}
//			return uuid;
//		};
//
//		inline boost::array<uint8_t, UUID_LENGTH>
//			getNextUuid_event() {
//			boost::array<uint8_t, UUID_LENGTH> uuid;
//			ULONG64 tmpUUID = UUIDL_event;
//			ULONG64 index = 128;
//			for (int i = UUID_LENGTH - 1; i >= 8; i--)
//			{
//				uuid[i] = tmpUUID % index;
//				tmpUUID /= 128;
//			}
//			tmpUUID = UUIDH_event;
//			for (int i = 7; i >= 0; i--)
//			{
//				uuid[i] = tmpUUID % index;
//				tmpUUID /= 128;
//			}
//
//
//			UUIDL_event++;
//
//			if (UUIDL_event == 0)
//			{
//				UUIDH_event++;
//			}
//
//			if (UUIDH_event == 0)
//				UUIDH_event++;
//			return uuid;
//		};
//	};

#include "records/uuid.h"
#include <chrono>
#include <ctime>
class UUIDGenerator {
public:
	boost::array < uint8_t, 16 > currentArray;
	UUIDGenerator(void) {
		currentArray[0] = (uint8_t)0;
		currentArray[1] = (uint8_t)0;
		currentArray[2] = (uint8_t)0;
		currentArray[3] = (uint8_t)0;
		currentArray[4] = (uint8_t)0;
		currentArray[5] = (uint8_t)0;
		currentArray[6] = (uint8_t)0;
		currentArray[7] = (uint8_t)0;
		currentArray[8] = (uint8_t)0;
		currentArray[9] = (uint8_t)0;
		currentArray[10] = (uint8_t)0;
		currentArray[11] = (uint8_t)0;
		currentArray[12] = (uint8_t)0;
		currentArray[13] = (uint8_t)0;
		currentArray[14] = (uint8_t)0;
		currentArray[15] = (uint8_t)0;
	}

	~UUIDGenerator(void) {
	}
	void setInitUuid(boost::array < uint8_t, 16 > arr) {
		currentArray = arr;
	}
	inline boost::array < uint8_t, 16 > getRandomUuid() {
		increase(15);
		return currentArray;
	}
private:
	bool increase(int index) {
		if (index == -1)
			return true;
		if (currentArray[index] == 127) {
			if (index == 15)
				std::cerr << "ARRAY FINISHED!!!" << std::endl;
			currentArray[index] = 0;
			return true;
		}
		else {
			if (increase(index - 1))
				currentArray[index]++;
			return false;
		}
	}
};


#endif  //MARPLE_RECORDS_UUID_GENERATOR_H_

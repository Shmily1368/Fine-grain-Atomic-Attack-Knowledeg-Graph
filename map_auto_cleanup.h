#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-3-27
// Updated 2018-3-30

#include <time.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <utility>

//#define CLEANUP_CIRCLE_TIME 36000000
#define CLEANUP_CIRCLE_TIME 120

template <typename KeyType, typename ValueType> class MapAutoCleanup
{
public:
	MapAutoCleanup() {
		time(&last_cleanup_time_);
		cleanup_circle_time_ = CLEANUP_CIRCLE_TIME;
        cache_map_.reserve(1000);
        cache_map_.rehash(1000);
	}
	MapAutoCleanup(float cleanup_circle_time) {
		MapAutoCleanup();
		this.cleanup_circle_time_ = cleanup_circle_time;
	}
	MapAutoCleanup(ValueType default_value) {
		MapAutoCleanup();
		setDefaultValue(default_value);
	}
	MapAutoCleanup(float cleanup_circle_time, ValueType default_value) {
		MapAutoCleanup(cleanup_circle_time);
		setDefaultValue(default_value);
	}
	~MapAutoCleanup() {
	}
    int size() { return cache_map_.size(); }
	void SetDefaultValue(ValueType default_value) {
		is_default_value_set_ = true;
		default_value_ = default_value;
	}
	void SetCleanupCircleTime(float cleanup_circle_time) {
		cleanup_circle_time_ = cleanup_circle_time;
	}

	/* Inquire  */
	ValueType GetValue(KeyType &key) {       
        auto iter = cache_map_.find(key);
		if (iter != cache_map_.end()) {
            iter->second.second = true;
			return iter->second.first;
		}
		else {
			if (is_default_value_set_) {               
				return default_value_;
			}
			else {
				ValueType value;             
				return value;
			}
		}
	}

	bool SetValue(KeyType &key, ValueType &value) {      
		time_t current_time;
		time(&current_time);
		if (cleanup_circle_time_ < difftime(current_time, last_cleanup_time_)) {
			AutoCleanup();
			last_cleanup_time_ = current_time;
		}
        
		cache_map_[key] = std::pair<ValueType, bool>(value, true);

		return true;
	}
    void DeleteKey(KeyType &key)
    { 
        cache_map_.erase(key);
        /*
        auto iter = cache_map_.begin();
        while (iter != cache_map_.end()) {
            if (iter->first == key) {
                iter = cache_map_.erase(iter);
                break;
            }           
            iter++;
        }
        */      
    }
private:
	bool is_default_value_set_ = false;
	/* The default value for GetValue() */
	ValueType default_value_;

	//pair<ValueType, bool> valueWithTimingPair; // value, timingFlag
	std::unordered_map<KeyType, std::pair<ValueType, bool>> cache_map_;

	time_t last_cleanup_time_;
	/* Defined the time interval between Clean up */
	float cleanup_circle_time_;

	void AutoCleanup() {
        LoggerRecord::WriteLog(L"MapAutoCleanup::AutoCleanup before size : " + std::to_wstring(cache_map_.size()), INFO);
		auto iter = cache_map_.begin();
		while (iter != cache_map_.end()) {
			if (!iter->second.second) {// not used recently, should be erased.
				iter = cache_map_.erase(iter);
			}
			else {
				iter->second.second = false;
				iter++;
			}
		}
#ifdef OUTPUT_COMMAND_LINE      
		std::cout << cache_map_.size() << std::endl;
#endif // OUTPUT_COMMAND_LINE;
        LoggerRecord::WriteLog(L"MapAutoCleanup::AutoCleanup after size : " + std::to_wstring(cache_map_.size()), INFO);
	}
};


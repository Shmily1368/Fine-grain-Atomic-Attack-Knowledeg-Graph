#include "stdafx.h"
#include "rule_matcher.h"
#include "tool_functions.h"
#include "public_json_interface.h"
#include "auto_lock.h"
#include <regex>

std::unordered_map<EventIdentifier, std::set<SRule>> rule_matcher::_rule_matcher;

rule_matcher::rule_matcher() {
}


rule_matcher::~rule_matcher() {
}

void rule_matcher::add_rule_map_by_file(std::string fileName)
{
    _rule_lock.WriteLock();
    public_json_interface::GetInstance().ParseRulebyFile(fileName, _rule_matcher);
    _rule_lock.WriteUnlock();
}

void rule_matcher::add_rule_map_by_string(std::string strContent) 
{
    _rule_lock.WriteLock();
    public_json_interface::GetInstance().ParseRulebyStr(strContent, _rule_matcher);
    _rule_lock.WriteUnlock();
}

void rule_matcher::add_rule_map(EventIdentifier EventID, SRule srule)
{
    _rule_lock.WriteLock();
    _rule_matcher[EventID].insert(srule);
    _rule_lock.WriteUnlock();
}

void rule_matcher::delete_rule_map(EventIdentifier EventID) 
{
    _rule_lock.WriteLock();
    auto iter = _rule_matcher.find(EventID);
    if (iter != _rule_matcher.end()) 
    {
        _rule_matcher.erase(iter);
    }
    _rule_lock.WriteUnlock();
}

void rule_matcher::update_rule_map(std::unordered_map<EventIdentifier, std::set<SRule>> rule)
{
    _rule_lock.WriteLock();
    _rule_matcher = rule;
    _rule_lock.WriteUnlock();
}

bool rule_matcher::exist_rule(EventIdentifier eventID) 
{
    _rule_lock.ReadLock();
    bool res = false;
    auto iter = _rule_matcher.find(eventID);
    if (iter != _rule_matcher.end()) {        
        res = true;
    }
    _rule_lock.ReadUnlock();
    return res;
}
/*
bool rule_matcher::get_rule_by_eventid(EventIdentifier eventID, SRule &srule) 
{
    _rule_lock.ReadLock();
    bool res = false;
    auto iter = _rule_matcher.find(eventID);
    if (iter != _rule_matcher.end()) {
        srule = iter->second;
        res = true;
    }
    _rule_lock.ReadUnlock();
    return res;
}
*/
bool rule_matcher::event_rule_matcher(EventRecord * ev, SRule &srule)
{
    if (!ev)
    {
        return false;
    }
    bool res = false;
    try
    {
        _rule_lock.ReadLock();
        do 
        {            
            EventIdentifier eventID(ev->get_event_identifier_().provider_id(), ev->get_event_identifier_().opcode());
            auto iter = _rule_matcher.find(eventID);
            if (iter != _rule_matcher.end()) {
                auto setrule = iter->second;                
                for each (auto var in setrule) 
                {
                    bool match_res = true;
                    auto attrributes = var.Attrributes;
                    if (attrributes.size() == 0)                    
                        continue;
                 
                    for each (auto varrule in attrributes) {
                        if (!attrributes_rule_matcher(ev, varrule)) {
                            match_res = false;
                            break;
                        }
                    }
                    // match succeed
                    if (match_res)
                    {
                        srule = var;
                        res = true;
                        break;
                    }
                }
                                            
            }
        } while (0);

        _rule_lock.ReadUnlock();
    }
    catch (...) {
        LoggerRecord::WriteLog(L"rule_matcher::event_rule_matcher catch exception ", LogLevel::ERR);
    }
    return res;
}

bool rule_matcher::attrributes_rule_matcher(EventRecord * ev, SAttrributes sattrributes)
{
    if (sattrributes.Field.length() == 0 || sattrributes.Target.length() == 0)
    {
        return false;
    }

    auto index_name = base_parameter_index.get_parameter_string_vector(sattrributes.Field);
    if (index_name == None)
    {
        return false;
    }

    auto str = ToolFunctions::WStringToString(ev->GetStringParameter(index_name));

    if (sattrributes.Match == 0)            // 正则匹配
    {        
        std::smatch m;
        //transform(sattrributes.Target.begin(), sattrributes.Target.end(), sattrributes.Target.begin(), tolower);
        //transform(str.begin(), str.end(), str.begin(), tolower);
        std::regex e(sattrributes.Target, regex_constants::icase);
        if (std::regex_search(str, m, e, regex_constants::match_default)) {
            return true;
        }
    }
    else if (sattrributes.Match == 1)       // 完全匹配
    {
        if(_stricmp(sattrributes.Target.c_str(), str.c_str()) == 0)  // 忽略大小写
                //if (sattrributes.Target == str)
        {
            return true;
        }
    }
    else if (sattrributes.Match == 2) {      // 正向模糊匹配        
        transform(sattrributes.Target.begin(), sattrributes.Target.end(), sattrributes.Target.begin(), tolower);
        transform(str.begin(), str.end(), str.begin(), tolower);        
        if (strstr(sattrributes.Target.c_str(), str.c_str()) != nullptr)
        {
            return true;
        }            
    }
    else if (sattrributes.Match == 3) {      // 反向模糊匹配      
        transform(sattrributes.Target.begin(), sattrributes.Target.end(), sattrributes.Target.begin(), tolower);
        transform(str.begin(), str.end(), str.begin(), tolower);
        if (strstr(str.c_str(), sattrributes.Target.c_str()) != nullptr) {
            return true;
        }
    }

    return false;
}

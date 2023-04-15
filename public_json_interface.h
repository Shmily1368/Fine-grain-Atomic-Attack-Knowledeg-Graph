#pragma once
#include <windows.h>
#include "event_identifier.h"
#include "event_record.h"
#include "publicstruct.h"
#include "json_include/rapidjson/document.h"

class public_json_interface {
    SINGLETON_DEFINITION(public_json_interface);
private:
    public_json_interface();
    ~public_json_interface();
public:
    bool ParseRulebyDocument(const rapidjson::Document &dom, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher);
    bool ParseRulebyStr(String strContent, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher);
    bool ParseRulebyFile(String fileName, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher);
    wstring GetEventArguments(EventRecord * ev);
};

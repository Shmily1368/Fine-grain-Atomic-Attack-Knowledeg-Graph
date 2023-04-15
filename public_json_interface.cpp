#include "stdafx.h"
#include "public_json_interface.h"
#include "json_include/rapidjson/filereadstream.h"
#include "json_include/rapidjson/document.h"
#include "json_include/rapidjson/prettywriter.h"
#include "json_include/rapidjson/stringbuffer.h"
#include <cstdio>
#include "tool_functions.h"
#include "event_record_manager.h"
#include "event_record.h"

using namespace rapidjson;

public_json_interface::public_json_interface() {
}


public_json_interface::~public_json_interface() {
}


bool public_json_interface::ParseRulebyDocument(const rapidjson::Document &dom, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher)
{
    try {
        if (!dom.HasMember("CustomRule") || !dom["CustomRule"].IsString()) 
        {
            LoggerRecord::WriteLog(L"public_json_interface::ParseRulebyDocument CustomRule is not exist or not string", LogLevel::ERR);
            return false;
        }
        const std::string& CustomRule = dom["CustomRule"].GetString();
        rapidjson::Document dom_rule;
        if (!dom_rule.Parse(CustomRule.c_str()).HasParseError()) {
            const std::string& result = dom_rule["result"].GetString();
            if (result == "success") {
                if (dom_rule.HasMember("data")) {
                    const rapidjson::Value& temp_data = dom_rule["data"];
                    if (temp_data.HasMember("CustomRule") && temp_data["CustomRule"].IsArray()) {
                        const rapidjson::Value& arr = temp_data["CustomRule"];
                        for (int i = 0; i < arr.Size(); ++i) {
                            SRule srule;
                            EventIdentifier EventID;
                            const rapidjson::Value& tmp = arr[i];
                            if (tmp.HasMember("ID") && tmp["ID"].IsInt()) {
                                srule.rule_id = tmp["ID"].GetInt();
                            }
                            if (tmp.HasMember("EVENT_ID") && tmp["EVENT_ID"].IsString()) {
                                auto eventID = tmp["EVENT_ID"].GetString();
                                STRING_VECTOR sig_vector;
                                StringUtil::split(eventID, '_', sig_vector);
                                if (sig_vector.size() != 2) {
                                    continue;
                                }

                                EventID = EventIdentifier(strtoul(sig_vector[0].c_str(), NULL, 0), atoi(sig_vector[1].c_str()));
                            }                        
                            if (tmp.HasMember("TTP") && tmp["TTP"].IsInt()) {
                                srule.TTP = tmp["TTP"].GetInt();
                            }
                            if (tmp.HasMember("ATTRIBUTES") && tmp["ATTRIBUTES"].IsArray()) {
                                const rapidjson::Value& arrAtt = tmp["ATTRIBUTES"];
                                for (int i = 0; i < arrAtt.Size(); ++i) {
                                    SAttrributes sattrributes;
                                    std::string eventID;
                                    const rapidjson::Value& vAtt = arrAtt[i];
                                    if (vAtt.HasMember("FIELD") && vAtt["FIELD"].IsString()) {
                                        sattrributes.Field = vAtt["FIELD"].GetString();
                                    }
                                    if (vAtt.HasMember("TARGET") && vAtt["TARGET"].IsString()) {
                                        sattrributes.Target = vAtt["TARGET"].GetString();
                                    }
                                    if (vAtt.HasMember("MATCH") && vAtt["MATCH"].IsString()) {
                                        sattrributes.Match = atoi(vAtt["MATCH"].GetString());
                                    }
                                    srule.Attrributes.insert(sattrributes);
//                                     LoggerRecord::WriteLog(L"ParseRulebyDocument add FIELD: " + ToolFunctions::StringToWString(sattrributes.Field)+
//                                         L" TARGET: " + ToolFunctions::StringToWString(sattrributes.Target),INFO);
                                }
                            }
                            rule_matcher[EventID].insert(srule);
                            LoggerRecord::WriteLog(L"ParseRulebyDocument add rule:" + std::to_wstring(srule.rule_id), DEBUG);
                        }
                    }
                }
            }
        }
    }
    catch (...) {
        LoggerRecord::WriteLog(L"ParseRulebyDocument catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return false;
    }
    return true;
}

bool public_json_interface::ParseRulebyStr(String strContent, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher)
{
    try
    {
        rapidjson::Document dom;
        if (!dom.Parse(strContent.c_str()).HasParseError()) {
            if (dom.HasMember("CustomRule") && dom["CustomRule"].IsArray()) {
                const rapidjson::Value& arr = dom["CustomRule"];
                for (int i = 0; i < arr.Size(); ++i) {
                    SRule srule;
                    EventIdentifier EventID;
                    const rapidjson::Value& tmp = arr[i];
                    if (tmp.HasMember("ID") && tmp["ID"].IsInt()) {
                        srule.rule_id = tmp["ID"].GetInt();
                    }
                    if (tmp.HasMember("EVENT_ID") && tmp["EVENT_ID"].IsString()) {
                        auto eventID = tmp["EVENT_ID"].GetString();
                        STRING_VECTOR sig_vector;
                        StringUtil::split(eventID, '_', sig_vector);
                        if (sig_vector.size() != 2) {
                            continue;
                        }

                        EventID = EventIdentifier(strtoul(sig_vector[0].c_str(), NULL, 0), atoi(sig_vector[1].c_str()));
                    }
                    //                 if (tmp.HasMember("Description") && tmp["Description"].IsString()) {
                    //                     srule.Description = tmp["Description"].GetString();
                    //                 }
                    if (tmp.HasMember("TTP") && tmp["TTP"].IsInt()) {
                        srule.TTP = tmp["TTP"].GetInt();
                    }
                    if (tmp.HasMember("ATTRIBUTES") && tmp["ATTRIBUTES"].IsArray()) {
                        const rapidjson::Value& arrAtt = tmp["ATTRIBUTES"];
                        for (int i = 0; i < arrAtt.Size(); ++i) {
                            SAttrributes sattrributes;
                            std::string eventID;
                            const rapidjson::Value& vAtt = arrAtt[i];
                            if (vAtt.HasMember("FIELD") && vAtt["FIELD"].IsString()) {
                                sattrributes.Field = vAtt["FIELD"].GetString();
                            }
                            if (vAtt.HasMember("TARGET") && vAtt["TARGET"].IsString()) {
                                sattrributes.Target = vAtt["TARGET"].GetString();
                            }
                            if (vAtt.HasMember("MATCH") && vAtt["MATCH"].IsInt()) {
                                sattrributes.Match = vAtt["MATCH"].GetInt();
                            }
                            srule.Attrributes.insert(sattrributes);
                        }
                    }
                    rule_matcher[EventID].insert(srule);
                }
            }
        }
    }
    catch (...)
    {
        LoggerRecord::WriteLog(L"ParseRulebyStr catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return false;
    }
    return true;
}

bool public_json_interface::ParseRulebyFile(String fileName, std::unordered_map<EventIdentifier, std::set<SRule>>& rule_matcher)
{
    try {
        std::ifstream in(fileName);
        if (!in.is_open()) {
            LoggerRecord::WriteLog(L"ParseRulebyFile open file failed,error:" + std::to_wstring(GetLastError()), ERR);
            return false;
        }
        std::string json_content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        return ParseRulebyStr(json_content, rule_matcher);
    }
    catch (...) {
        LoggerRecord::WriteLog(L"ParseRulebyFile catch exception,error:" + std::to_wstring(GetLastError()), ERR);
        return false;
    }
    return true;
}

wstring public_json_interface::GetEventArguments(EventRecord * rec)
{
    if (!rec)	return L"";

    rapidjson::Document record_document;
    rapidjson::Document::AllocatorType& doc_allocator = record_document.GetAllocator();
    rapidjson::Value rec_doc_root(rapidjson::kObjectType);

    for (int i = 0; i < rec->parameter_list_.size(); i++) {
        const char* parm_name;
        parm_name = json_parameter_name_list[EventRecordManager::GetInstance().event_strucp_map[rec->event_identifier_][i].name];
        String parameter_name(parm_name);
        if (g_parameter_string.find(parameter_name) != g_parameter_string.end())
        {
            String parm;
            parm = ToolFunctions::WStringToString(rec->parameter_list_[i].s);
            rapidjson::Value str_val;
            str_val.SetString(parm.c_str(), (rapidjson::SizeType)parm.length(), doc_allocator);
            rec_doc_root.AddMember(
                rapidjson::StringRef(parm_name),
                str_val,
                doc_allocator);
        }
        else {
            rec_doc_root.AddMember(rapidjson::StringRef(parm_name), rec->parameter_list_[i].d, doc_allocator);
        }
    }      

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    rec_doc_root.Accept(writer);

    return ToolFunctions::StringToWString(buffer.GetString());
}

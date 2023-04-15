#pragma once
#include "event_identifier.h"
#include "event_record.h"
#include "publicstruct.h"

class rule_matcher 
{
    SINGLETON_DEFINITION(rule_matcher);

private:
    rule_matcher();
    virtual ~rule_matcher();
public:
    void add_rule_map_by_file(std::string fileName);
    void add_rule_map_by_string(std::string strContent);
    void add_rule_map(EventIdentifier EventID, SRule srule);
    void delete_rule_map(EventIdentifier EventID);
    void update_rule_map(std::unordered_map<EventIdentifier, std::set<SRule>> rule);
    bool exist_rule(EventIdentifier eventID);
    //bool get_rule_by_eventid(EventIdentifier eventID, SRule &srule);
    bool event_rule_matcher(EventRecord* ev, SRule &srule);
    bool attrributes_rule_matcher(EventRecord * ev, SAttrributes sattrributes);
private:
    mutable RwLock _rule_lock;
    static std::unordered_map<EventIdentifier, std::set<SRule>> _rule_matcher;
    ParameterIndex base_parameter_index;
};


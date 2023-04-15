/********************************************************************
	Created:		2019-01-02
	Author:			chips;
	Version:		1.0.0(version);
	Description:	init project setting;
----------------------------------------------------------------------------
                                                                            
----------------------------------------------------------------------------
  Remark         :			                                                
----------------------------------------------------------------------------
  Change History :                                                          
  <Date>     | <Version> | <Author>       | <Description>                   
----------------------------------------------------------------------------
  2018/01/02 |	1.0.0	 |	chips		  | Create file                     
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#include <boost/program_options.hpp>

using namespace std;
using namespace boost::program_options;

class Setting
{
	SINGLETON_DEFINITION(Setting);

public:
	void Init(int argc, char* argv[]);

private:
	Setting(void) {};
	~Setting(void) {};

private:
	DEFINE_PROPERTY_READONLY(char, collector_mode);
	DEFINE_PROPERTY_REF_READONLY(String, verification);
	DEFINE_PROPERTY_REF_READONLY(String, kafka_address);
	DEFINE_PROPERTY_REF_READONLY(String, kafka_topic);
	DEFINE_PROPERTY_REF_READONLY(int_32, cs_process_id);
	DEFINE_PROPERTY_READONLY(int_32, kafka_partition);
	DEFINE_PROPERTY_REF_READONLY(String, format_file);
	DEFINE_PROPERTY_REF_READONLY(String, output_mode);
	DEFINE_PROPERTY_READONLY(bool, optimize_api_parse);
	DEFINE_PROPERTY_READONLY(bool, local_detector_parse);
	DEFINE_PROPERTY_REF_READONLY(String, local_detector_mode);
	DEFINE_PROPERTY_READONLY(int_32, visible_window_task_interval);
	DEFINE_PROPERTY_REF_READONLY(String, offline_log_file);
	DEFINE_PROPERTY_REF_READONLY(String, offline_dll_rva_folder);
	DEFINE_PROPERTY_REF_READONLY(String, offline_drive_map_file);
	DEFINE_PROPERTY_REF_READONLY(String, offline_process_filter_mode);
	DEFINE_PROPERTY_REF_READONLY(String, offline_output_whitelist_process_id);
	DEFINE_PROPERTY_READONLY(bool, enable_maximum_dump);
	DEFINE_PROPERTY_READONLY(bool, enable_performace_monitor);
	DEFINE_PROPERTY_READONLY(int_32, collector_init_gear);
	DEFINE_PROPERTY_READONLY(bool, enable_gear_adjustment);
	DEFINE_PROPERTY_READONLY(bool, enable_hardware_adjustment);
	DEFINE_PROPERTY_REF_READONLY(String, autorun_info_file_simplified);
	DEFINE_PROPERTY_REF_READONLY(String, autorun_info_file_full);
	// add by zxw on 20191111
	DEFINE_PROPERTY_READONLY(bool, enable_ransom_detector);
    // add by zxw on 20200409
    DEFINE_PROPERTY_READONLY(bool, enable_honey_pot);
    // add by zxw on 20200409
    DEFINE_PROPERTY_READONLY(bool, enable_ransom_output);  
    // add by zxw on 20200519
    DEFINE_PROPERTY_READONLY(bool, enable_debug_output); 
	// add by zxw on 20200811
    DEFINE_PROPERTY_READONLY(bool, enable_pruner_output);	
    // add by zxw on 20200909
    DEFINE_PROPERTY_REF_READONLY(String, kafka_user_name);
    DEFINE_PROPERTY_REF_READONLY(String, kafka_password);
    // add by zxw on 20201020
    DEFINE_PROPERTY_READONLY(bool, enable_rule_match);

	DEFINE_PROPERTY_READONLY(bool, enable_powershell_detector);
};
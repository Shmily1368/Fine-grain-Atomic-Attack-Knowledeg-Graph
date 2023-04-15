#include "stdafx.h"
#include "unit.h"
#include "event.h"
#include "processTree.h"
#include "feature.h"
#include <unordered_map>
#include <fstream>
#include "event_record.h"
#include "event_record_manager.h"
#include "tool_functions.h"
#include "init_collector.h"
#include "setting.h"
#include "filter.h"

extern vector<pprocess> processUnitTree;
string scalemain(const char * restore_filename, string input);
string predictmain(const char * load_model, string input);
//string range_path = "data\\features.all-etw.range";
//string model_path = "data\\features.all-etw.model";
string range_path_overwrite = "data\\features.all-etw-overwrite.range";
string model_path_overwrite = "data\\features.all-etw-overwrite.model";
string range_path_irp2 = "data\\features.all-etw-irp2.range";
string model_path_irp2 = "data\\features.all-etw-irp2.model";
string range_path_irp3 = "data\\features.all-etw-irp3.range";
string model_path_irp3 = "data\\features.all-etw-irp3.model";
string output_path = "output\\output.out";
string all_path = "output\\allfeature.out";

void makeFeature(pprocess Process, feature& Feature) {    //do the making feature work

	for (vector<unit>::iterator iter = Process->units.begin(); iter != Process->units.end();)
	{
		punit unit = &(*iter);                              		
		Feature.update_timestamp(unit);
		Feature.update_file_type(unit);
		Feature.update_action_path_i(unit);
		Feature.cal_access_frequency(unit);
		Feature.update_file_size_change(unit);
		Feature.cal_system_call(unit);
		Feature.update_file_magic_number_change(unit);
		Feature.update_file_similarity(unit);

		iter = Process->units.erase(iter);
	}
	Feature.cal_fraction();
	Feature.cal_irp_sequence();
	Feature.update_api(Process->apis);   //do the api feature work and irp work
	vector<string>().swap(Process->apis); // clear apis
}
void testFeature(feature& Feature) {        //call svm and do the detect work
	string range[3] = { range_path_overwrite , range_path_irp3 , range_path_irp2 };
	string model[3] = { model_path_overwrite , model_path_irp3 , model_path_irp2 };
	for (int i = 0; i < 3; i++) {
		string sp = scalemain(range[i].c_str(), Feature.toString());
		sp = predictmain(model[i].c_str(), sp);
		if (sp == "1") {
			//Get result and send 
			EventRecord* event_record = EventRecordManager::GetInstance().ParseRansomDetectorEvent(Feature.pid, Feature.ppid, ToolFunctions::StringToWString(Feature.process_name),
				ToolFunctions::StringToWString(Feature.pprocess_name), ToolFunctions::StringToWString(Feature.toString()));
			if (event_record)
			{
				LoggerRecord::WriteLog(L"testFeature detect feature: " + ToolFunctions::StringToWString(Feature.process_name), LogLevel::INFO);
				InitCollector::GetCollector()->PushSendRecord(event_record);
                // add by zxw on 20210513
                if (Filter::GetInstance().GetRansomTerminate() == 1)
                {
                    ToolFunctions::KillProcess(Feature.pid);
                }
                //
			}
            // add by zxw on 20200409
            if (Setting::GetInstance().enable_ransom_output())
            {
                ofstream write(output_path, ios::app);
                write << "pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << " testname: " << i << endl;
                write << Feature.toString() << endl;
                write.close();
            }

			break;
		}
	}
    // add by zxw on 20200409
    if (Setting::GetInstance().enable_ransom_output())
    {
        ofstream write(all_path, ios::app);
        write << "pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << endl;
        write << Feature.toString() << endl;
        write.close();
    }
}
void getUnits(){                           // get the units, create features and clear the units.
	vector<feature> FeatureList;
	for (vector<pprocess>::iterator iter = processUnitTree.begin(); iter != processUnitTree.end();)
	{
		pprocess Process = *iter;
		if (Process->units.size() != 0) {
			feature newfeature(Process->pid, Process->path); 
			newfeature.ppid = Process->parentPid;
			newfeature.pprocess_name = Process->parentName;
			makeFeature(Process, newfeature);
			FeatureList.push_back(newfeature);
			iter++;
		}
		else if (Process->units.size() == 0 && Process->isalive == false) {
			delete Process;
			iter = processUnitTree.erase(iter);
		}
		else {
			iter++;
		}
	}
	for (vector<feature>::iterator iter = FeatureList.begin(); iter != FeatureList.end();)
	{
		testFeature(*iter);
		iter = FeatureList.erase(iter);
	}
    // add by zxw on 20200409
    if (Setting::GetInstance().enable_ransom_output())
    {
        ofstream write(all_path, ios::app);
        write << endl;
        write.close();
    }

}
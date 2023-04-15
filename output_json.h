#pragma once
#include "event_record.h"
#include "etwdata.pb.h"
#include "output.h"
#include <fstream>
#include <stdio.h>

using namespace ETWproto;
using namespace std;

#define OUTPUT_JSON_REPEAT_TIMES 10000

class OutputJson : public Output
{
public:
	OutputJson();
	~OutputJson();
	virtual bool OutputEventRecord(EventRecord* rec) override;
	virtual void DataCompress(EventRecords* rec, String* data_str) override { }	
	virtual void Clean() 
	{
		fprintf(outfile, "%s\n", rec_json.c_str());
		rec_json.clear();
	};

private:
	FILE* outfile;
	String rec_json;
	unsigned int output_event_sum = 0;
	unsigned long long currentprocessevent = 0;
};


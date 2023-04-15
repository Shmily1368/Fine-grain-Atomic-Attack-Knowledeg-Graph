/********************************************************************
	Created:		2019-04-11
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task for read pipe;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/04/11 |	1.0.0	 |	xuduo		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#include "thread_task_base.h"
#include "json_include/rapidjson/document.h"

using PipeProcessCallback = std::function<void(const rapidjson::Document& in_data, rapidjson::Document& reply)>;
struct PipeProcessCallbackConfig
{
	PipeProcessCallbackConfig(PipeProcessCallback cb_t, bool sync_t) : cb(cb_t), sync(sync_t) { }
	PipeProcessCallback cb;
	bool sync;
};
using PipeProcessCallbackConfigMap = std::map<String, PipeProcessCallbackConfig>;

class PipeReadThreadTask : public BaseThreadTask
{
public:
	PipeReadThreadTask();
	~PipeReadThreadTask();

	virtual void Log() override;
	virtual void Init() override;

private:
	virtual void _Excute();
	void _Process(const rapidjson::Document& in_data) const;

	//TODO move out;
	void _ProcessHealthCheck(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessInitTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessAddTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessRemoveTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessChangeTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessChangeGear(const rapidjson::Document& in_data, rapidjson::Document& reply);
	void _ProcessParseAutorun(const rapidjson::Document& in_data, rapidjson::Document& reply);
	// add by zxw on 20191030 update local ip
	void _ProcessUpdateClientIP(const rapidjson::Document& in_data, rapidjson::Document& reply);
	// add by zxw on 20191206 ransom suffix white list
	void _ProcessRansomSuffixWhiteList(const rapidjson::Document& in_data, rapidjson::Document& reply);
    // add by zxw on 20201019
    void _ProcessUpdateCustomRule(const rapidjson::Document& in_data, rapidjson::Document& reply);
    void _ProcessRuleMatchSwitch(const rapidjson::Document& in_data, rapidjson::Document& reply);
    // add by zxw on 20210508
    void _ProcessCertificateList(const rapidjson::Document& in_data, rapidjson::Document& reply);
    
private:
	PipeProcessCallbackConfigMap _process_callback_map;
};
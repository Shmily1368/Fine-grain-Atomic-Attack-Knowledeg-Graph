//#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include "RansomDetector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "CJsonObject.hpp"
#include "unit.h"
#include "processTree.h"
#include "feature.h"
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <mutex>
#include <condition_variable>

//#include <boost/chrono/duration.hpp>
//#include <boost/thread/thread.hpp>
//#pragma comment(lib, "ws2_32.lib")  

#define DEFAULT_BUFFER 100000 /*缓冲区大小*/
//std::mutex event_lock;//多线程标准输出同步锁


string scalemain(const char * restore_filename, string input);
string predictmain(const char * load_model, string input);
void getUnits();
void processEvent(event& singleEvent);
extern unordered_map<int, pprocess> processTree;
extern vector<pprocess> processUnitTree;
extern unordered_map<string, vector<string>> fileMap;
int testwindow = 1 * 5;

RansomDetector::RansomDetector() 
{
	
}


RansomDetector::~RansomDetector()
{

}


void InitItemRepository(ItemRepository *ir)
{
	ir->write_position = 0; // 初始化产品写入位置.
	ir->read_position = 0; // 初始化产品读取位置.
}

int RansomDetector::Init(void)
{
	InitItemRepository(&gItemRepository);
	//std::thread producer(&RansomDetector::ProducerTask,this); // 创建生产event线程，之后可以直接用压入替换
	std::thread consumer(&RansomDetector::ConsumerTask,this); // 创建消费event,产生unit之线程.
	//producer.detach();
	consumer.detach();
    int countes = 0;
	while (1) {
		std::this_thread::sleep_for(std::chrono::seconds(testwindow));
		{
			{
				std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
				cout << "live process num:" << processTree.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
			}

			std::unique_lock<std::mutex> lock_unit(unit_lock);
			getUnits();                 //主线程定时将unit转为feature，并进行检测
			lock_unit.unlock();

			{
				std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
				cout << "process num:" << processUnitTree.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
			}
            countes++;
            if (countes % 10 == 0)
            {
                countes = 0;
                LoggerRecord::WriteLog(L"RansomDetector live process num:" + std::to_wstring(processTree.size()) +
                    L" process num:" + std::to_wstring(processUnitTree.size()) +
                    L" fileMap num:" + std::to_wstring(fileMap.size()), LogLevel::INFO);
#ifdef OUTPUT_COMMAND_LINE 
                int_64 sum_size = 0;
                for (auto i = fileMap.begin(); i != fileMap.end(); i++)
                {
                    sum_size += (i->first.capacity() + 28);
                    for (auto j = i->second.begin(); j != i->second.end(); j++)
                        sum_size += ((*j).capacity() + 28);
                }
                sum_size = sum_size / 1024;
                string temp = "fileMap num sum_size memory: " + std::to_string(sum_size) + "KB";
                cout << temp.c_str() << endl;
                LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp), LogLevel::INFO);
#endif // OUTPUT_COMMAND_LINE;
            }
		}
	}
}


void ProduceItem(ItemRepository * ir, string item)
{
	std::unique_lock<std::mutex> lock(ir->event_mtx); // item buffer is full, just wait here.
	while (((ir->write_position + 1) % ITEMREPOSITORYSIZE) == ir->read_position) {
		(ir->repo_not_full).wait(lock);
	}

	(ir->event_buffer)[ir->write_position] = event(item);

	(ir->write_position)++;                        // 写入位置后移.

	if (ir->write_position == ITEMREPOSITORYSIZE) // 写入位置若是在队列最后则重新设置为初始位置.
		ir->write_position = 0;

	(ir->repo_not_empty).notify_all();             // 通知消费者产品库不为空.
	lock.unlock();                                 // 解锁.
}
void RansomDetector::PushRansomRecord(String &input) {
	ProduceItem(&gItemRepository, input);
	_push_count++;
	if (_push_count % 100000 == 0) {
		std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "producer: " << _push_count << endl;
#endif // OUTPUT_COMMAND_LINE;
	}
}
// add by zxw on 20191114
void ProduceItem(ItemRepository * ir, event item)
{
    // add 20191218 wate one microseconds；
    //boost::this_thread::sleep_for(boost::chrono::microseconds(1));
	std::unique_lock<std::mutex> lock(ir->event_mtx); // item buffer is full, just wait here.
	while (((ir->write_position + 1) % ITEMREPOSITORYSIZE) == ir->read_position) {
		(ir->repo_not_full).wait(lock);
	}

	(ir->event_buffer)[ir->write_position] = item;

	(ir->write_position)++;                        // 写入位置后移.

	if (ir->write_position == ITEMREPOSITORYSIZE) // 写入位置若是在队列最后则重新设置为初始位置.
		ir->write_position = 0;

	(ir->repo_not_empty).notify_all();             // 通知消费者产品库不为空.
	lock.unlock();                                 // 解锁.
}
// add by zxw on 20191114
void RansomDetector::PushRansomRecord(event item) {
	ProduceItem(&gItemRepository, item);
	
	_push_count++;
	if (_push_count % 100000 == 0) {
		std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "producer: " << _push_count << endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"PushRansomRecord producer: " + std::to_wstring(_push_count), LogLevel::INFO);
	}
}


//void SplitString(const string& srcStr, vector<string>& vec, const string& separator)
//{
//
//	string::size_type posSubstringStart; // 子串开始位置
//
//	string::size_type posSeparator;        //  分隔符位置
//
//	posSeparator = srcStr.find(separator);
//	posSubstringStart = 0;
//	while (string::npos != posSeparator) {
//		vec.push_back(srcStr.substr(posSubstringStart, posSeparator - posSubstringStart));
//
//		posSubstringStart = posSeparator + separator.size();
//		posSeparator = srcStr.find(separator, posSubstringStart);
//	}
//
//	if (posSubstringStart != srcStr.length())  // 截取最后一段数据
//		vec.push_back(srcStr.substr(posSubstringStart));
//}



void RansomDetector::ConsumeItem(ItemRepository *ir)
{
	event data;
	std::unique_lock<std::mutex> lock(ir->event_mtx);   // item buffer is empty, just wait here.
	while (ir->write_position == ir->read_position)
	{
		(ir->repo_not_empty).wait(lock);
	}

	data = (ir->event_buffer)[ir->read_position]; // 读取某一产品
	{
		std::unique_lock<std::mutex> lock_unit(unit_lock);
		processEvent(data);
		lock_unit.unlock();                                 // 解锁.
	}

	(ir->read_position)++;                        // 读取位置后移

	if (ir->read_position >= ITEMREPOSITORYSIZE) // 读取位置若移到最后，则重新置位.
		ir->read_position = 0;

	(ir->repo_not_full).notify_all();             // 通知消费者产品库不为满.
	lock.unlock();                                // 解锁.
}


//void RansomDetector::ProducerTask()
//{
//	stringstream str1;
//	string str;
//	event x;
//	int j = 0;
//	WSADATA wsd;
//	SOCKET sListen, sClient;
//	int AddrSize;
//	unsigned short port;
//	struct sockaddr_in local, client;
//	char Buffer[DEFAULT_BUFFER];
//	int ret;
//	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
//		printf("WinSock init fail!\n");
//		return;
//	}
//	sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); //创建Socket
//	if (sListen == SOCKET_ERROR) {
//		printf("socket() fail: %d\n", WSAGetLastError());
//		WSACleanup();
//		return;
//	}
//
//	std::string ip = "127.0.0.1";
//	local.sin_family = AF_INET;
//	local.sin_addr.s_addr = inet_addr(ip.c_str());
//	port = 6666;                                         //获取端口值
//	local.sin_port = htons(port);
//
//	if (SOCKET_ERROR == ::bind(sListen, (struct sockaddr*)&local, sizeof(local))) {
//		printf("bind() fail: %d\n", WSAGetLastError());     	//绑定Socket
//		closesocket(sListen);
//		WSACleanup();
//		return;
//	}
//	listen(sListen, 8);                                   //打开监听
//	printf("listen\n");
//	while (1) {
//		AddrSize = sizeof(client);                           //监听是否有连接请求
//		sClient = accept(sListen, (struct sockaddr*)&client, &AddrSize);
//		if (sClient == INVALID_SOCKET) {
//			printf("accept() fail: %d\n", WSAGetLastError());
//			closesocket(sListen);
//			WSACleanup();
//			return;
//		}
//		printf("accept\n");
//		while (1) {
//			ret = recv(sClient, Buffer, DEFAULT_BUFFER - 1, 0);
//			if (ret == 0) {
//				break;
//			}
//			else if (ret == SOCKET_ERROR) {
//				printf("recv() fail: %d\n", WSAGetLastError());
//				break;
//			}
//			else {
//				Buffer[ret] = '\0';
//				str = Buffer;
//				if (str.size() != 0) {
//					vector<string> vec;
//					SplitString(str, vec, "\n");
//					for (int i = 0; i < vec.size(); i++) {
//						ProduceItem(&gItemRepository, vec[i]);
//						j++;
//						if (j % 100000 == 0) {
//							std::lock_guard<std::mutex> lock(out_lock);
//							cout << "producer: " << j << endl;
//						}
//					}
//				}
//			}
//		}
//
//	}
//	closesocket(sListen);
//	WSACleanup();
//}

void RansomDetector::ConsumerTask()
{
	int j = 0;
	while (1)
	{
        // add 20191218 wate one microseconds；
        //boost::this_thread::sleep_for(boost::chrono::nanoseconds(100));
		ConsumeItem(&gItemRepository);
		j++;
		if (j % 100000 == 0) {
			std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
			cout << "consumer: " << j << endl;
#endif // OUTPUT_COMMAND_LINE;
			LoggerRecord::WriteLog(L"ConsumerTask consumer: " + std::to_wstring(j), LogLevel::INFO);
		}
	}
}



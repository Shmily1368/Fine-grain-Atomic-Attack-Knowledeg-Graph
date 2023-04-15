#pragma once
//#include"../stdafx.h"
#include <stdio.h>
#include <io.h>
#include <string.h>
#include <direct.h>
#include<string>
class file_deal
{

public:
	/*
	函数入口：文件夹的绝对路径
			  const char*  dirPath
	函数功能：删除该文件夹，包括其中所有的文件和文件夹
	返回值：  0  删除
			 -1  路径不对，或其它情况，没有执行删除操作
	*/
	static int  removeDir(const char* dirPath);
	static int hasDir(std::string dirpath);
	static int hasFile(std::string dirpath);
	//-1 表示写文件失败 0表示成功
	static int writeTofile(std::string filepath, std::string& content);
	//-1 表示写文件失败 0表示成功
	static int readFromFile(std::string filepath, std::string& content);
	static int removeFile(std::string filepath);

};


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
	������ڣ��ļ��еľ���·��
			  const char*  dirPath
	�������ܣ�ɾ�����ļ��У������������е��ļ����ļ���
	����ֵ��  0  ɾ��
			 -1  ·�����ԣ������������û��ִ��ɾ������
	*/
	static int  removeDir(const char* dirPath);
	static int hasDir(std::string dirpath);
	static int hasFile(std::string dirpath);
	//-1 ��ʾд�ļ�ʧ�� 0��ʾ�ɹ�
	static int writeTofile(std::string filepath, std::string& content);
	//-1 ��ʾд�ļ�ʧ�� 0��ʾ�ɹ�
	static int readFromFile(std::string filepath, std::string& content);
	static int removeFile(std::string filepath);

};


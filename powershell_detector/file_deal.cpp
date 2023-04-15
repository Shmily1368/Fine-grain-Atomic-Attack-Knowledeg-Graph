//#include"stdafx.h"
#include "file_deal.h"
#include<fstream>
int  file_deal::removeDir(const char* dirPath)
{

	struct _finddata_t fb;   //������ͬ�����ļ��Ĵ洢�ṹ��
	char  path[250];
	intptr_t    handle;
	int  resultone;
	int   noFile;            //��ϵͳ�����ļ��Ĵ�����

	noFile = 0;
	handle = 0;


	//����·��
	strcpy(path, dirPath);
	strcat(path, "/*");

	handle = _findfirst(path, &fb);
	//�ҵ���һ��ƥ����ļ�
	if (handle != 0&&handle!=-1)
	{
		//�����Լ����ҵ�ƥ����ļ�������ִ��
		while (0 == _findnext(handle, &fb))
		{
			//windows�£����и�ϵͳ�ļ�����Ϊ��..��,������������
			noFile = strcmp(fb.name, "..");

			if (0 != noFile)
			{
				//��������·��
				memset(path, 0, sizeof(path));
				strcpy(path, dirPath);
				strcat(path, "/");
				strcat(path, fb.name);
				//����ֵΪ16����˵�����ļ��У�����
				if (fb.attrib == 16)
				{
					removeDir(path);
				}
				//���ļ��е��ļ���ֱ��ɾ�������ļ�����ֵ�����û����ϸ���飬���ܻ������������
				else
				{
					remove(path);
				}
			}
		}
		//�ر��ļ��У�ֻ�йر��˲���ɾ����������������˺ܾã���׼c���õ���closedir
		//������ܣ�һ�����Handle�ĺ���ִ�к󣬶�Ҫ���йرյĶ�����
		_findclose(handle);
	}
	else if (handle == -1) {
		return -1;
	}
	//�Ƴ��ļ���
	resultone = _rmdir(dirPath);
	return  resultone;
}
int file_deal::hasDir(std::string dirpath) {
	return _access(dirpath.c_str(), 0)==0;
}
int file_deal::hasFile(std::string dirpath) {
	return _access(dirpath.c_str(), 0);
}
int file_deal::writeTofile(std::string filepath, std::string& content) {
	std::ofstream ofile(filepath);
	if (!ofile) {
		return -1;
	}
	ofile << content;
	ofile.close();
	return 0;
}
int file_deal::readFromFile(std::string filepath, std::string& content) {
	std::ifstream ifile(filepath);
	if (!ifile) {
		return -1;
	}
	ifile >> content;
	ifile.close();
	return 0;
}
int removeFile(std::string filepath) {
	return remove(filepath.c_str());
}
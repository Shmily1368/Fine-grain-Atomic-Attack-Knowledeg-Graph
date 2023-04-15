//#include"stdafx.h"
#include "file_deal.h"
#include<fstream>
int  file_deal::removeDir(const char* dirPath)
{

	struct _finddata_t fb;   //查找相同属性文件的存储结构体
	char  path[250];
	intptr_t    handle;
	int  resultone;
	int   noFile;            //对系统隐藏文件的处理标记

	noFile = 0;
	handle = 0;


	//制作路径
	strcpy(path, dirPath);
	strcat(path, "/*");

	handle = _findfirst(path, &fb);
	//找到第一个匹配的文件
	if (handle != 0&&handle!=-1)
	{
		//当可以继续找到匹配的文件，继续执行
		while (0 == _findnext(handle, &fb))
		{
			//windows下，常有个系统文件，名为“..”,对它不做处理
			noFile = strcmp(fb.name, "..");

			if (0 != noFile)
			{
				//制作完整路径
				memset(path, 0, sizeof(path));
				strcpy(path, dirPath);
				strcat(path, "/");
				strcat(path, fb.name);
				//属性值为16，则说明是文件夹，迭代
				if (fb.attrib == 16)
				{
					removeDir(path);
				}
				//非文件夹的文件，直接删除。对文件属性值的情况没做详细调查，可能还有其他情况。
				else
				{
					remove(path);
				}
			}
		}
		//关闭文件夹，只有关闭了才能删除。找这个函数找了很久，标准c中用的是closedir
		//经验介绍：一般产生Handle的函数执行后，都要进行关闭的动作。
		_findclose(handle);
	}
	else if (handle == -1) {
		return -1;
	}
	//移除文件夹
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
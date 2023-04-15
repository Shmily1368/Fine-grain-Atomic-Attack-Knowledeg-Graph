#pragma once
#include <iostream>
#include <vector>

class VbaParser
{
private:
	//Olefile olefile;
	std::vector<std::string> vbaFiles;
	std::vector<std::string> generatedVbaFiles;
	bool isZipFile(const std::string& filename);
	int isOleFile(const std::string& filename);
	bool isVbaCodeMalicious(std::string data);
	std::vector<std::string> openXml(std::string filename);
	std::vector<std::string> openWord2003Xml(std::string filename);
	std::vector<std::string> getVbaFiles(std::vector<std::string> &filepaths);
	std::vector<std::string> getVbaFilesUseSigtool(std::vector<std::string> &filepaths);
	std::vector<std::string> getVbaFilesUseDll(std::vector<std::string> &filepaths);
	std::vector<std::string> openMht(std::string filename);

public:
	VbaParser(const std::string& filename);
	bool isFileMalicious();
	void ListVbaFiles(std::vector<std::string>& file_list);
};

/********************************************************************
	Created:		2019-01-02
	Author:			chips;
	Version:		1.0.0(version);
	Description:	be used to as a synonym for the type denoted by type-id;
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

#include <iostream>
#include <string>
#include <vector>
#include <queue>
#include <deque>
#include <map>
#include <list>
#include <set>
#include <ctime>
#include <unordered_set>
#include <unordered_map>
using namespace std;

//base data type
using int_16 = short;
using uint_16 = unsigned short;
using int_32 = int;
using uint_32 = unsigned int;
using int_64 = long long;
using uint_64 = unsigned long long;
using String = std::string;

using LLONG = long long;
using ULONG = unsigned long;

//pair
using ULONG_LLONG_PAIR = pair<ULONG, LLONG>;

//vector
using STRING_VECTOR = vector<string>;
using LLONG_VECTOR = vector<LLONG>;
using STRING_VECTOR_VECTOR = vector<vector<string>>;

//map
using INT_WSTRING_MAP = std::map <int, std::wstring>;
using STRING_STRING_UMAP = std::unordered_map<std::string, std::string>;

//set
using STRING_SET = std::unordered_set<std::string>;

using StringList = std::list<String>;

//queue;
using Int32Queue = std::queue<int_32>;


#define EMPTY_STRING ""

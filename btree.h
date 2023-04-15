#pragma once

#include <assert.h>
#include <Windows.h>
#include "thread_task_manager.h"

class btree;

struct dllAddress
{
	ULONG64 ImageBase;
	ULONG64 ImageSize;
	std::string FileName;
	ULONG64 ImageEnd;
	btree* rva_tree;
	BOOLEAN Verification;
	BOOLEAN useless;
	dllAddress()
		: ImageBase(0)
		, ImageSize(0)
		, FileName("")
		, ImageEnd(0)
		, rva_tree(NULL)
		, useless(FALSE)
		, Verification(FALSE)
	{
		
	}
};

struct NodeAdress
{
	ULONG64 l;
	ULONG64 r;
	NodeAdress(ULONG64 temp_a, ULONG64 temp_b) : l(temp_a), r(temp_b) {}
	NodeAdress() {}
	bool operator< (const NodeAdress& a) const
	{
		if (this->r <= a.l) return true;
		return false;
	}
};

struct node
{
	dllAddress key_value;
	node(dllAddress temp) : key_value(temp)
	{
		OBJECT_MEMORY_MONITOR_CTOR(node);
	}
	node() 
	{
		OBJECT_MEMORY_MONITOR_CTOR(node);
	}
	~node()
	{
		OBJECT_MEMORY_MONITOR_DTOR(node);
	}
};

class LRUCache{
private:
	std::list< std::pair<ULONG64, node*> > item_list;
	std::unordered_map<ULONG64, std::list<std::pair<ULONG64, node*>>::iterator> item_map;
	size_t cache_size;
private:
	void clean(void){
		while (item_map.size()>cache_size){
			auto last_it = item_list.end(); last_it--;
			item_map.erase(last_it->first);
			item_list.pop_back();
		}
	};
public:
	LRUCache(int cache_size_) :cache_size(cache_size_){
		;
	};

	void put(ULONG64 key, node* val){
		auto it = item_map.find(key);
		if (it != item_map.end()){
			item_list.erase(it->second);
			item_map.erase(it);
		}
		item_list.push_front(std::make_pair(key, val));
		item_map.insert(std::make_pair(key, item_list.begin()));
		clean();
	};
	bool exist(const ULONG64 key){
		return (item_map.count(key)>0);
	};
	node* get(const ULONG64 key){
		assert(exist(key));
		auto it = item_map.find(key);
		item_list.splice(item_list.begin(), item_list, it->second);
		return it->second->second;
	};

};
class btree
{
public:
	btree();
	~btree();

	void insert(const dllAddress& key);
	void erase(const dllAddress& key);
	node *search(ULONG64 key);
	bool count(ULONG64& key) { return reb_black_tree_.count(std::move(NodeAdress(key, key))); }
	void destroy_tree();
	void print_tree();
	size_t Size() { return reb_black_tree_.size(); }

private:
	void destroy_tree(node *leaf);
	node *root;
	std::map<NodeAdress, node*> reb_black_tree_;
	long long size;
	LRUCache cache;
};
#include "stdafx.h"
#include "btree.h"

btree::btree() 
	: cache(500)
{
	root = NULL;
	size = 0;
}

btree::~btree()
{
	destroy_tree();
}

void btree::destroy_tree(node *leaf)
{
	for (auto iter = reb_black_tree_.begin(); iter != reb_black_tree_.end(); iter++) {
		delete iter->second;
		iter->second = NULL;
	}
	reb_black_tree_.clear();
	size = 0;
	std::map<NodeAdress, node*>().swap(reb_black_tree_);
}

void btree::insert(const dllAddress& key)
{
	node* node_t = new node(key);
	NodeAdress address_t = NodeAdress(key.ImageBase, key.ImageEnd);
	auto iter = reb_black_tree_.find(address_t);
	if (iter != reb_black_tree_.end())
	{
		SAFE_DELETE(iter->second);
		reb_black_tree_.erase(iter);
	}
	else
	{
		++size;
	}
	reb_black_tree_.insert(std::make_pair(address_t, node_t));
}

void btree::erase(const dllAddress& key)
{
	NodeAdress address_t = NodeAdress(key.ImageBase, key.ImageEnd);
	auto iter = reb_black_tree_.find(address_t);
	if (iter != reb_black_tree_.end())
	{
		SAFE_DELETE(iter->second);
		reb_black_tree_.erase(iter);
		--size;
	}
}

node *btree::search(ULONG64 key)
{
	//if (cache.exist(key))
	//	return cache.get(key);
	auto result = reb_black_tree_.find(std::move(NodeAdress(key,key)));
	if (result == reb_black_tree_.end()) return NULL;
	//cache.put(key,result->second);
	return result->second;
}

void btree::destroy_tree()
{
	destroy_tree(root);
}

void btree::print_tree()
{
	for (auto iter = reb_black_tree_.begin(); iter != reb_black_tree_.end(); iter++) 
	{
#ifdef OUTPUT_COMMAND_LINE
		std::cout << iter->second->key_value.FileName << endl;
#endif // OUTPUT_COMMAND_LINE;
	}
}

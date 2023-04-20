import tempfile

import os

import networkx
import networkx as nx
import matplotlib.pylab as plt
import pylab
import json
import sys
import matplotlib as mpl

sys.path.append("../")

from pygraphml import GraphMLParser
from pygraphml import Graph

# 根据节点内容和属性来做排序

# ProcessStart
# 读取 GML 文件
# G = networkx.DiGraph
# G = networkx.read_graphml(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\TechniqueRawDateGraph_ml\T1574.002-1_5416.gml',label="id")
# G = networkx.read_gml(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\TechniqueRawDateGraph_ml\T1219-10_10012.gml') #good
G = networkx.read_graphml(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\test\T1003.002-5_10416.test',edge_key_type=str) #good
# G = nx.read_gml(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\test\T1620-1_12152.txt.txt',label='id')
# label = G.graph["d0"]
# print(label)

# default_color = G.graph["edge_default"]["data"]
# for u, v, data in G.edges(data=True):
#     if "color" not in data:
#         data["color"] = default_color

edge = G.edges
print(edge)
for i in edge:
    # print(type(i))
    data = G.get_edge_data(i[0], i[1])
    # print(data)
    try:
        print(data['edge_label'])
    except:
        pass
os._exit(0)
    # print(data['tag'])
    # print(data['d0'])


print(type(G.edges))
# for i in G.edges:
#     print(i["tag"])
print(G)
print(f'Nodes: {G.nodes}')
print(f'Edges: {G.edges}')
nx.draw_networkx(G)
pylab.show()


os._exit(0)

for i in G.nodes:
    print(i)
    # print(nx.get_node_attributes())

sorted_nodes = list(nx.topological_sort(G))
print(sorted_nodes)


# 按照节点入度排序
in_degree_sorted_nodes = sorted(G.nodes(), key=G.in_degree)
print("按照节点入度排序的结果：", in_degree_sorted_nodes)

# 按照节点出度排序
out_degree_sorted_nodes = sorted(G.nodes(), key=G.out_degree)
print("按照节点出度排序的结果：", out_degree_sorted_nodes)

# 按照 PageRank 值排序
pagerank_sorted_nodes = sorted(G.nodes(), key=nx.pagerank(G).get)
print("按照 PageRank 值排序的结果：", pagerank_sorted_nodes)



# os._exit(0)

# for i in G:
#     print(i)
#     print("___")

print(G)
# print(G.edge_labels)
# print(not G)
# 输出图的节点和边信息
print(f'Nodes: {G.nodes}')
print(f'Edges: {G.edges}')
# networkx.draw_networkx(G)
# nx.draw_networkx_labels(G,pos = nx.spring_layout(G))
nx.draw_networkx(G)
pylab.show()

# flg, ax = plt.subplots()
# pos = nx.spring_layout(G)
# nx.draw_networkx_edge_labels(G, pos, edge_labels="label")



os._exit(0)
# os.exit(0)


# g = Graph()
#
# n1 = g.add_node("A")
# n2 = g.add_node("B")
# n3 = g.add_node("C")
# n4 = g.add_node("D")
# n5 = g.add_node("E")
#
# g.add_edge(n1, n3)
# g.add_edge(n2, n3)
# g.add_edge(n3, n4)
# g.add_edge(n3, n5)
#
# print(g)
# g.set_root(n1)
# nodes = g.BFS()
# for node in nodes:
#     print(node)
# g.show()

# fname = r"E:\MyData\AttackGraph\fine-grain\ARTDate\test\1.txt"
# parser = GraphMLParser()
# parser.write(g, fname)

# Visualize the GraphML file
# print(fname)
# with open(fname) as f:
#     print(f.read())
import gmatch4py as gm
fname = r"E:\MyData\AttackGraph\fine-grain\ARTDate\TechniqueRawDateGraph_ml\T1112-7.txt"
parser = GraphMLParser()
g = parser.parse(fname)

g.show()
# g = parser.parse(fname)
# G=nx.read_gml(fname,label='id')
# # G = nx.Graph(fname)
# nx.draw_networkx(G)
# print(G.edges())

# G = nx.parse_gml(fname)
# print(G)


# g.show()
# pos = nx.spring_layout(G)
# nx.draw(G, pos, with_labels=True, node_size=500, node_color='w', node_shape='.')
import tempfile
import os
import sys

sys.path.append("../")
import networkx as nx
from pygraphml import GraphMLParser
from pygraphml import Graph

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
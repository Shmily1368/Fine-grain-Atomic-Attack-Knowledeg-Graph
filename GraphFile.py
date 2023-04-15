import tempfile
import os
import sys

sys.path.append("../")

from pygraphml import GraphMLParser
from pygraphml import Graph

g = Graph()

n1 = g.add_node("A")
n2 = g.add_node("B")
n3 = g.add_node("C")
n4 = g.add_node("D")
n5 = g.add_node("E")

g.add_edge(n1, n3)
g.add_edge(n2, n3)
g.add_edge(n3, n4)
g.add_edge(n3, n5)

print(g)
g.set_root(n1)
nodes = g.BFS()
for node in nodes:
    print(node)
# g.show()

fname = r"E:\MyData\AttackGraph\fine-grain\ARTDate\test\1.txt"
parser = GraphMLParser()
parser.write(g, fname)

# Visualize the GraphML file
print(fname)
with open(fname) as f:
    print(f.read())

# # import matplotlib as mpl
# # import matplotlib.pyplot as plt
# # import networkx as nx
#
# # Gmatch4py use networkx graph
# import networkx as nx
# # import the GED using the munkres algorithm
# import gmatch4py as gm
#
#
# g1=nx.complete_bipartite_graph(5,4)
# g2=nx.complete_bipartite_graph(6,4)
#
# ged=gm.GraphEditDistance(1,1,1,1) # all edit costs are equal to 1
# result=ged.compare([g1,g2],None)
# print(result)
#
# ged.similarity(result)
# # or
# ged.distance(result)


import networkx as nx
# import gmatch4py as gm
# ged = gm.GraphEditDistance(1,1,1,1)
# result = ged.set_attr_graph_used("theme","color") # Edge colors and node themes attributes will be used.
# print(result)
#
# gm.VertexRanking(ged)



blackrule = open(".\\ARTDate\\Rule\\RegistryBlack-vmware.txt","a+")

blackrule.write("418A073AA3BC3475"+"\n")
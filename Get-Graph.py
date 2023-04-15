import networkx as nx
import matplotlib.pylab as plt
import pylab
import json





G = nx.DiGraph()
edge_labels = {}

num = 0
def get_graph(filemame):
    with open(filemame,"r",encoding="utf-8") as f:
        lines = f.readlines()
        lines = lines[:700]
        for line in lines:
            line = json.loads(line)
            processID = line["processID"]
            EventName = line["EventName"]
            temarguments = line["arguments"]
            temarguments_1 = temarguments
            if("Thread" in EventName):
                continue
            if(processID<=0):
                continue
            # 进程
            if("Process" in EventName):
                if "Start" in EventName:
                    G.add_edges_from([(processID,temarguments["ProcessId"])])
                    edge_labels[(processID,temarguments["ProcessId"])] = EventName
            # 镜像
            # if ("Image" in EventName):
            #     # if "ImageDCStart" in EventName:
            #     G.add_edges_from([(processID, temarguments["FileName"])])
            #     edge_labels[(processID, temarguments["FileName"])] = EventName
            # 文件
            if ("File" in EventName):
                G.add_edges_from([(processID, temarguments["FileName"])])
                edge_labels[(processID, temarguments["FileName"])] = EventName
            # 网络
            if ("IPV4" in EventName):
                if "Recv" in EventName:
                    G.add_edges_from([("IP Connected",processID)])
                    edge_labels[("IP Connected",processID)] = EventName
                else:
                    G.add_edges_from([(processID,"IP Connected")])
                    edge_labels[(processID,"IP Connected")] = EventName
            #注册表
            if("Registry" in EventName):
                G.add_edges_from([(processID, temarguments["KeyName"])])
                edge_labels[(processID, temarguments["KeyName"])] = EventName




            # if("ImageFileName" in temarguments.keys()):
            #     # temarguments = temarguments["ImageFileName"]
            #     if "ProcessId" in temarguments.keys():
            #         temarguments = temarguments["ProcessId"]
            # elif("FileName" in temarguments.keys()):
            #     temarguments = temarguments["FileName"]
            #     temarguments = temarguments.split("\\")[-1]
            #
            # elif("KeyName" in temarguments.keys()):
            #     temarguments = temarguments["KeyName"]
            #     temarguments = temarguments.split("\\")[-1]
            # else:
            #     continue
            # print(temarguments)
            # G.add_edges_from([(processID,temarguments)])
            # edge_labels[(processID,temarguments)] = EventName
            # print(line["processID"])


# get_graph(".\\test.txt")

if __name__=="__main__":
    #get_graph(".\\test.txt")
    # get_graph(".\\GraphTest.txt")
    get_graph(".\\test.out")
    #G.add_edges_from([("1","2")])
    #edge_labels[("1","2")] = "test"
    # print(G.edges)
    flg, ax = plt.subplots()
    pos = nx.spring_layout(G)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    nx.draw(G, pos, ax=ax, with_labels=True,node_color = "blue",arrowsize = 30,node_size=650)
    # nx.draw(G, pos, ax=ax, with_labels=True, arrowsize=30, node_size=1000)
    # nx.draw_networkx_edge_labels(G,pos,edge_labels=edge_labels)
    # nx.draw(G,pos,node_size=1000,edge_color=edge_colors,edge_cmap=plt.cm.Reds,arrows =True,cmap = plt.get_cmap('jet'))
    pylab.show()
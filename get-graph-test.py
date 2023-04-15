import networkx as nx
import matplotlib.pylab as plt
import pylab
import json





G = nx.DiGraph()
edge_labels = {}
ProcessID2NameID = {}
num = 0
red_edges =[]
# int2ip = lambda x: '.'.join([str(int(x/(256**i)%256)) for i in range(3,-1,-1)])
int2ip = lambda x: '.'.join([str(int(x/(256**i)%256)) for i in range(0,4,1)])
print(int2ip(16777343))
def get_graph(filemame):
    with open(filemame,"r",encoding="utf-8") as f:
        lines = f.readlines()
        lines = lines[:1500]
        for line in lines:
            line = json.loads(line)
            processID = line["processID"]
            EventName = line["EventName"]
            temarguments = line["arguments"]
            temarguments_1 = temarguments
            # if("Thread" in EventName):
            #     continue
            if(processID<=0 or processID==4):
                continue
            # 特定PID
            # flag = False
            # DPID = "3444"
            # if "ProcessId" in temarguments.keys():
            #     if DPID in str(temarguments["ProcessId" ]):
            #         flag = True
            # else:
            #     flag = False
            # # flag = False
            # if((DPID in str(processID)) or flag):
            #     pass
            # else:
            #     continue
            # 特定PID
            if (processID in ProcessID2NameID.keys()):
                processID = ProcessID2NameID[processID]
            # if("svchost" in str(processID)):#主要路线
            #     continue
            # if("services" in str(processID)):#主要路线
            #     continue
            # if "6488" in str(processID):
            #     continue
            # 进程
            if("Process" in EventName):
                if "Start" in EventName:
                    #ProcessID2NameID[processID] = temarguments["ImageFileName"]+"("+str(processID)+")"
                    ProcessID2NameID[temarguments["ProcessId"]] = temarguments["ImageFileName"]+"("+str(temarguments["ProcessId"])+")"
                    G.add_edges_from([(processID,ProcessID2NameID[temarguments["ProcessId"]] )])
                    edge_labels[(processID,ProcessID2NameID[temarguments["ProcessId"]] )] = EventName
                if "End" in EventName:
                    try:
                        del ProcessID2NameID[line["processID"]]
                    except:
                        print("Process Delete error")
                        continue

            #镜像
            if ("Image" in EventName):
                # if "ImageDCStart" in EventName:
                G.add_edges_from([(processID, temarguments["FileName"])])
                edge_labels[(processID, temarguments["FileName"])] = EventName
            # 文件
            if ("File" in EventName):
                # print(EventName)
                if("FileName" in temarguments.keys()):
                    G.add_edges_from([(processID, temarguments["FileName"])])
                    edge_labels[(processID, temarguments["FileName"])] = EventName
                elif("OpenPath" in temarguments.keys()):
                    G.add_edges_from([(processID, temarguments["OpenPath"])])
                    edge_labels[(processID, temarguments["OpenPath"])] = EventName
                else:
                    print(EventName)
                    # print("File Event error")
            # 网络
            if ("IPV4" in EventName):
                if "Recv" in EventName:
                    IP = int2ip(temarguments["saddr"])+":"+str(temarguments["saddr"])
                    G.add_edges_from([(IP,processID)])
                    edge_labels[(IP,processID)] = EventName
                else:
                    IP = int2ip(temarguments["daddr"])+":"+str(temarguments["dport"])
                    G.add_edges_from([(processID,IP)])
                    red_edges.append((processID,IP))
                    edge_labels[(processID,IP)] = EventName
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
    get_graph(".\\ARTDate\\T1547.001-3.out")
    #G.add_edges_from([("1","2")])
    #edge_labels[("1","2")] = "test"
    # print(G.edges)
    flg, ax = plt.subplots()
    pos = nx.spring_layout(G)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    edge_colors = ['black' if not edge in red_edges else 'red' for edge in G.edges()]

    nx.draw(G, pos, ax=ax, with_labels=True,node_color = "blue",arrowsize = 30,node_size=650,edge_color=edge_colors)
    # nx.draw(G, pos, ax=ax, with_labels=True, arrowsize=30, node_size=1000)
    # nx.draw_networkx_edge_labels(G,pos,edge_labels=edge_labels)
    # nx.draw(G,pos,node_size=1000,edge_color=edge_colors,edge_cmap=plt.cm.Reds,arrows =True,cmap = plt.get_cmap('jet'))
    pylab.show()
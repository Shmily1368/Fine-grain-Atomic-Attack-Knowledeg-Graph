import networkx as nx
import matplotlib.pylab as plt
import pylab
import json
import matplotlib.pylab as plt

num = 0.0
eventscale  = [0.0 for i in range(6)]
def get_graph(filemame):
    global num
    with open(filemame,"r",encoding="utf-8") as f:
        lines = f.readlines()
        #lines = lines[:700]
        for line in lines:
            num = num + 1
            line = json.loads(line)
            processID = line["processID"]
            EventName = line["EventName"]
            temarguments = line["arguments"]
            temarguments_1 = temarguments
            if("Thread" in EventName):
                eventscale[1] = eventscale[1] + 1
            # 进程
            if("Process" in EventName):
                eventscale[0] = eventscale[0] + 1
            if ("Image" in EventName):
                eventscale[5] = eventscale[5] + 1
            #     # if "ImageDCStart" in EventName:
            #     G.add_edges_from([(processID, temarguments["FileName"])])
            #     edge_labels[(processID, temarguments["FileName"])] = EventName
            # 文件
            if ("File" in EventName):
                eventscale[2] = eventscale[2] + 1
            # 网络
            if ("IPV4" in EventName):
                eventscale[3] = eventscale[3] + 1
            #注册表
            if("Registry" in EventName):
                eventscale[4] = eventscale[4] + 1



# get_graph(".\\test.txt")

if __name__=="__main__":
    get_graph(r".\\ARTDate\\EventScale.out")
    result = [i/num*100.0 for i in eventscale]
    #print(num)
    #result = result*100.0
    print(result)
    # result = [str(i)+"%" for i in result]
    x1 = [1,2,3,4,5,6]
    x = ["Process","Thread","File","Internet","Registry","Image",]
    for a,b in zip(x1,result):
        # plt.text(a,b+0.05, ('%.2f'+'%')% b,ha="center",va="bottom",fontsize = 11)
        plt.text(a, b + 0.05, ('%.2f'%b + '%'), ha="center", va="bottom", fontsize=11)
    plt.xticks(x1,x)
    plt.bar(x1,result)
    plt.show()
    # get_graph(".\\GraphTest.txt")
    #get_graph(".\\test.out")

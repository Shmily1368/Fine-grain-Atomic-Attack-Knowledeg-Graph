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




G = nx.DiGraph()
edge_labels = {}
ProcessID2NameID = {}
num = 0
red_edges =[]
ProcessFlag = True
# int2ip = lambda x: '.'.join([str(int(x/(256**i)%256)) for i in range(3,-1,-1)])
int2ip = lambda x: '.'.join([str(int(x/(256**i)%256)) for i in range(0,4,1)])
print(int2ip(16777343))
ResigtryFilter = [r"Environment\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers",
                    "cmd.exe",
                  "CurrentControlSet",
                  # "\REGISTRY\USER",
                    r"\Disallowed\Certificates",
                  # "\SystemCertificates\Disallowed"
                  r"\REGISTRY\MACHINE\Software\Microsoft\SystemCertificates\CA\Software\Policies\Microsoft\SystemCertificates\CA\Software\Microsoft\EnterpriseCertificates\CA\Software\Microsoft\SystemCertificates\Disallowed\Software\Policies\Microsoft\SystemCertificates\Disallowed\Software\Microsoft\EnterpriseCertificates\Disallowed\Software\Microsoft\SystemCertificates\Root\Software\Microsoft\SystemCertificates\AuthRoot\Software\Policies\Microsoft\SystemCertificates\Root\Software\Microsoft\EnterpriseCertificates\Root\Software\Microsoft\SystemCertificates\SmartCardRoot\Software\Microsoft\SystemCertificates\TrustedPeople\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Software\Microsoft\EnterpriseCertificates\TrustedPeople\Software\Microsoft\SystemCertificates\trust\Software\Policies\Microsoft\SystemCertificates\trust\Software\Microsoft\EnterpriseCertificates\trust\Software\Microsoft\SystemCertificates\Disallowed\Software\Policies\Microsoft\SystemCertificates\Disallowed\Software\Microsoft\EnterpriseCertificates\Disallowed\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap",
                  # "powershell.exe",
                  "Internet Settings",
                    "Schannel",
                  ]
FileFilter = [
                "C:\Windows\servicing\LCU\Package_for_RollupFix",
]


sepPID= "11760"
# sepPID= "19324"
# sepPID = "16856"
# sepPID= "2928"
spePIDs = [sepPID]
CommandLine = {}


def get_special_PID(line):
    line = json.loads(line)
    processID = line["processID"]
    EventName = line["EventName"]
    temarguments = line["arguments"]
    temarguments_1 = temarguments
    #特定PID
    flag = False
    DPID = "3444"
    if "ProcessId" in temarguments.keys():
        if DPID in str(temarguments["ProcessId" ]):
            flag = True
    else:
        flag = False
    # flag = False
    if((DPID in str(processID)) or flag):
        pass
    return flag
    #特定PID


def PorcessEvent(processID,processID_tem,EventName,temarguments):
    # if(len(spePIDs)==1):
    #     try:
    #         print(temarguments["CommandLine"])
    #     except:
    #         pass
    global ProcessFlag
    if ("Process" in EventName):
        if "Start" in EventName:
            # ProcessID2NameID[processID] = temarguments["ImageFileName"]+"("+str(processID)+")"
            if(temarguments["ImageFileName"]+"\n" in ProcessBlack):return # process 黑名单
            if(ProcessFlag and len(spePIDs)==1 and temarguments["ImageFileName"]=="powershell.exe"):
            # if (len(spePIDs) == 1 and ProcessFlag):
                spePIDs[0]=str(temarguments["ProcessId"])
                ProcessFlag = False
                return
            spePIDs.append(str(temarguments["ProcessId"]))
            ProcessID2NameID[temarguments["ProcessId"]] = temarguments["ImageFileName"] + "(" + str(temarguments["ProcessId"]) + ")"
            # ProcessID2NameID[temarguments["ProcessId"]] = processID
            G.add_edges_from([(processID, ProcessID2NameID[temarguments["ProcessId"]])])
            edge_labels[(processID, ProcessID2NameID[temarguments["ProcessId"]])] = EventName
            # 2023/4/20 add
            G.edges[processID, ProcessID2NameID[temarguments["ProcessId"]]]["edge_label"] = EventName

def ThreadEvent(processID,processID_tem,EventName,temarguments):
    if ("ThreadStart" in EventName):
        thispid = ""
        if (processID_tem != temarguments["ProcessId"]):
            if (temarguments["ProcessId"] in ProcessID2NameID.keys()):
                # return
                print(ProcessBlack)
                if (ProcessID2NameID[temarguments["ProcessId"]].split("(")[0]+"\n" in ProcessBlack):return
                thispid = ProcessID2NameID[temarguments["ProcessId"]]
            else:
                return
                thispid = temarguments["ProcessId"]
                #spePIDs.append(str(temarguments["ProcessId"]))
            # print(processID_tem, thispid)
            G.add_edges_from([(processID, thispid)])
            edge_labels[(processID, thispid)] = EventName
            # red_edges.append((processID, thispid))

def ImageEvent(processID,processID_tem,EventName,temarguments):
    if ("Image" in EventName):
        # if "ImageDCStart" in EventName:
        G.add_edges_from([(processID, temarguments["FileName"])])
        edge_labels[(processID, temarguments["FileName"])] = EventName


def FileEvent(processID,processID_tem,EventName,temarguments):
    if ("File" in EventName):
        # print(EventName)
        if ("FileName" in temarguments.keys()):
            ThisEventFilename = temarguments["FileName"]
            # if (("T1547.001" not in temarguments["FileName"]) and (r"Microsoft\Windows\Start Menu\Programs\Startup".lower() not in temarguments["FileName"].lower())
            # and r"C:\windows\system32\calc" not in temarguments["FileName"]
            # and False):
            #     return
            # if len(temarguments["FileName"]) >= 30:FileIoDelete
            #     temarguments["FileName"] = temarguments["FileName"][:15] + "......" + temarguments["FileName"][-15:]
            # G.add_edges_from([(processID, temarguments["FileName"])])
            # edge_labels[(processID, temarguments["FileName"])] = EventName
        elif ("OpenPath" in temarguments.keys()):
            ThisEventFilename = temarguments["OpenPath"]
            # if ("T1547.001" not in temarguments["OpenPath"] and "Microsoft\Windows\Start Menu\Programs\Startup".lower() not in temarguments["OpenPath"].lower()
            #         and r"C:\windows\system32\calc" not in temarguments["OpenPath"]
            # and False):
            #     return
            # if len(temarguments["OpenPath"]) >= 30:
            #     temarguments["OpenPath"] = temarguments["OpenPath"][:15] + "......" + temarguments["OpenPath"][-15:]
        else:
            # pass
            # print(EventName)
            return
            # print("File Event error")
        if (("FileIoCreate" in EventName or "IoRead" in EventName or "FileIoRename" in EventName or "FileIo#Delete" in EventName) and "startup" not in ThisEventFilename):return
        if(ThisEventFilename!="" and blackflag):blackrule2.write(ThisEventFilename+"\n")
        for temfile in FileFilter:
            if(temfile in ThisEventFilename):return

        if(not blackflag and ThisEventFilename+"\n" in FileBlack):return


        # if((("wangjian" in ThisEventFilename and "Start Menu" not in ThisEventFilename) or "Collector" in ThisEventFilename or ThisEventFilename=="") and "Atomic".lower() not in ThisEventFilename.lower()):return
        if((("wangjian" in ThisEventFilename and "Start Menu" not in ThisEventFilename) or ("26248" in ThisEventFilename and "Start Menu" not in ThisEventFilename) or "Collector" in ThisEventFilename or ThisEventFilename=="") and "Atomic".lower() not in ThisEventFilename.lower()):return
        # if ( "Collector" in ThisEventFilename): return
        # print(ThisEventFilename)
        G.add_edges_from([(processID, ThisEventFilename)])
        # edge_labels[(processID, ThisEventFilename)] = EventName
        if ((processID, ThisEventFilename) in edge_labels.keys()):
            if (EventName not in edge_labels[(processID, ThisEventFilename)]):
                edge_labels[(processID, ThisEventFilename)] = edge_labels[(processID, ThisEventFilename)] + "\\" + EventName
        else:
            edge_labels[(processID, ThisEventFilename)] = EventName
        red_edges.append((processID, ThisEventFilename))
        # if ("FileIoFile" in EventName or ".vbs" in ThisEventFilename.lower()):
        #     print(EventName)
            # red_edges.append((processID, ThisEventFilename))
        # print(ThisEventFilename)
def InternetEvent(processID,processID_tem,EventName,temarguments):
    if ("IPV4" in EventName):
        if "Recv" in EventName:
            IP = int2ip(temarguments["saddr"]) + ":" + str(temarguments["saddr"])
            G.add_edges_from([(IP, processID)])
            edge_labels[(IP, processID)] = EventName
        else:
            IP = int2ip(temarguments["daddr"]) + ":" + str(temarguments["dport"])
            G.add_edges_from([(processID, IP)])
            red_edges.append((processID, IP))
            edge_labels[(processID, IP)] = EventName
def RegistrytEvent(processID, processID_tem, EventName, temarguments):
    if ("Query" in EventName or "Open" in EventName or "Close"in EventName or "Create" in EventName or("KCB" in EventName)):# and "RunOnce" not in temarguments["KeyName"]
        return
    if ("Registry" in EventName):
        if (temarguments["KeyName"] == "" or "\Windows" not in temarguments["KeyName"]):
            return
        # if( "wangjian" in temarguments["KeyName"] or "Collector" in temarguments["KeyName"]):return
        if(not blackflag and temarguments["KeyName"]+"\n" in RegistryFile):return

        if(blackflag):blackrule.write(temarguments["KeyName"].replace("\r","")+"\n")
        for temregistry in ResigtryFilter:
            if(temregistry in temarguments["KeyName"]):return


        print(temarguments["KeyName"])
        # print(temarguments["KeyName"])
        # if ("\Software\Microsoft\Windows\CurrentVersion\RunOnce".lower() not in temarguments["KeyName"].lower()):
        #     # if("\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" not in temarguments["KeyName"]):
        #     return
        # if(r"\Registry\Machine".lower() in temarguments["KeyName"].lower()):
        #     return
        if len(temarguments["KeyName"]) >= 30:
            temarguments["KeyName"] = temarguments["KeyName"][:15] + "......" + temarguments["KeyName"][-15:]
        G.add_edges_from([(processID, temarguments["KeyName"])])
        edge_labels[(processID, temarguments["KeyName"])] = EventName



def get_graph(filemame):
    global CommandLine
    with open(filemame,"rb") as f:
        lines = f.readlines()
        lines = lines[2:]
        # print(lines)
        # lines = lines[:1500]
        for line in lines:
            # print(line)
            line = json.loads(line)
            processID = line["processID"]
            processID_tem = processID
            EventName = line["EventName"]
            temarguments = line["arguments"]
            temarguments_1 = temarguments
            if(processID<=0 or processID==4):
                continue
            if(str(processID) not in spePIDs):
                continue
            if (processID in ProcessID2NameID.keys()):
                processID = ProcessID2NameID[processID]
            PorcessEvent(processID, processID_tem, EventName, temarguments)
            if ProcessFlag and len(spePIDs)==1:
                continue
            ThreadEvent(processID, processID_tem, EventName, temarguments)
            ImageEvent(processID, processID_tem, EventName, temarguments)
            FileEvent(processID, processID_tem, EventName, temarguments)
            InternetEvent(processID, processID_tem, EventName, temarguments)
            RegistrytEvent(processID, processID_tem, EventName, temarguments)
            # if("svchost" in str(processID)):#主要路线
            #     continue
            # if("services" in str(processID)):#主要路线
            #     continue
            # if "6488" in str(processID):
            #     continue
            # 进程
            # 添加CommandLine
            # if("CommandLine" in temarguments.keys() and "ProcessId" in temarguments.keys()):
            #     if(temarguments["ProcessId"] in CommandLine.keys()):
            #         pass
            #         #CommandLine[temarguments["ProcessId"]] = str(CommandLine[temarguments["ProcessId"]]) + temarguments["CommandLine"]
            #     else:
            #         CommandLine[temarguments["ProcessId"]] = temarguments["CommandLine"]
            # print(CommandLine)
            # 添加CommandLine
            # if("Process" in EventName):
            #     if "Start" in EventName:
            #         #ProcessID2NameID[processID] = temarguments["ImageFileName"]+"("+str(processID)+")"
            #         spePIDs.append(str(temarguments["ProcessId"]))
            #         ProcessID2NameID[temarguments["ProcessId"]] = temarguments["ImageFileName"]+"("+str(temarguments["ProcessId"])+")"
            #         #ProcessID2NameID[temarguments["ProcessId"]] = processID
            #         G.add_edges_from([(processID,ProcessID2NameID[temarguments["ProcessId"]] )])
            #         edge_labels[(processID,ProcessID2NameID[temarguments["ProcessId"]] )] = EventName
                # if "End" in EventName:
                #     try:
                #         del ProcessID2NameID[line["processID"]]
                #     except:
                #         print("Process Delete error")
                #         continue
            # 线程
            # if("ThreadStart" in EventName):
            #     thispid = ""
            #     if(processID_tem != temarguments["ProcessId"]):
            #         if (temarguments["ProcessId"] in ProcessID2NameID.keys()):
            #             continue
            #             thispid = ProcessID2NameID[temarguments["ProcessId"]]
            #         else:
            #             thispid = temarguments["ProcessId"]
            #             spePIDs.append(str(temarguments["ProcessId"]))
            #         print(processID_tem,thispid)
            #         G.add_edges_from([(processID,thispid)])
            #         edge_labels[(processID,thispid)] = EventName
            #         red_edges.append((processID, thispid))
            # 镜像
            # if ("Image" in EventName):
            #     # if "ImageDCStart" in EventName:
            #     G.add_edges_from([(processID, temarguments["FileName"])])
            #     edge_labels[(processID, temarguments["FileName"])] = EventName
            #文件
            # if ("File" in EventName):
            #     # print(EventName)
            #     if("FileName" in temarguments.keys() ):
            #         ThisEventFilename = temarguments["FileName"]
            #         if (("T1547.001" not in temarguments["FileName"]) and (r"Microsoft\Windows\Start Menu\Programs\Startup".lower() not in temarguments["FileName"].lower())):
            #             print(temarguments)
            #             print(temarguments["FileName"])
            #             print((r"Microsoft\Windows\Start Menu\Programs\Startup" not in temarguments["FileName"]))
            #             continue
            #         # if len(temarguments["FileName"]) >= 30:
            #         #     temarguments["FileName"] = temarguments["FileName"][:15] + "......" + temarguments["FileName"][-15:]
            #         # G.add_edges_from([(processID, temarguments["FileName"])])
            #         # edge_labels[(processID, temarguments["FileName"])] = EventName
            #     elif("OpenPath" in temarguments.keys()):
            #         ThisEventFilename = temarguments["OpenPath"]
            #         if ("T1547.001" not in temarguments["OpenPath"] and "Microsoft\\Windows\\Start Menu\\Programs\\Startup".lower() not in temarguments["OpenPath"].lower()):
            #             continue
            #         # if len(temarguments["OpenPath"]) >= 30:
            #         #     temarguments["OpenPath"] = temarguments["OpenPath"][:15] + "......" + temarguments["OpenPath"][-15:]
            #     else:
            #         # pass
            #         # print(EventName)
            #         continue
            #         # print("File Event error")
            #     G.add_edges_from([(processID, ThisEventFilename)])
            #     # edge_labels[(processID, ThisEventFilename)] = EventName
            #     if((processID, ThisEventFilename) in edge_labels.keys()):
            #         if(EventName not in edge_labels[(processID, ThisEventFilename)]):
            #             edge_labels[(processID, ThisEventFilename)] = edge_labels[(processID, ThisEventFilename)]+"\\"+EventName
            #     else:
            #         edge_labels[(processID, ThisEventFilename)] = EventName
            #     if("FileIoFile" in EventName):
            #         print(EventName)
            #         print(line)
            #         red_edges.append((processID, ThisEventFilename))
            #网络
            # if ("IPV4" in EventName):
            #     if "Recv" in EventName:
            #         IP = int2ip(temarguments["saddr"])+":"+str(temarguments["saddr"])
            #         G.add_edges_from([(IP,processID)])
            #         edge_labels[(IP,processID)] = EventName
            #     else:
            #         IP = int2ip(temarguments["daddr"])+":"+str(temarguments["dport"])
            #         G.add_edges_from([(processID,IP)])
            #         red_edges.append((processID,IP))
            #         edge_labels[(processID,IP)] = EventName
            # print(spePIDs)
            # continue
            #注册表
            # if("Registry" in EventName):
            #     if("\Software\Microsoft\Windows\CurrentVersion\RunOnce" not in temarguments["KeyName"]):
            #     # if("\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" not in temarguments["KeyName"]):
            #         continue
            #     # if("\\" not in temarguments["KeyName"]):
            #     #     continue
            #     # if("Close" in EventName):
            #     #     continue
            #     # if (processID_tem not in CommandLine.keys()):
            #     #     continue
            #     # if(temarguments["KeyName"] not in CommandLine[processID_tem]):
            #     #     continue
            #     # if("3444" not in str(processID)):
            #     #     continue
            #     #print(temarguments["KeyName"])
            #     if len(temarguments["KeyName"])>=30:
            #         temarguments["KeyName"] = temarguments["KeyName"][:15]+"......"+temarguments["KeyName"][-15:]
            #     G.add_edges_from([(processID, temarguments["KeyName"])])
            #     edge_labels[(processID, temarguments["KeyName"])] = EventName



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
    # blackrule = open(".\\ARTDate\\Rule\\RegistryBlack.txt","a+")
    # blackrule2 = open(".\\ARTDate\\Rule\\FileBlack.txt","a+")
    # blackrule = open(".\\ARTDate\\Rule\\RegistryBlack.txt","r")
    # blackrule2 = open(".\\ARTDate\\Rule\\FileBlack.txt","r")
    # RegistryFile = blackrule.readlines()
    # FileBlack = blackrule2.readlines()
    #####
    blackflag = False
    if not blackflag:
        blackrule = open(".\\ARTDate\\Rule\\RegistryBlack.txt", "r")
        blackrule2 = open(".\\ARTDate\\Rule\\FileBlack.txt", "r")
        blackrule3 = open(".\\ARTDate\\Rule\\ProcessBlack.txt", "r")
        RegistryFile = blackrule.readlines()
        FileBlack = blackrule2.readlines()
        ProcessBlack = blackrule3.readlines()
    else:
        blackrule = open(".\\ARTDate\\Rule\\RegistryBlack.txt","a+")
        blackrule2 = open(".\\ARTDate\\Rule\\FileBlack.txt","a+")

    for i in range(len(FileBlack)):
        FileBlack[i] = FileBlack[i].replace("wangjian","26248")
    print(FileBlack)
    #### get black
    # print(FileBlack)
    # spePIDs[0] = "5232"
    # get_graph(".\\ARTDate\\Benign\\Normal-5232.out")

    # spePIDs[0] = "6312"
    # spePIDs[0] = "16504"
    # get_graph(r"E:\MyData\AttackGraph\fine-grain\ARTDate\Techniques\T1218.011-1_16504.txt")
    # spePIDs.extend('3828,5428,6668,10472,19248,19328'.split(',')[0])
    # print(spePIDs)

    # spePIDs[0] = "14744"
    # spePIDs[0] = "12692"
    # get_graph(".\\ARTDate\\T1547.001-4_2.out")
    # spePIDs[0] = "3444"
    # spePIDs[0] = "15000"
    # get_graph(".\\ARTDate\\Benign\\Normal-5232.out")

    # get_graph(".\\ARTDate\\T1055-3.out")
    # get_graph(".\\ARTDate\\T1547.001-4_2.out")

    # get_graph(".\\ARTDate\\T1547.001-1.out")
    # print(spePIDs)
    # folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\\TechniqueRawDate'
    # folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\\GraphFile0411'
    # folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\Graph-Vmware-All'
    # folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\test'
    folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\GraphFileAll1015'
    # folder_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\test'
    files = os.listdir(folder_path)
    for file in files:
        if os.path.isfile(os.path.join(folder_path, file)):
            file_path = os.path.join(folder_path, file)
            print(file_path)
            G = nx.DiGraph()
            edge_labels = {}
            ProcessID2NameID = {}
            num = 0
            red_edges = []
            ProcessFlag = True
            fileinfo = file.replace(".txt","").split("_")
            spePIDs = [str(fileinfo[1])]
            print(spePIDs)
            get_graph(file_path)
            # print(file_path)
            flg, ax = plt.subplots()
            pos = nx.spring_layout(G)
            nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
            edge_colors = ['black' if not edge in red_edges else 'red' for edge in G.edges()]

            nx.draw(G, pos, ax=ax, with_labels=True, node_color="blue", arrowsize=30, node_size=650,
                    edge_color=edge_colors)
            # pylab.show()
            # plt.savefig(r'E:\MyData\AttackGraph\fine-grain\ARTDate\\TechniqueRawDateGraph\\'+fileinfo[0]+'.png',dpi = 300)
            # plt.savefig(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\Graph-Vmware-All-Graph\\'+fileinfo[0]+'.png',dpi = 300)
            plt.savefig(r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\Graph-Vmware-All-Graph2\\'+file.replace(".txt","")+'.png',dpi = 300)
            plt.close()


            fname = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\TechniqueRawDateGraph_ml2' +"\\" + file.replace(".txt","")+'.gml'
            # fname = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\test' +"\\" + file.replace(".txt","")+'.test'
            print(fname)
            networkx.write_gml(G,fname)
            # networkx.write_gml(G,fname)
            # with open(fname, 'wb') as f:
            #     nx.write_edgelist(G, f, data=[edge_labels.values()], delimiter=',', encoding='utf-8')

            # with open(fname, 'wb') as f:
            #     nx.write_edgelist(G, f, data=True, delimiter=',', encoding='utf-8')

            # networkx.write_gml(G,fname)
            # parser = GraphMLParser()
            # parser.write(G, fname)
            #
            # # Visualize the GraphML file
            # print(fname)
            # with open(fname) as f:
            #     print(f.read())
            # test
            # seed = 13648  # Seed random number generators for reproducibility
            # pos = nx.spring_layout(G, seed=seed)
            #
            # node_sizes = [3 + 10 * i for i in range(len(G))]
            # M = G.number_of_edges()
            # edge_colors = range(2, M + 2)
            # edge_alphas = [(5 + i) / (M + 4) for i in range(M)]
            # cmap = plt.cm.plasma
            #
            # nodes = nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color="indigo")
            # edges = nx.draw_networkx_edges(
            #     G,
            #     pos,
            #     node_size=node_sizes,
            #     arrowstyle="->",
            #     arrowsize=10,
            #     edge_color=edge_colors,
            #     edge_cmap=cmap,
            #     width=2,
            # )
            # # set alpha value for each edge
            # for i in range(M):
            #     edges[i].set_alpha(edge_alphas[i])
            #
            # pc = mpl.collections.PatchCollection(edges, cmap=cmap)
            # pc.set_array(edge_colors)
            # plt.colorbar(pc)
            #
            # ax = plt.gca()
            # ax.set_axis_off()
            # plt.show()


            # print(r'E:\MyData\AttackGraph\fine-grain\ARTDate\\TechniqueRawDateGraph\\'+fileinfo[0]+'.png')
    os._exit(0)
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
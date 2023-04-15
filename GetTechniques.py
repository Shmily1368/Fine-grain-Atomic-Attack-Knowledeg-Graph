import csv
TechniqueFile = open(r"E:\MyData\AttackGraph\fine-grain\atomics\Indexes\index.yaml","r",encoding="gbk",errors="ignore")


num=0
row = 0
f = open('./ARTDate/WindowsTechniques.csv', 'w',newline="")
writer = csv.writer(f)

MyRow=1
MyColum=1
def wirtecsv(MyRow,MyColum,MyData):
    with open('./ARTDate/csv_file.csv', 'r+', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # 写入数据到指定行列
        row_number = 1  # 行数
        column_number = 1  # 列数
        data = MyData  # 要写入的数据
        rows = csv.reader(csvfile)
        for i, row in enumerate(rows):
            if i == row_number - 1:
                row[column_number - 1] = data
            writer.writerow(row)
        # 将所有行写回文件
        csvfile.truncate()
        csvfile.seek(0)
        writer.writerows(csv.reader(csvfile))
csvdata = [0]*3
IfWindows = False
TechniqueNum = 1
TemTechniqueName = ""
windowsflag = False
for i in TechniqueFile:
    # if(len(i.replace("\n",""))==0 or len(i)==0):
    #     break
    if("---" in i):continue
    flag = False
    if(i[0]!=" "):flag=True
    i=i.replace("\n", "").replace("\r", "")
    if(len(i)==0):continue
    if(flag):
        print(i)
        csvdata[0]=i.replace(":","")
    elif csvdata[0] == 0:
        csvdata[0]=""
    # if("      - Windows"==i[:16]):print("Windows(√)")
    if("      name:" == i[:11]):
        csvdata[1]=i
        print(i)
    elif csvdata[1]==0:
        csvdata[1]=""
    if("T1" in i[:4]):
        csvdata[2]=i
        # windowsflag = False
        # TechniqueNum = 1
        print(i)
    elif csvdata[2] == 0:
        csvdata[2]=""
    if("    - name:"==i[:11]):
        csvdata.append(i)
        print(i)
    if("      auto_generated_guid"==i[:len("      auto_generated_guid")]):
        csvdata.append(i.split(":")[1])
        print(i.split(":")[1])
    if("      - windows"==i[:15]):
        csvdata.append("windows(√)")
        print("windows(√)")
    if("      input_arguments:"==i[:24] or "      executor:" in i[:15]):
        if(len(csvdata)==5):
            csvdata.append("windows(×)")
            # del csvdata[3:]
            # TechniqueNum = TechniqueNum+1
            # windowsflag = True
    if(len(csvdata)==6):
        print(csvdata)
        if(csvdata[1]!=""):
            TechniqueNum = 1
            # if(not windowsflag):
            #     TechniqueNum = 1
            # print("哈哈",csvdata[1].split("name:")[1])
            # csvdata[1] = csvdata[2].replace(":","")+csvdata[1].split("name:")[1]#.replace("'","").replace(" ","")
            csvdata[1] = csvdata[2] + csvdata[1].split("name:")[1].replace("'","")#.replace(" ","")
        if(csvdata[2]!=""):
            csvdata[3]=csvdata[2].replace(":","")+"-"+str(TechniqueNum)+":"+csvdata[3].split("e:")[1]
            TemTechniqueName = csvdata[2].replace(":","")
        else:
            csvdata[3] = TemTechniqueName + "-" + str(TechniqueNum) + ":" + csvdata[3].split("e:")[1]
        TechniqueNum = TechniqueNum+1

        del csvdata[2]
        # del csvdata[3]
        writer.writerow(csvdata)
        csvdata=[0]*3

    # print(i)
    # if(i[0]!=" "):
    #     print(i)
    # try:
    #     if(i[2]=="T"):
    #         print(i)
    # except:
    #     pass
    # num+=1
    # if(num>2000):break

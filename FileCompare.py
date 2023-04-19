import os


folder1_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\Graph-Vmware-All'
folder2_path = r'E:\MyData\AttackGraph\fine-grain\ARTDate\RawGraphDate\TechniqueRawDateGraph_ml'


# 获取两个文件夹中的文件名列表
folder1_names = os.listdir(folder1_path)
folder2_names = os.listdir(folder2_path)
for i in range(len(folder1_names)):
    tem = folder1_names[i].split("_")[0]
    if tem in folder1_names:
        print(tem)
    folder1_names[i] = folder1_names[i].split("_")[0]
#
for i in range(len(folder2_names)):
    folder2_names[i] = folder2_names[i].split(".txt")[0]

# print(folder1_names)
# # print(folder2_names)
# folder1_names = list(set(folder1_names))
# print(len(folder1_names))
# print(len(folder2_names))
#
找到不同的文件名
different_names = set(folder1_names).symmetric_difference(set(folder2_names))

print(different_names)

# 打印不同的文件名
for name in different_names:
    print(name)
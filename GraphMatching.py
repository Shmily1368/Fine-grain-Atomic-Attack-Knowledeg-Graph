import os

with open('mylogfile.txt', 'r') as f:
    for line in f:
        if line.startswith('Event: '):
            # 提取事件类型
            event_type = line.split('Event: ')[1].strip()
        elif line.startswith('Process Name: '):
            # 提取进程名称
            process_name = line.split('Process Name: ')[1].strip()
        elif line.startswith('Process ID: '):
            # 提取进程 ID
            process_id = line.split('Process ID: ')[1].strip()
        elif line.startswith('Parent Process ID: '):
            # 提取父进程 ID
            parent_process_id = line.split('Parent Process ID: ')[1].strip()

            # 在这里可以对提取到的数据进行处理和分析
            # 比如，可以将进程事件作为节点，并将它们之间的关系作为边标记

            # 输出提取到的数据
            print(f'Event Type: {event_type}')
            print(f'Process Name: {process_name}')
            print(f'Process ID: {process_id}')
            print(f'Parent Process ID: {parent_process_id}')
import os

averageTimes = []
def read_rules(rule_file_path):
    with open(rule_file_path, 'rb') as fh:
        fh.seek(-1024, 2)
        last = fh.readlines()[-2].decode()
        return last

for i in range(1,33):
    averageTimes.append(read_rules("report_"+ f"{i:02d}" +".txt"))

for i in averageTimes:
    print(i)
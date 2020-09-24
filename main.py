import sys
import functions as f
import time

rule_file_path      = sys.argv[1]
packet_file_path    = sys.argv[2]

root = f.Node(tag="^")


all_rules = f.read_rule_file(rule_file_path)

rule_src_binaries = [eachElement.src_binary for eachElement in all_rules]
rule_dst_binaries = [eachElement.dst_binary for eachElement in all_rules]

for i in range(0, len(rule_src_binaries)):
    f.add_node (root, rule_src_binaries[i], rule_dst_binaries[i], 0, i, True)

#f.show(root)

all_packets = f.read_packet_file(packet_file_path)

start = time.time_ns()
# Classification Algorithm
print (f.clasify(root, all_packets, all_rules, rule_src_binaries, rule_dst_binaries))

stop = time.time_ns()

Elpased = int(stop - start)
average = Elpased/len(all_packets)
print("It took %d ns to classify %d packets" % (Elpased, len(all_packets)))
print("The average time for each packet is %d ns" % average)
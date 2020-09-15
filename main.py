import sys
import network_utils as nu
import binary_tree as bt
import time

# passing input varables to the program. [rule_file, packet_file]
rule_file    = sys.argv[1]
packet_file  = sys.argv[2]

all_rules = nu.read_rules(rule_file)

# Generate Tree
root = bt.Node()  #show(root)   

#print(rules)

src_sub_binaries = [x.src_sub_binary for x in all_rules]
dst_sub_binaries = [x.dst_sub_binary for x in all_rules]
#print(src_sub_binaries)
#print(dst_sub_binaries)

# Go and make the Tiers (Tier 1 and then Tier2) 
for i in range(0, len(src_sub_binaries)):
    bt.add_src_nodes(root, src_sub_binaries[i], 0, dst_sub_binaries[i],i)

# When we reach here the Tier 1 and Tier 2 has been completed.
# We have the rule Tree and now we should check the incoming packets with this tree.

#bt.show(root)

# Test incoming_packets2.txt
packets = nu.read_packets(packet_file)
start = time.time_ns()
actions = bt.get_packets_actions(root, packets, all_rules, False)
stop = time.time_ns()
Elpased = int(stop - start)
average = Elpased/100000
print("It took %d ns to classify 100.000 packets" % Elpased)
print("The average time for each packet is %d ns" % average)

#print(actions)

# Test random generated packets
""" nu.generate_random_packet_file("random_packets.txt",100000)

packets = nu.read_packets(packet_file)

for i in range(2,6):
    nu.generate_random_packet_file("random_packets.txt",10**i)
    packets = nu.read_packets("random_packets.txt")
    
    start = int(round(time.time() * 1000))
    actions = bt.get_packets_actions(root, packets, rules, False)
    stop = int(round(time.time() * 1000))
    
    print("It took %d ms to rout %d packets" % ((stop - start)*10, 10**i)) #backward compatible """
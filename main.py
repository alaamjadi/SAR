import sys
import network_utils as nu
import binary_tree as bt
import time

ruleFile    = sys.argv[1]
packetFile  = sys.argv[2]

rules = nu.read_rules(ruleFile)

# Generate Tree
root = bt.Node()

src_sub_binaries = [x.src_sub_binary for x in rules]
dst_sub_binaries = [x.dst_sub_binary for x in rules]

for i in range(0, len(src_sub_binaries)):
    bt.add_src_nodes(root, src_sub_binaries[i], 0, dst_sub_binaries[i],i)


# Test incoming_packets2.txt
packets = nu.read_packets(packetFile)
actions = bt.get_packets_actions(root, packets, rules, True)
#print(actions)


# Test random generated packets
# nu.generate_random_packet_file("random_packets.txt",10000)

packets = nu.read_packets(packetFile)

for i in range(2,5):
    nu.generate_random_packet_file(packetFile,10**i)
    packets = nu.read_packets(packetFile)
    
    start = int(round(time.time_ns()))
    actions = bt.get_packets_actions(root, packets, rules, False)
    stop = int(round(time.time_ns()))
    
    print("It took %d ms to route %d packets" % ((stop - start)/1e6, 10**i))
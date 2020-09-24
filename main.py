import sys
import time
import network_utils as nu
import binary_tree as bt


# Receiving Rule list and packet list as input arguments
rule_file    = sys.argv[1]
packet_file  = sys.argv[2]

# Reading all the rule entries and putting them into a list
all_rules = nu.read_rules(rule_file)

# Creating the root node
root = bt.Node()

# Converting the Rule's source and destination netIDs into the binary format and putting them into two separate lists
src_sub_binaries = [x.src_sub_binary for x in all_rules]
dst_sub_binaries = [x.dst_sub_binary for x in all_rules]

# Going through all Rule's source and destination sub binaries to create the tree
for i in range(0, len(src_sub_binaries)):
    bt.add_src_nodes(root, src_sub_binaries[i], 0, dst_sub_binaries[i],i)

# Draw the tree that was created i the previous step
#bt.show(root)

# Reading all the incoming packets and putting them into a list
packets = nu.read_packets(packet_file)

# Starting the timer for measuring the Classification time
start = time.time_ns()

# Classificaton Algoritm (Matching and getting the packets actions)
actions = bt.get_packets_actions(root, packets, all_rules, False)

# Stopping the timer for measuring the Classification time
stop = time.time_ns()

# Calculating the elpased time between the start and stop of the timer
Elpased = int(stop - start)

# Calculating the average classification time
average = Elpased/len(packets)

# Printing the results of the classification (Average Time)
print("It took %d ns to classify %d packets" % (Elpased,len(packets)))
print("The average time for each packet is %d ns" % average)
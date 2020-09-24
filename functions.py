import random
import sys

root                = None
rule_src_binaries   = []
all_rules           = []
all_packets         = []

candidates_T1       = []
candidates_T2       = []
candidates_T1_T2    = []
candidates_PP       = []


########################################### Network Utils ###########################################

def ip_to_binary(ip):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

def netID_extractor(netID):
    netID = netID.split('/')
    ip = netID[0]
    netmask = int(netID[1])
    binaryPrefix = ip_to_binary(ip)[:netmask] 
    return binaryPrefix

def read_rule_file(rule_file_path):
    all_rules = []
    rule_file = open(rule_file_path, 'r') 
    rules_raw = rule_file.readlines()
    for line in rules_raw: 
        tmp = [ eachElement.strip() for eachElement in line.split(",")]
        all_rules.append(Rule(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]))
    return all_rules

def read_packet_file(packet_file_path):
    all_packets = []
    packet_file = open(packet_file_path, 'r')
    packets_raw = packet_file.readlines()
    for line in packets_raw:
        tmp = [ eachElement.strip() for eachElement in line.split(",")]
        all_packets.append(Packet(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4]))
    return all_packets

def show(node, indent="", has_left=False):
    last_indent = "|--"

    if has_left:
        last_indent = "--"
    elif node.tag == "^":
        indent = ""
        last_indent = ""

    if not node.end:
        print("%s%sTag = %s" % (indent, last_indent, node.tag))
    else:
        print("%s%sTag = %s, Rules: %s" % (indent, last_indent, node.tag, node.node_rules))

    if node.right is not None:
        if node.left is None:
            show(node.right, indent + "   ")
        else:
            show(node.right, indent + "  |", True)

    if node.left is not None:
        if node.rootTier2 is None:
            show(node.left, indent + "  ")
        else:
            show(node.left, indent + "  |", True)

    if node.rootTier2 is not None:
        show(node.rootTier2, indent + "  ")

############################### Hierarchical Classification Algorithm ###############################

class Node():
    tag             = None
    left            = None
    right           = None
    rootTier2       = None  #dst_root
    node_rules      = None
    end             = False #Used for drawing the tree
    def __init__(self, tag):
        self.tag        = tag
        self.node_rules = []

class Rule:
    src_netID   = None
    src_binary  = None
    dst_netID   = None
    dst_binary  = None
    protocol    = None
    src_port    = None
    dst_port    = None
    action      = None
    def __init__(self, src_netID, dst_netID, protocol, src_port, dst_port, action):
        self.src_netID = src_netID
        self.dst_netID = dst_netID
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action

        if self.src_netID == "*":
            self.src_binary = "*"
        else:
            self.src_binary = netID_extractor(self.src_netID)

        if self.dst_netID == "*":
            self.dst_binary = "*"
        else:
            self.dst_binary = netID_extractor(self.dst_netID)

class Packet():
    src_ip      = None
    src_binary  = None
    dst_ip      = None
    dst_binary  = None
    protocol    = None
    src_port    = None
    dst_port    = None
    def __init__(self, src_ip, dst_ip, protocol, src_port, dst_port):
        self.src_ip     = src_ip
        self.src_binary = ip_to_binary(src_ip)
        self.dst_ip     = dst_ip
        self.dst_binary = ip_to_binary(dst_ip)
        self.protocol   = protocol
        self.src_port   = src_port
        self.dst_port   = dst_port
    
def add_node (node, src_binary, dst_binary, index, all_rule_index, Tier1):
    if Tier1:
        if src_binary == "*":
            index += 1

        if len(src_binary) == index:
            node.node_rules.append(all_rule_index)
            node.end = True
            if node.rootTier2 is None:
                node.rootTier2 = Node(tag="#")
            add_node(node.rootTier2, src_binary, dst_binary, 0, all_rule_index, False)
            return

        if src_binary[index] == "0":
            if node.left is None:
                node.left = Node(tag=node.tag + "0")
            add_node(node.left, src_binary, dst_binary, index+1, all_rule_index, True)

        if src_binary[index] == "1":
            if node.right is None:
                node.right = Node(tag=node.tag + "1")
            add_node(node.right, src_binary, dst_binary, index+1, all_rule_index, True)

    elif not Tier1:
        if dst_binary == "*":
            index += 1

        if len(dst_binary) == index:
            node.node_rules.append(all_rule_index)
            node.end = True
            return

        if dst_binary[index] == "0":
            if node.left is None:
                node.left = Node(tag=node.tag + "0")
            add_node(node.left, src_binary, dst_binary, index+1, all_rule_index, False)

        if dst_binary[index] == "1":
            if node.right is None:
                node.right = Node(tag=node.tag + "1")
            add_node(node.right, src_binary, dst_binary, index+1, all_rule_index, False)

def match(root, node, packet_src, packet_dst, index, candidates, Tier1, rule_src_binaries):
    if Tier1:
        print("TIER 1:: ", "Node: ", node, "Packet_Source: ", packet_src, "Packet_Destination: ", packet_dst, "Index: ", index)
        # Is the node gray?
        if node.node_rules is not None:
            candidates.extend(node.node_rules)
        # Binary value = 0, does the node have left edge?
        if packet_src[index]=="0":
            if node.left is not None:
                match(root, node.left, packet_src, packet_dst, index+1, candidates, True, rule_src_binaries)
                return
        # Binary value = 1, does the node have right edge?
        if packet_src[index]=="1":
            if node.right is not None:
                match(root, node.right, packet_src, packet_dst, index+1, candidates, True, rule_src_binaries)
                return
        # No match!
        if len(candidates) == 0:
            print("No Match in Tier1")
            return
        # We reached inermediate or end node, we have to find the nodes one by one with having higher priority rules.
        if len(candidates) != 0:
            candidates_T1 = sorted(set(candidates))
            print("We have a match(es) in Tier 1 and the rule indices are ", candidates_T1)
            
            for i in candidates_T1:
                print("Checking the candidate: ", i)
                
                print(candidates_T1[i])
                """ if rule_src_binaries[i] == "*":
                    match(root, MoveToNode(root, "*", 0), packet_src, packet_dst, 0, candidates_T2, False, rule_src_binaries)
                else:
                    #print(MoveToNode(root, rule_src_binaries[int(candidates_T1[i])],0))
                    match(root, MoveToNode(root, rule_src_binaries[i],0), packet_src, packet_dst, 0, candidates_T2, False, rule_src_binaries)
                tmp = sorted(list(set(candidates_T1).intersection(candidates_T2)))
                candidates_T1_T2.extend(tmp) """

def MoveToNode (node, address, index):
    #print(node, index)
    if address == "*":
        index += 1
    if len(address) == index:
        return node
    if address[index] == "0":
        MoveToNode(node.left, address, index + 1)
        return node
    if address[index] == "1":
        MoveToNode(node.right, address, index + 1)
        return node

def Protocol_Port_Check(all_rules, rule_indices, packet):
    rule_indices = sorted(list(set(rule_indices)))
    for i in rule_indices:
        if all_rules[i].protocol != "*" and all_rules[i].protocol != packet.protocol:
            continue
        if not is_in_port_range(all_rules[i].src_port, packet.src_port):
            continue
        if not is_in_port_range(all_rules[i].dst_port, packet.dst_port):
            continue
        candidates_PP.append(i)


def is_in_port_range(rule_port,packet_port):
    if "-" in rule_port:
        start = int(rule_port.split("-")[0])
        end = int(rule_port.split("-")[1])
        return start <= int(packet_port) and  int(packet_port) <= end
    elif "*" == rule_port:
        return True
    else:
        return rule_port == packet_port

def clasify(node, all_packets, all_rules, rule_src_binaries, rule_dst_binaries):
    root = node
    all_packets = all_packets
    all_rules = all_rules

    for packet in all_packets:
        #candidates_T1, candidates_T2, candidates_T1_T2, candidates_PP = [], [], [], []
        match(root, node, packet.src_binary, packet.dst_binary, 0, candidates_T1, True, rule_src_binaries)
        Protocol_Port_Check(all_rules, candidates_T1_T2, packet)
        """ if len(candidates_PP) != 0:
            print("Match found! Rule Indices: \n", candidates_PP)
        else:
            print("No match found!") """
        print(candidates_PP)
    return candidates_PP

#print("Error:: sPrefix is not  *  or  0  or  1. Check the rule number %d" %all_rule_index + 1)
#sys.exit()
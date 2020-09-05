# High-performance container datatypes
from collections import deque
import ipaddr
import ipaddress
import socket
import numpy as np
from scipy.cluster.hierarchy import dendrogram, linkage
import pandas as pd
import re

# Global variables
buk = None
last_prefix = None
length = None

# Packet Classification parameters
SRC_IP = 0
DST_IP = 1
PROTO = 2
SPORT = 3
DPORT = 4
ACTION = 5

# Topologies
TOPO = 2


def hierarchical_classification(self,ff,f1_all,ff2,clear_f2,ff3,all_proto,fsport,all_sport,fdport,all_dport):
		if any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) and any(ele in ff3 for ele in fsport) and any(ele in fsport for ele in fdport)==True:
				print "tier1"
				for i in ff2:
					acca=self.classify[i][ACTION]
				#print "action", self.classify[ff2][ACTION]
				#for i in ff2:
				#	action=self.classify[i][ACTION]
		#if res = any(ele in ff for ele in ff2) ==True:
		elif any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) and any(ele in ff3 for ele in fsport)==True:
			print "tier2"
			for i in ff2:
				acca=self.classify[i][ACTION]
			
		elif any(ele in ff for ele in ff2) and any(ele in ff2 for ele in ff3) ==True:
			print "tier3"
			for i in ff2:
				acca=self.classify[i][ACTION]
		elif any(ele in ff for ele in ff2)==True:
			print "tier4"
			for i in ff2:
				acca=self.classify[i][ACTION]
		else:
			print "loooh"
		return acca



class Node():
    # initialization of a node for the tree
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None
        self.parent = None
        self.child = None
        self.root = None
        self.color = None
        self.rule = []

#####<>#####

    # adding a rule address to the tree
    def add_rule(self, rule):
        # self.rule=rule
        self.rule.append(rule)


class Tree():
    # initialization of the tree setting the root to None
    def __init__(self):
        self.root = None

#####<>#####

    # building the tree appending one node
    def add_node(self, key, node=None):
        global length
        # setting the root
        if node is None:
            node = self.root
        if self.root is None:
            self.root = Node(key)
        else:
            if (key[length] == '0'):
                length = length + 1
                # adding left node
                if node.left is None:
                    node.left = Node(key)
                    node.left.parent = node
                    length = 0
                    return
                else:
                    # adding nodes to the left one
                    return self.add_node(key, node=node.left)
            else:
                length = length + 1
                # adding right node
                if node.right is None:
                    node.right = Node(key)
                    node.right.parent = node
                    length = 0
                    return
                else:
                    # adding nodes to the right one
                    return self.add_node(key, node=node.right)

#####<>#####

    # searching a specific node to assign him a rulle
    def add_rule(self, key, l, rule, node):
        if node is None:
            node = self.root
        if self.root.key == key:
            print "key is at the root::", node.key
            node.add_rule(rule)
            print "rule is ::", rule
            return self.root
        else:
            #### Never put rule a*, 0, 1 ####
            if len(node.key) == len(key):
                #print "\nact", rule
                # rule=rule+rule
                #print "added to node: ", node.key
                node.add_rule(rule)
                #print "s", node.add_rule(rule)
                l = 0
                return
            elif key[l] == "0" and node.left is not None:
                l = l + 1
                #print "s", key
                return self.add_rule(key, l, rule, node=node.left)
            elif key[l] == "1" and node.right is not None:
                l = l + 1
                return self.add_rule(key, l, rule, node=node.right)
            else:
                l = 0
                return None

#####<>#####

    # print of the tree with nodes ordered by level
    def print_tree(self, head, queue=deque()):
        if head is None:
            return
        print "\nkey: ", head.key, "\nrule: ", head.rule

        if head.right is not None:
            print "Node right: ", head.right.key
        else:
            print "Node right:  --"
        if head.left is not None:
            print "Node left: ", head.left.key
        else:
            print "Node left:  --"
            [queue.append(node) for node in [head.left, head.right] if node]
            if queue:
                self.print_tree(queue.popleft(), queue)

#####<>#####

    def finding_prefix(self, IP_add_str, n1, i):
        global buk
        global last_prefix

        IP_add_bin = fromIPtoBinary(IP_add_str)
        #IP_add_bin = IP_add_str
        IP_add_bin += "00"
        # sort=[]

#####<>#####

        # sort=[]
        buk = []
        buk.append(n1.rule)

        if last_prefix == '*':
            return "*"

        # search index < of binary address length
        if i < len(IP_add_bin):
            # sort.append(n1.rule)
            if IP_add_bin[i] == "0" and n1.left is not None:
                i = i + 1
                if n1.rule is not None:
                    last_prefix = n1.rule
                return self.finding_prefix(IP_add_str, n1.left, i)

            # next character of the IP is a one and current node has a child
            elif IP_add_bin[i] == "1" and n1.right is not None:
                i = i + 1
                if n1.rule is not None:
                    last_prefix = n1.rule
                return self.finding_prefix(IP_add_str, n1.right, i)

            # if I get here, I don't have kids, I'm at the bottom of the tree
            else:
                if n1.rule is not None:
                    return n1.rule
                    #print "=========smotri",data
                else:
                    return last_prefix
        else:
            return last_prefix

#####<>#####

    def finding_prefix_one(self, IP_add_str, n1, i):
        #global buk
        global last_prefix
        if IP_add_str == "*":
            print "root"
            print "Nothing"
        #IP_add_bin = fromIPtoBinary(IP_add_str)
        IP_add_bin = IP_add_str
        IP_add_bin += "1"
        sort = []
        #print "lllllllllllllll", last_prefix

#####<>#####

        sort.append(last_prefix)
        # buk=[]
        # buk.append(n1.rule)
        if last_prefix == '*':
            return "*"

        # search index < of binary address length
        if i < len(IP_add_bin):
            # sort.append(n1.rule)
            if IP_add_bin[i] == "0" and n1.left is not None:
                i = i + 1
                if n1.rule is not None:
                    last_prefix = n1.rule
                return self.finding_prefix_one(IP_add_str, n1.left, i)

            # next character of the IP is a one and current node has a child
            elif IP_add_bin[i] == "1" and n1.right is not None:
                i = i + 1
                if n1.rule is not None:
                    last_prefix = n1.rule
                return self.finding_prefix_one(IP_add_str, n1.right, i)

            # if I get here, I don't have kids, I'm at the bottom of the tree
            else:
                if n1.rule is not None:
                    return n1.rule
                    #print "=========smotri",data
                else:
                    return last_prefix
        else:
            return last_prefix
###################################################################################################################



###############					    ###############		  
#######                                     #######
###              Extra Functions                ###


############### IP Conversion from Binary to Decimal ###############
def fromBinarytoIP(string):
    splitter = 8
    divided = [string[i:i+splitter] for i in range(0, len(string), splitter)]
    decimal = []
    i = 0
    while i < 4:
        decimal.append(int(divided[i], 2))
        i = i + 1
    IPaddress = str(decimal[0])
    for i in range(1, 4):
        IPaddress = IPaddress + '.' + str(decimal[i])
    return str(IPaddress)


############### IP Conversion from Decimal to Bin ###############
def fromIPtoBinary(item):
    return '{0:08b}'.format(int(item.split(".")[0]))+'{0:08b}'.format(int(item.split(".")[1]))+'{0:08b}'.format(int(item.split(".")[2]))+'{0:08b}'.format(int(item.split(".")[3]))


def paddingAddress(list):
    i = 0
    padded_list = list
    while i < len(list):
        if len(list) < 8:
            while len(padded_list[i]) < 8:
                padded_list[i] = '0' + padded_list[i]
        i = i + 1
    return padded_list
###################################################################################################################


############### Incoming Packet Structure ###############
incomingPacket = {
    "sIP": None,
    "dIP": None,
    "proto": None,
    "sPort": None,
    "dPort": None,
    "sIP_b": None,
    "dIP_b": None,
}

############### Router/Switch Rule Structure ###############
routerSwithRule = {
    "Priority": None,
    "sNetID": None,
    "dNetID": None,
    "proto": None,
    "sPort": None,
    "dPort": None,
    "action": None,
    "sPrefix": None,
    "dPrefix": None,
}

############### Read a text file ###############


def readFile(string):
    with open(string, 'r') as handler:
        array_temp = [re.sub(r'\s*([,])\s*', r'\1', line).rstrip('\n')
                      for line in handler]
        return array_temp

############### Prefix creation ###############


def prefixBuilder(IP_MASK):
    list1, list2 = [], []
    list1 = IP_MASK[0].split(".")
    for items in list1:
        list2.append('{0:08b}'.format(int(items)))
    binaryIP = ''.join(list2)
    return binaryIP[:int(IP_MASK[1])]


############### Assigning IP List to the structure ###############
for each_element in readFile('incoming_packets.txt'):
    incomingPacket['sIP'] = each_element.split(",")[0]
    incomingPacket['dIP'] = each_element.split(",")[1]
    incomingPacket['proto'] = each_element.split(",")[2]
    incomingPacket['sPort'] = each_element.split(",")[3]
    incomingPacket['dPort'] = each_element.split(",")[4]
    incomingPacket['sIP_b'] = fromIPtoBinary(each_element.split(",")[0])
    incomingPacket['dIP_b'] = fromIPtoBinary(each_element.split(",")[1])
""" print ">>!Message:  Reading....IP List....Start Matching...." """

priorityCounter = 0
############### Assigning Rule List to the structure ###############
for each_element in readFile('rule_list.txt'):
    priorityCounter = priorityCounter + 1
    routerSwithRule['Priority'] = priorityCounter
    routerSwithRule['sNetID'] = each_element.split(",")[0]
    routerSwithRule['dNetID'] = each_element.split(",")[1]
    routerSwithRule['proto'] = each_element.split(",")[2]
    routerSwithRule['sPort'] = each_element.split(",")[3]
    routerSwithRule['dPort'] = each_element.split(",")[4]
    routerSwithRule['action'] = each_element.split(",")[5]
    
    if routerSwithRule['sNetID'] == "*":
        routerSwithRule['sPrefix'] = "*"
    
    else:
        routerSwithRule['sPrefix'] = prefixBuilder(
            [routerSwithRule['sNetID'].split("/")[0], routerSwithRule['sNetID'].split("/")[1]]) + '*'
    
    if routerSwithRule['dNetID'] == "*":
        routerSwithRule['dPrefix'] = "*"
    
    else:
        routerSwithRule['dPrefix'] = prefixBuilder(
            [routerSwithRule['dNetID'].split("/")[0], routerSwithRule['dNetID'].split("/")[1]]) + '*'
            
    print routerSwithRule
""" print ">>!Message:  Reading....Rule List....Start Drawing Trie...." """



###			    							   ###
#######									   #######
############### Test and Debugging ###############
""" if __name__ == "__main__": """

""" var = Tree() 

print var.finding_prefix('192.168.1.1') """

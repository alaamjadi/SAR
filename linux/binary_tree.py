import network_utils as nu

"""
Container for binary tree nodes
"""
class Node:
    value = None # used for debugging
    zero = None # zero child
    one = None # one child
    dst_root = None # If this node has sub-tier this field will contain its root refference
    end = False # True if any rules finished here, False otherwise
    node_rules = None
    
    def __init__(self, value="^", end=False):
        self.value = value
        self.end = end
        if self.end:
            self.node_rules = []

"""
This Method add second-tier nodes to the tree recursively
"""
def add_dst_nodes(node, dst_rule, index, rule_index):
    # reach end of the second-tier rules
    # we enter this if statement if we have finished all the rules.
    if len(dst_rule) <= index :
        # we don't have a new node
        if node.zero is None: 
            node.zero = Node("$",end=True)
        
        # We make the node.zero.end as True and clear the rules
        if not node.zero.end :
            node.zero.end = True
            node.zero.node_rules = []
        
        # We append the rule index becaue it was a match.
        node.zero.node_rules.append(rule_index)
        
        # Comes out from this function and goes to add_src_nodes() and then comes out again to the main.
        return
    
    # Add zero child
    if dst_rule[index] == "0":
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        add_dst_nodes(node.zero,dst_rule, index+1, rule_index)
    # Add one child
    else :
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        add_dst_nodes(node.one,dst_rule, index+1, rule_index)

"""
This Method add first-tier nodes to the tree recursively
"""
def add_src_nodes(node, src_rule, index, dst_rule, rule_index):
    # in case of src_sub='*' this block will execute and then next if statement will execute too.
    if src_rule is None:
        src_rule=[]
    
    # If we have * as src_binary or dst_binary and if we reached the last bit of src_binary
    # We enter this statement when we are finished with field1
    if len(src_rule) <= index :
        # in case of src_sub=10.0.0.0/24 dst_sub = '*' or src_sub='*' dst_sub = '10.0.0.0/24' or src_sub='*' dst_sub = '*'
        if dst_rule is None: # dst_sub_binary was None >> we had a * in the destination
            # if we have match
            if not node.end:
                #print(index, node.end, node.node_rules)
                node.node_rules = []

            node.end = True
            node.node_rules.append(rule_index) # append the rule index since it was a gray node
            #print(index, node.end, node.node_rules)
            return
        
        # add next-trie root to the tree
        if node.dst_root is None:
            # root of the 2nd triangle
            node.dst_root = Node(value="#")
        # create 2nd triangle
        add_dst_nodes(node.dst_root, dst_rule, 0, rule_index)
        return
    
    # add zero child recursive
    if src_rule[index] == "0":
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        add_src_nodes(node.zero,src_rule, index+1, dst_rule, rule_index)
    # add one child recursive
    else :
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        add_src_nodes(node.one,src_rule, index+1, dst_rule, rule_index)
        

"""
Depict the tree
"""
def show(root, indent="", has_zero=False):

    last_indent = "|--"
    if has_zero:
        last_indent = "--"
    elif root.value == "^":
        indent = ""
        last_indent = ""

    if not root.end:
        print("%s%svalue = %s" % (indent, last_indent, root.value))
    else:
        print("%s%svalue = %s, rules: %s" % (indent, last_indent, root.value, root.node_rules))

    if root.one is not None:
        if root.zero is None:
            show(root.one, indent + "   ")
        else:
            show(root.one, indent + "  |", True)
    if root.zero is not None:
        if root.dst_root is None:
            show(root.zero, indent + "  ")
        else:
            show(root.zero, indent + "  |", True)
    if root.dst_root is not None:
        show(root.dst_root, indent + "  ")
        
        
def match_dst(node, dst_bin, dst_index, candidate_actions):
#     print(node.value)
    if node.end :
        candidate_actions.extend(node.node_rules)
        # we should not return otherwise we can gave more end
    
    # if it's 32bits
    if dst_index > 32:
        #match final
        if node.zero.value == "$":
            #node_rules added
            candidate_actions.extend(node.zero.node_rules)
        return
    
    if node.zero is not None and (dst_bin[dst_index] == "0" or node.zero.value == "$"):
        fake_delay()
        match_dst(node.zero, dst_bin, dst_index+1, candidate_actions)
    if node.one is not None and dst_bin[dst_index] == "1":
        fake_delay()
        match_dst(node.one, dst_bin, dst_index+1, candidate_actions)
    return


def match_src(node, src_bin, src_index, dst_bin, dst_index, candidate_actions):
#     print(node.value)
    if node.end :
        #node_rules=[1,2] > [1,2,3]
        candidate_actions.extend(node.node_rules)
    
    #If src_incoming_IP matched with src_rule > 2nd tier
    if node.dst_root is not None:
        match_dst(node.dst_root, dst_bin, dst_index, candidate_actions)
    
    # we start from root
    # If it has a zero attribute
    if node.zero is not None and (src_bin[src_index] == "0" or node.zero.value == "$" ):
        fake_delay()
        match_src(node.zero, src_bin, src_index+1, dst_bin, dst_index, candidate_actions)
    #If it has a one attribute
    if node.one is not None and src_bin[src_index] == "1":
        fake_delay()
        match_src(node.one, src_bin, src_index+1, dst_bin, dst_index, candidate_actions)
    return

def get_packets_actions(root, packets, all_rules, debug):
    actions=[]
    noMatch = 0
    Matched = 0
    for packet in packets:
#         txt = input("Type something to test this out: ")
        candidate_actions = []
        match_src(root, packet.src_binary, 0, packet.dst_binary, 0, candidate_actions)
        
    
        final_actions = []
        
        for i in candidate_actions:
            if all_rules[i].protocol != '*' and all_rules[i].protocol != packet.protocol:
                continue
            if not nu.is_in_port_range(all_rules[i].src_port, packet.src_port):
                continue
            if not nu.is_in_port_range(all_rules[i].dst_port, packet.dst_port):
                continue
            final_actions.append(i)
        
        """ if debug:
            if len(final_actions) != 0:
                print("action picked: " + str(sorted(final_actions)[0]))
            else:
                print(final_actions)
                print("action picked: " + "No match!") """
        if len(final_actions) != 0:
            Matched = Matched + 1
            final_rule = all_rules[sorted(final_actions)[0]]
            """ print(
                "Packet>> ".ljust(10) +
                "sIP: %s".ljust(20) % (packet.src_ip) + 
                "dIP: %s".ljust(20) % (packet.dst_ip) +
                "protocol: %s".ljust(14) % (packet.protocol) +
                "sPort: %s".ljust(12) % (packet.src_port) +
                "dPort: %s".ljust(12) % (packet.dst_port) +
                "\n" +
                "Rule>>".ljust(10) +
                "sIP: %s".ljust(20) % (final_rule.src_sub) + 
                "dIP: %s".ljust(20) % (final_rule.dst_sub) +
                "protocol: %s".ljust(14) % (final_rule.protocol) +
                "sPort: %s".ljust(12) % (final_rule.src_port) +
                "dPort: %s".ljust(12) % (final_rule.dst_port) +
                "action: %s".ljust(20) % (final_rule.action) +
                "Priority: %s" %(str(sorted(final_actions)[0]+1)) +
                 "\n") """
            actions.append(all_rules[sorted(final_actions)[0]].action)
        else:
            noMatch = noMatch + 1
            #print("action picked: " + "No match!")
    print("%d".ljust(8) %Matched + "packets matched the rules.\n" + "%d".ljust(5) %noMatch + "packets did not match the rules.\n")
    return actions

def fake_delay():
    [0] * 200
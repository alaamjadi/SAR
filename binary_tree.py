import network_utils as nu

"""
Container for binary tree nodes
"""
class Node:
    value       = None
    zero        = None
    one         = None
    dst_root    = None
    end         = False
    node_rules  = None
    def __init__(self, value="^", end=False):
        self.value = value
        self.end = end
        self.node_rules = []

"""
This Method add second-tier nodes to the tree recursively
"""
def add_dst_nodes(node, dst_rule, index, rule_index):
    # Reached the last binary number
    if len(dst_rule) <= index :
        # We reached the end node, we can choose one of the attributes for assigning "$" sign. I have chosen attribute zero (left) as an indicator, it could be even attribute one (right). If there isn't any we create it.
        if node.zero is None: 
            node.zero = Node("$",end=True)
        # If there is already a node zero, change the end attribute to True.
        if not node.zero.end :
            node.zero.end = True
            #node.zero.node_rules = []
        # Adding the current rule to this node
        node.zero.node_rules.append(rule_index)
        return
    # Adding the left node
    if dst_rule[index] == "0":
        # Does this node has a left node? If no, create a new node as left
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        # Continue with adding nodes from the left node
        add_dst_nodes(node.zero,dst_rule, index+1, rule_index)
    # Adding the right node
    else :
        # Does this node has a right node? If no, create a new node as right
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        # Continue with adding nodes from the right node
        add_dst_nodes(node.one,dst_rule, index+1, rule_index)

"""
This Method add first-tier nodes to the tree recursively
"""
def add_src_nodes(node, src_rule, index, dst_rule, rule_index):
    # Rule.src_sub = *  => src_rule = None
    if src_rule is None:
        src_rule=[]
    # src_rule = [] which means src_sub=* or Reached the last binary number
    if len(src_rule) == index:
        # Checking if it is a root Tier 2 node. If not
        if dst_rule is None:
            # Is this node already gray (node.end=True)? If no, make the node_rules empty.
            if not node.end:
                node.node_rules = []
            # Making the node.end=True since we reached the end of Tier 1 and this is a gray node
            node.end = True
            # Adding the current rule to this node
            node.node_rules.append(rule_index)
            return
        # Is this already a root Tier 2 node? If no, add a new node as root Tier2
        if node.dst_root is None:
            node.dst_root = Node(value="#")
        #># Now go for the nodes in Tier 2
        add_dst_nodes(node.dst_root, dst_rule, 0, rule_index)
        return
    # Adding the left node
    if src_rule[index] == "0":
        # Does this node has a left node? If no, create a new node as left
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        # Continue with adding nodes from the left node
        add_src_nodes(node.zero, src_rule, index+1, dst_rule, rule_index)
    # Adding the right node
    else :
        # Does this node has a right node? If no, create a new node as right
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        # Continue with adding nodes from the right node
        add_src_nodes(node.one, src_rule, index+1, dst_rule, rule_index)

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

"""
Classification Algorithm - Matching the Tier 2 Nodes
"""        
def match_dst(node, dst_bin, dst_index, candidate_actions):
    # If the end attribute is True, It means we reached the end node in Tier 2, so we add its rules to candidate_actions list
    if node.end :
        candidate_actions.extend(node.node_rules)
    # If we reach the maximum number index, we add its rules to candidate_actions list and return
    if dst_index > 32:
        if node.zero.value == "$":
            candidate_actions.extend(node.zero.node_rules)
        return
    # It goes forward with the matching in case of having "0" as binary address. If the value is "$" it means we have reached the end and the node.zero.end is True, so it will be catched in next round.
    if node.zero is not None and (dst_bin[dst_index] == "0" or node.zero.value == "$"):
        match_dst(node.zero, dst_bin, dst_index+1, candidate_actions)
    # It goes forward with the matching in case of having "1" as binary address.
    if node.one is not None and dst_bin[dst_index] == "1":
        match_dst(node.one, dst_bin, dst_index+1, candidate_actions)
    return

"""
Classification Algorithm - Matching the Tier 1 Nodes, at the end jumps to the matching of Tier 2 nodes
""" 
def match_src(node, src_bin, src_index, dst_bin, dst_index, candidate_actions):
    # If the end attribute is True, It means we reached the end node in Tier 1, so we add its rules to candidate_actions list
    if node.end :
        candidate_actions.extend(node.node_rules)
    # If dst_root has a value it means it has the reference to root node for Tier 2
    if node.dst_root is not None:
        match_dst(node.dst_root, dst_bin, dst_index, candidate_actions)
    # It goes forward with the matching in case of having "0" as binary address. If the value is "$" it means we have reached the end and the node.zero.end is True, so it will be catched in next round.
    if node.zero is not None and (src_bin[src_index] == "0" or node.zero.value == "$" ):
        match_src(node.zero, src_bin, src_index+1, dst_bin, dst_index, candidate_actions)
    # It goes forward with the matching in case of having "1" as binary address.
    if node.one is not None and src_bin[src_index] == "1":
        match_src(node.one, src_bin, src_index+1, dst_bin, dst_index, candidate_actions)
    return

def get_packets_actions(root, packets, all_rules, debug):
    # This list contains all the incoming packet match results
    actions=[]
    # Counter for tracking the matches and no matches among all the incoming packets. The sum of this two is equal to all of the incoming nodes
    noMatch = 0
    Matched = 0
    # Running the Clasification Algorithm for every incoming packet
    for packet in packets:
        # This list contains all the possible matchs for Tier 1 and Tier 2 (Field 1 and 2)
        candidate_actions = []
        # Matching the incoming packet with the rule tree for the Tier 1 nodes (Filed 1). At the end it will jump to the Matching for the Tier 2 nodes (Field 2)
        match_src(root, packet.src_binary, 0, packet.dst_binary, 0, candidate_actions)
        # This list contains all the possible matchs for T1 & T2 and considering protocol and port matches too (Field 3  &  Field 4  &  Field 5)
        final_actions = []
        # Checking the candidates of one packet for other fields (protocol and port)
        # If there is no match here, it will continue in the loop over candiate_actions, it will check other candidates.
        # The outcome of this check is final_actions.
        for i in candidate_actions:
            if all_rules[i].protocol != '*' and all_rules[i].protocol != packet.protocol:
                continue
            if not nu.is_in_port_range(all_rules[i].src_port, packet.src_port):
                continue
            if not nu.is_in_port_range(all_rules[i].dst_port, packet.dst_port):
                continue
            final_actions.append(i)
        
        # Now we have all the full possible matches in the final_actions list.
        # If the list is empty, it means there were no matches.
        # If the list is not empty, we have to sort it by rule index number and choose the one with lower priority number.
        
        # In case we have a match
        if len(final_actions) != 0:
            Matched = Matched + 1
            # Sorting the matches and choosing the first one in the list
            final_rule = all_rules[sorted(final_actions)[0]]
            # Printing out the match result (Rule, Incoming Packet)
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
            # Adding the final match of each packets to the actions list
            actions.append(all_rules[sorted(final_actions)[0]].action)
        # In case we don't have a match
        else:
            noMatch = noMatch + 1
        #This loop iterates for all the incoming packets.
    # 
    print("%d".ljust(8) %Matched + "packets matched the rules.\n" + "%d".ljust(5) %noMatch + "packets did not match the rules.\n")
    return actions

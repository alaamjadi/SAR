import network_utils as nu

"""
Container for binary tree nodes
"""
class Node:
    value = None # used for debugging
    zero = None # zero child
    one = None # one child
    dst_root = None # If this node has sub-tier this field will contain its root refference
    end = False # True if all rules has finished here, False otherwise
    rules = None

    def __init__(self, value="^", end=False):
        self.value = value
        self.end = end
        if self.end:
            self.rules = []


"""
This method adds first-tier nodes to the trie recursively
"""
def add_src_nodes(node, rule, index, dst_rule, rule_index):
    
    # in case of src_sub='*' this block will execute
    if rule is None:
        rule=[]
    
    if len(rule) <= index :
        # in case of src_sub=10.0.0.0/24 dst_sub = '*' or src_sub='*' dst_sub = '10.0.0.0/24' or src_sub='*' dst_sub = '*'
        # this block will execute as well
        if dst_rule is None:
            if not node.end:
                node.rules = []
            
            node.end = True
            node.rules.append(rule_index)
            return
        
        # add next-trie root to the tree
        if node.dst_root is None:
            node.dst_root = Node(value="#")
        
        add_dst_nodes(node.dst_root, dst_rule, 0, rule_index)
        return
    
    # add zero child recursive
    if rule[index] == "0":
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        add_src_nodes(node.zero,rule, index+1, dst_rule, rule_index)
    
    # add one child recursive
    else :
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        add_src_nodes(node.one,rule, index+1, dst_rule, rule_index)


"""
This method adds second-tier nodes to the tree recursively
"""
def add_dst_nodes(node, rule, index, rule_index):
    # reach end of the second-tier add rules
    if len(rule) <= index :
        if node.zero is None:
            node.zero = Node("$",end=True)
            
        if not node.zero.end :
            node.zero.end = True
            node.zero.rules = []
        
        node.zero.rules.append(rule_index)
        return
    
    # Add zero child
    if rule[index] == "0":
        if node.zero is None:
            node.zero = Node(value=(node.value + "0"))
        add_dst_nodes(node.zero,rule, index+1, rule_index)

    # Add one child
    else :
        if node.one is None:
            node.one = Node(value=(node.value + "1"))
        add_dst_nodes(node.one,rule, index+1, rule_index)


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
        print("%s%svalue = %s, rules: %s" % (indent, last_indent, root.value, root.rules))

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

        
def match_dst(node, dst_bin, dst_index, actions):
    if node.end :
        actions.extend(node.rules)
    
    if dst_index >= 32:
        if node.zero.value == "$":
            actions.extend(node.zero.rules)
        return
    
    if node.zero is not None and dst_bin[dst_index] == "0":
        match_dst(node.zero, dst_bin, dst_index+1, actions)
        return

    if node.one is not None and dst_bin[dst_index] == "1":
        match_dst(node.one, dst_bin, dst_index+1, actions)
        return

    return


def match(node, src_bin, src_index, dst_bin, dst_index, actions):
    if node.end :
        actions.extend(node.rules)
        
    if node.dst_root is not None:
        match_dst(node.dst_root, dst_bin, dst_index, actions)
        
    if node.zero is not None and src_bin[src_index] == "0":
        match(node.zero, src_bin, src_index+1, dst_bin, dst_index, actions)
        return

    if node.one is not None and src_bin[src_index] == "1":
        match(node.one, src_bin, src_index+1, dst_bin, dst_index, actions)
        return

    return


def is_in_port_range(rule_port,packet_port):
    
    if "-" in rule_port:
        start = int(rule_port.split("-")[0])
        end = int(rule_port.split("-")[1])
        return start <= int(packet_port) and int(packet_port) <= end

    elif "*" == rule_port:
        return True

    else:
        return rule_port == packet_port


def get_packets_actions(root, packets, rules, debug):
    actions=[]

    for packet in packets:
        candidate_actions = []
        match(root, packet.src_binary, 0, packet.dst_binary, 0, candidate_actions)
    
        final_actions = []
    
        for i in candidate_actions:
            if rules[i].protocol != '*' and rules[i].protocol != packet.protocol:
                continue

            if not is_in_port_range(rules[i].src_port, packet.src_port):
                continue

            if not is_in_port_range(rules[i].dst_port, packet.dst_port):
                continue

            final_actions.append(i)
        
        if debug:
            print(final_actions)
            print("action picked: " + str(sorted(final_actions)[0]))
        actions.append(rules[sorted(final_actions)[0]].action)

    return actions
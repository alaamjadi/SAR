"""
Program Logic Helper
"""

# 1 read rules, create Rule objects and make the list of rule objects.
We read the packets with read_rulse() and put the results in a list called rules.
A Rule has the following attributes:
    src_sub         = None
    src_ip          = None
    src_netmask     = None
    src_sub_binary  = None
    dst_sub         = None
    dst_ip          = None
    dst_netmask     = None
    dst_sub_binary  = None
    src_port        = None
    dst_port        = None
    protocol        = None
    action          = None
We create the Rule objects by constructing it from class Rule().
: While creating the rules, we directly put the src_sub, dst_sub, protocol, src_port, dst_port and action inside their attributs.
We check the values of the src_sub and dst_sub attributes,
if they have the value= "*" then we dont change the src_sub_binary and dst_sub_binary values and they remain as None.
Otherwise we calculate the binary values with using extract_info() function.
So at the end the rules list contains a list of Rule objects.


# 2 create a tree object
a Node class has the following attributes:
    value   = None
    zero    = None  When we have a binary value of zero, in the tree we want to go on left
    one     = None  When we have a binary value of one, in the tree we want to go on right
    dst_root= None  When we have sub tree for the field 2, this field will contain its root reference
    end     = False  If evaluation of the rules are finished for this node we make it True
    rules   = None
We create the first node by constructing it from class Node(). We call this Node, root.
At the beginning we assign the value="^" and end=False as defined in __init__ method.
While we are creating the Node() if the end attribute is True, we will make the rules attribute, as an empty list rules = []

# 3 creating the list of source and destination binary prefixes
We go through the rule list that we made at step1 and extract the values of src_sub_binary and dst_sub_binary attributes.
We create two new lists and we call them src_sub_binaries and dst_sub_binaries. In case th src_sub or dst_sub was * in step1, we will have None value in these two lists.

# adding nodes for field1
We call the function add_src_nodes() which is a recursive function, it iterates inside itself and when its done it will call the add_dst_nodes().
We iterate over src_sub_binaries list items and pass each element of src_sub_binaries and dst_sub_binaries as input to the add_src_nodes() function.
.for the first time we pass the root object Node() as the input node to this function and then we will change the input node along the adding procedure.
When we call add_src_nodes() function, we check 4 if statements.
def add_src_nodes(node = root, src_rule = src_sub_binaries, index = 0, dst_rule, rule_index):
    if src_rule (which is the src_sub_binaries) == "0":
        we check if we already had zero attribute in the node:
            if not we will change the node.zero attribute to a new Node() object with a value of the old node.value conactinated with a zero ("0")
    if src_rule (which is the src_sub_binaries) == "1":
        we check if we already had one attribute in the node:
            if not we will change the node.one attribute to a new Node() object with a value of the old node.value conactinated with a one ("1")
    > We do this till we reach the len(src_rule, which is the number of bits aka prefix)==index. This means we have finished field1 of one rule
    Now we have to add the 
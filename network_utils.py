import random

"""
This method extracts IP, netmask and binary representation of IP from its subnet.
"""
def extract_info(sub):
    sub = sub.split('/')
    ip = sub[0]
    netmask = int(sub[1])
    binary = ip_to_binary(ip)[:netmask] 
    return ip, netmask, binary


"""
This method converts ip to its binary representation.
"""
def ip_to_binary(ip):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])


"""
This class stores rule information and its metadata. Metadatas are calculated in the constructor
"""
class Rule:
    src_sub = None
    src_ip = None
    src_netmask = None
    src_sub_binary = None

    dst_sub = None
    dst_ip = None
    dst_netmask = None
    dst_sub_binary = None
    
    src_port = None
    dst_port = None
    protocol = None
    action = None

    def __init__(self, src_sub, dst_sub, protocol, src_port, dst_port, action):
        self.src_sub = src_sub
        self.dst_sub = dst_sub
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action
        
        if self.src_sub is not '*':
            self.src_ip, self.src_netmask, self.src_sub_binary = extract_info(self.src_sub)
            
        if self.dst_sub is not '*':
            self.dst_ip, self.dst_netmask, self.dst_sub_binary = extract_info(self.dst_sub)


"""
This method read all rules from a file.
"""
def read_rules(rule_file_path):
    rules = []
    rules_file = open(rule_file_path, 'r') 
    rules_raw = rules_file.readlines() 
        
    for line in rules_raw: 
        tmp = [elem.strip() for elem in line.split(",")]
        rules.append(Rule(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]))
    return rules


"""
This class stores packet informations and its metadata. Metadatas are calculated in constructor
"""
class Packet:
    src_ip = None
    dst_ip = None
    protocol = None
    src_port = None
    dst_port = None
    
    src_binary = None
    dst_binary = None
    
    def __init__(self, src_ip, dst_ip, protocol, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port 
        
        self.src_binary = ip_to_binary(src_ip)
        self.dst_binary = ip_to_binary(dst_ip)


"""
This method reads all the incoming packets from a file.
"""
def read_packets(packet_file_path):
    packets = []
    packet_file = open(packet_file_path, 'r') 
    packets_raw = packet_file.readlines()

    for packet in packets_raw: 
        tmp = [elem.strip() for elem in packet.split(",")]
        packets.append(Packet(tmp[0],tmp[1], tmp[2], tmp[3], tmp[4]))
    return packets


"""
This method generates random IPs.
"""
def generate_random_ip():
    return "17." + ".".join(map(str, (random.randint(0, 255) for _ in range(3))))


"""
This method generates random packet list using generate_random_ip() method.
"""
def packet_generator():
    src_ip = generate_random_ip()
    dst_ip = generate_random_ip()
    protocol = random.randint(0, 255)

    src_port = random.randint(0, 65535)
    dst_port = random.randint(0, 65535)
    return "%s,%s,%s,%d,%d" % (src_ip, dst_ip, protocol, src_port, dst_port)


"""
This method generates random packet file using packet_generator() method.
"""
def generate_random_packet_file(file_name, count):
    f = open(file_name, "w")
    for i in range(0,count):
        f.write(packet_generator()+"\n")
    f.close()
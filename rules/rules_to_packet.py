import random

"""
This method generates a random Net ID.
"""
def generate_random_netID(prefix):
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))+"/"+str(prefix)

"""
This method generates a random rule.
"""
def rule_generator(prefix):
    src_ip = generate_random_netID(prefix)
    dst_ip = generate_random_netID(prefix)
    protocol = random.randint(0, 255)
    src_port = random.randint(0, 65535)
    dst_port = random.randint(0, 65535)
    action = random.choice(["ALLOW", "DENY"])
    return "%s,%s,%s,%d,%d,%s" % (src_ip, dst_ip, protocol, src_port, dst_port, action)

"""
This method generates a rule file with a specified number of random rules.
"""
def generate_random_rule_file(file_name, count, prefix):
    f = open(file_name, "w")
    for i in range(0,count):
        f.write(rule_generator(prefix)+"\n")
    f.close()

"""
This method read all rules from a file.
"""
def makeSpecialPackets(rule_file_path):
    rules_file = open(rule_file_path, 'r') 
    rules_raw = rules_file.readlines() 
    
    f = open("packets_special.txt", "a")
    for line in rules_raw: 
        tmp = [ elem.strip() for elem in line.split(",")]
        f.write(tmp[0].split("/")[0]+","+tmp[1].split("/")[0]+","+ tmp[2]+","+ tmp[3]+","+ tmp[4]+"\n")
    f.close()

# creating separate rule files for prefixes from 1 to 32
for i in range(1,33):
    makeSpecialPackets("Rule_"+ f"{i:02d}" +".txt")
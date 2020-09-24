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
    return "%s,%s,%d,%d,%d,%s" % (src_ip, dst_ip, protocol, src_port, dst_port, action)

"""
This method generates a rule file with a specified number of random rules.
"""
def generate_random_rule_file(file_name, count, prefix):
    f = open(file_name, "w")
    for i in range(0,count):
        f.write(rule_generator(prefix)+"\n")
    f.close()

# creating separate rule files for prefixes from 1 to 32
for i in range(1,33):
    generate_random_rule_file("Rule_" + f"{i:02d}" + ".txt",100, i)











"""
This method generates a random Net ID.
"""
def gen_random_IP():
    return ".".join(map(str, (random.randint(1, 255) for _ in range(4))))


"""
This method generates a random rule.
"""
def rule_genLookAlike(startPrefix, endPrefix):
    src_ip = gen_random_IP()
    dst_ip = gen_random_IP()
    RuleList = []
    for i in range(startPrefix,endPrefix+1):
        src_netID = src_ip + "/" + str(i)
        dst_netID = dst_ip + "/" + str(i)
        protocol = random.randint(0, 255)
        src_port = random.randint(0, 65535)
        dst_port = random.randint(0, 65535)
        action = random.choice(["ALLOW", "DENY"])
        RuleList.append(("%s,%s,%s,%d,%d,%s" % (src_netID, dst_netID, protocol, src_port, dst_port, action)))
    return RuleList


"""
This method generates a rule file with a specified number of random rules.
"""
def gen_rule_LookAlike_file(file_name, startPrefix, endPrefix):
    tmp = rule_genLookAlike(startPrefix, endPrefix)
    f = open(file_name + str(startPrefix) + "-" + str(endPrefix) + ".txt", "w")
    for i in range(len(tmp)):
        f.write(tmp[i]+"\n")
    f.close()

# creating mixed rule list
#print (rule_genLookAlike(1,10))
gen_rule_LookAlike_file("Rule_LookAlike",20,30)
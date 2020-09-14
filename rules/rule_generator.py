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

# creating separate rule files for prefixes from 1 to 32
for i in range(1,33):
    generate_random_rule_file("Rule_"+str(i)+".txt",100, i)
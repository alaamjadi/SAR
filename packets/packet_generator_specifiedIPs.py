import random

"""
This method generates a random IP address.
"""
def generate_random_ip(firstOctet):
    return str(firstOctet) + ".".join(map(str, (random.randint(0, 255) for _ in range(3))))

"""
This method generates a random packet.
"""
def packet_generator(firstOctet):
    src_ip = generate_random_ip(firstOctet)
    dst_ip = generate_random_ip(firstOctet)
    protocol = random.randint(0, 255)
    src_port = random.randint(0, 65535)
    dst_port = random.randint(0, 65535)
    return "%s,%s,%s,%d,%d" % (src_ip, dst_ip, protocol, src_port, dst_port)

"""
This method generates a packet file with a specified number of random packets.
"""
def generate_random_packet_file(file_name, count):
    f = open(file_name, "w")
    for i in range(0,count):
        f.write(packet_generator("192")+"\n")
    f.close()

# creating a packet file with 100k entries
generate_random_packet_file("packets.txt",100000)
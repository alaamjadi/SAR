import network_utils as nu

for i in range(7,8):
    nu.generate_random_packet_file("random"+str(i)+str(".txt"),10**i)
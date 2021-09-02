# This python script takes as input the txt file which contains information about the packet size and forms  frequency# table for each of the packet size

if __name__ == '__main__':
    packet_info = open('hw1q14.txt','r')
    reader = packet_info.read().strip()
    packets = reader.split('\n')
    packet_size_map = {}
    for packet in packets:
        sub = (packet[packet.find('length ')+len('length '):])
        length = int(sub[:sub.find(':')])
        if length in packet_size_map:
            packet_size_map[length] += 1
        else:
            packet_size_map[length] = 1
    print ('Packet Size\tFrequency')
    for packet_size in packet_size_map:
        print (packet_size,'\t\t', packet_size_map[packet_size])

import struct 

def checksum(data):
   
    sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        sum += word
    while (sum >> 16) != 0:
        sum = (sum & 0xFFFF) + (sum >> 16)
    return struct.pack('!H', ~sum & 0xFFFF)

def string_to_bytes(string):
  return int(string, 2).to_bytes(len(string) // 8, byteorder='big')

packet_type = "00001000" 
packet_code = "00000000"
packet_checksum = "0000000000000000"
packet_ID = "1010101010101010"
packet_sequence = "0101010101010101"
packet = packet_type + packet_code + packet_checksum + packet_ID + packet_sequence 

print (checksum(string_to_bytes(packet)))



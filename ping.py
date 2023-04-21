import socket
import struct
import time
import sys

if (len(sys.argv) < 2):
    print("An IP adress to ping is required. Use the command 'help' for more info")
    exit()

if (sys.argv[1] == "help"):
    print("help text")




#function to get local ip adress
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # open test socket to get local ip adress
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        #exception, this is not the normal case nor is it useful
        IP = '127.0.0.1'
    finally:
        s.close()
    #return the local IP adress 
    return IP

#function that converts ip adress to binary string
def ip_to_bytes(ip_adress):
    binary_adress = bytearray()
    #spilt ip adress by periods
    ip_adress = ip_adress.split(".")
    for number in ip_adress :
        binary_adress += int(number).to_bytes(1, "little")
    return binary_adress

#simplest way to convert string (of multiple of 8) to bytes
def string_to_bytes(string):
  return int(string, 2).to_bytes(len(string) // 8, byteorder='big')


#different checksum that uses bytearrays instead
#works properly on my system and is easier to use with the rest of my code
#due to less conversions
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        sum += word
    while (sum >> 16) != 0:
        sum = (sum & 0xFFFF) + (sum >> 16)
    return struct.pack('!H', ~sum & 0xFFFF)

source_ip = get_local_ip()
dest_ip = socket.gethostbyname(sys.argv[1])


packet_type = b'\x08'
packet_code = b'\x00'
packet_checksum = b'\x00\x00'
packet_ID = b'\xaa\xaa'
packet_sequence = b'\xff\xff'
packet_data = str(time.time()).encode()
packet = packet_type + packet_code + packet_checksum + packet_ID + packet_sequence + packet_data

print(packet)
packet_checksum = checksum(packet)
print(packet_checksum)
packet = packet_type + packet_code + packet_checksum + packet_ID + packet_sequence +packet_data






ip_header  = b'\x45\x00\x00\x1c'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x01\xa6\x00'  # TTL, Protocol | Header Checksum
ip_header += ip_to_bytes(source_ip) # Source Address
ip_header += ip_to_bytes(dest_ip)  # Destination Address



packet = ip_header + packet
    
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
#s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.settimeout(1) #waiting a bit longer because program was missing quite a few packets
while True:
    print("pinging " + str(dest_ip))
    
    x = s.sendto(packet, (dest_ip,0))
    print(str(x) + " bytes sent")
    
    
    try:
        message = s.recv(100)
        print("receved packet length" + str(len(message)))

    except socket.timeout:
        print("Packet Lost")
        break

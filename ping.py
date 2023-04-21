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


#provided checksum function
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer 

source_ip = get_local_ip()
dest_ip = '127.0.0.1'	# or socket.gethostbyname('www.google.com')

packet_padding = str(format(0, '0160b'))
packet_type = "00001000" 
packet_code = "00000000"
packet_checksum = "0000000000000000"
packet_ID = "1010101010101010"
packet_sequence = "0101010101010101"
packet = packet_type + packet_code + packet_checksum + packet_ID + packet_sequence 

packet_checksum = str(format(checksum(packet), '08b'))
packet = packet_type + packet_code + packet_checksum + packet_ID + packet_sequence 
packet = string_to_bytes(packet)





ip_header  = b'\x45\x00\x00\x1c'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x01\xa6\x00'  # TTL, Protocol | Header Checksum
ip_header += ip_to_bytes(source_ip) # Source Address
ip_header += ip_to_bytes(dest_ip)  # Destination Address



packet = ip_header + packet
    
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
while True:
    print("sending ping")
    
    x = s.sendto(packet, ("10.0.0.1",0))
    print(x)
    time.sleep(.1)
    
"""
    try:
        print("recieving")
        message = s.recv(64).decode()
        print(message)
        s.decode

    finally:
        exit()
"""
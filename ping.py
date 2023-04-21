import socket
import struct
import time
import sys
import random

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
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    for count in range(0, countTo, 2):
        thisVal = string[count+1] * 256 + string[count]
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

def create_ICMP_packet(packet_type, packet_code, packet_checksum, packet_ID, packet_sequene, packet_data):
    
    
    ICMP_packet = struct.pack("!BBHHH", packet_type, packet_code, packet_checksum, packet_ID, packet_sequene)
    ICMP_packet = ICMP_packet + packet_data
    packet_checksum = checksum(ICMP_packet)
    print("Packet cheskcusm: " + str(packet_checksum))
    ICMP_packet = struct.pack("!BBHHH", packet_type, packet_code, packet_checksum, packet_ID, packet_sequene) + packet_data
    
    return ICMP_packet



def create_IP_header():
    ip_header  = b'\x45\x00\x00\x1c'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x01\xa6\x00'  # TTL, Protocol | Header Checksum
    ip_header += ip_to_bytes(source_ip) # Source Address
    ip_header += ip_to_bytes(dest_ip)  # Destination Address
    return ip_header

source_ip = get_local_ip()
dest_ip = socket.gethostbyname(sys.argv[1])














    
s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_ICMP)
#s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.settimeout(1) 
sequence_counter = 0
packet_id = random.randint(0,1000)
while True:
    print("pinging " + str(dest_ip))
    timestamp = struct.pack("!d",time.time())
    
    packet = create_ICMP_packet(8, 0, 0, packet_id, sequence_counter, timestamp) #packet type, packet code, packet checksum, packet id, sequence, payload
    
    x = s.sendto(packet, (dest_ip,0))
    
    
    
    try:
        message = s.recv(50) #using 50 bytes for buffer because that is full packet size with all internet headers
        print("receved packet length" + str(len(message[20:])))

        recieved_ICMP_type, recieved_ICMP_code, recieved_ICMP_checksum, recieved_ICMP_id, recieved_ICMP_sequence, recieved_ICMP_payload = struct.unpack("!BBHHHd", message[20:])
        expected_checksum = checksum(struct.pack("!BBHHHd", recieved_ICMP_type, recieved_ICMP_code, 0, recieved_ICMP_id, recieved_ICMP_sequence, recieved_ICMP_payload))
        if(recieved_ICMP_type == 0 and recieved_ICMP_code == 0 and recieved_ICMP_checksum == expected_checksum and recieved_ICMP_id == packet_id and recieved_ICMP_sequence == sequence_counter):
            response_time = round((time.time() - recieved_ICMP_payload) * 1000)
            print("{} bytes from {} ({}): icmp_seq={} time={} ms".format(len(message), sys.argv[1], dest_ip, recieved_ICMP_sequence, response_time))
        else:
            print("invalid packet recieved")

        time.sleep(1) # after successful recieve in time under timeout, wait to prevent packet spam
        sequence_counter += 1

    except socket.timeout:
        print("Packet Lost")
        sequence_counter += 1
        break

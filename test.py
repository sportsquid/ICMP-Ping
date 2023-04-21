import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def ip_to_bytes(ip_adress):
    binary_adress = bytearray()
    #spilt ip adress by periods
    ip_adress = ip_adress.split(".")
    for number in ip_adress :
        binary_adress += int(number).to_bytes(1, "little")
    return binary_adress

source_ip = "192.168.1.9"
dest_ip = "127.0.0.1"

ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
ip_header += ip_to_bytes(source_ip) # Source Address
ip_header += ip_to_bytes(dest_ip)  # Destination Address

tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
tcp_header += b'\x00\x00\x00\x00' # Sequence Number
tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer
print(ip_header)
packet = ip_header + tcp_header

while True:

    s.sendto(packet, ('10.10.10.1', 0))
    time.sleep(.2)


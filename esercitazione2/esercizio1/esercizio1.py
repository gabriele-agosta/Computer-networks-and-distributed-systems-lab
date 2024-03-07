import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Linux Kernel specification


ip_header = b"\x45\x00\x00\x28"
ip_header += b"\xab\xcd\x00\x00"
ip_header += b"\x40\x06\xa6\xec"
ip_header += b"\x0a\x0a\x0a\x02"
ip_header += b"\x0a\x0a\x0a\x01"

tcp_header = b"\x30\x39\x00\x50"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x50\x02\x71\x10"
tcp_header += b"\xe6\x32\x00\x00"

packet = ip_header + tcp_header
s.sendto(packet, ("localhost", 0))
s.close()
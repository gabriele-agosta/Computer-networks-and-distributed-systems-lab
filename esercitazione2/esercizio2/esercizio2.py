import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("lo", 0))

ethernet_header = b"\x00\x0c\x29\xd3\xbe\xd6"  
ethernet_header += b"\x00\x0c\x29\xe0\xc4\xaf"  
ethernet_header += b"\x08\x00"  

ip_header = b"\x45\x00\x00\x28"
ip_header += b"\xab\xcd\x00\x00"
ip_header += b"\x40\x06\xa6\xec"
ip_header += b"\x0a\x0a\x0a\x02"
ip_header += b"\x0a\x0a\x0a\x01"
print(ip_header)

tcp_header = b"\x30\x39\x00\x50"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x50\x02\x71\x10"
tcp_header += b"\xe6\x32\x00\x00"

packet = ethernet_header + ip_header + tcp_header
s.send(packet)
s.close()
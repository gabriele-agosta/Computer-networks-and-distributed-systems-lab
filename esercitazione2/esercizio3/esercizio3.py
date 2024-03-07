import socket
import zlib

class EthernetHeader:
    def __init__(self, dest, src, protocol):
        self.dest = dest
        self.src = src
        self.protocol = protocol
        self.checksum = self.evaluateChecksum()

    def getValue(self):
        return self.dest + self.src + self.protocol + self.checksum.to_bytes(4, byteorder='big')

    def evaluateChecksum(self):
        header_bytes = b""
        header_bytes += self.dest
        header_bytes += self.src
        header_bytes += self.protocol

        checksum = zlib.crc32(header_bytes) & 0xFFFFFFFF
        return checksum

class IPHeader:
    def __init__(self, version, ihl, tos, total_length, identification, flags, offset, ttl, protocol, source_ip, dest_ip):
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.protocol = protocol
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.checksum = self.evaluateChecksum()

    def evaluateChecksum(self):
        header_bytes = b""

        header_bytes += ((self.version << 4) + self.ihl).to_bytes(1, byteorder='big')
        header_bytes += bytes([self.tos])
        header_bytes += self.total_length.to_bytes(2, byteorder='big')
        header_bytes += self.identification.to_bytes(2, byteorder='big')
        offset_value = ((self.flags << 13) + self.offset)
        header_bytes += offset_value.to_bytes(2, byteorder='big')
        header_bytes += self.ttl.to_bytes(1, byteorder='big')
        header_bytes += bytes([self.protocol])
        header_bytes += b"\x00\x00"
        header_bytes += bytes(map(int, self.source_ip.split('.')))
        header_bytes += bytes(map(int, self.dest_ip.split('.')))

        checksum = 0
        for i in range(0, len(header_bytes), 2):
            checksum += (header_bytes[i] << 8) + header_bytes[i + 1]

        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = 0xFFFF - checksum
        print(f"Checksum IP: {hex(checksum)}")
        return checksum

    def getValue(self):
        version_ihl = (self.version << 4) + self.ihl
        return version_ihl + self.tos + self.total_length + self.identification + self.flags + self.offset + self.ttl + self.protocol + self.checksum + int(self.source_ip.replace('.', '')) + int(self.dest_ip.replace('.', ''))

class TCPHeader:
    def __init__(self, source_port, dest_port, seq_num, ack_num, offset, ns, cwr, ece, urg, ack, psh, rst, fin, syn, win_size, urg_pointer, ip_header):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.offset = offset
        self.ns = ns
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.fin = fin
        self.syn = syn
        self.win_size = win_size
        self.urg_pointer = urg_pointer
        self.checksum = self.evaluateChecksum(ip_header.protocol, ip_header.source_ip, ip_header.dest_ip, 20)
    
    def evaluateChecksum(self, protocol, source_ip, dest_ip, tot_len):
        header_bytes = b""

        header_bytes += protocol.to_bytes(2, byteorder='big')
        header_bytes += bytes(map(int, source_ip.split('.')))
        header_bytes += bytes(map(int, dest_ip.split('.')))
        header_bytes += tot_len.to_bytes(2, byteorder='big')
        header_bytes += self.source_port.to_bytes(2, byteorder='big')
        header_bytes += self.dest_port.to_bytes(2, byteorder='big')
        header_bytes += self.seq_num.to_bytes(4, byteorder='big')
        header_bytes += self.ack_num.to_bytes(4, byteorder='big')
        # header_bytes += ((self.offset << 4) | (self.ns << 3) | (self.cwr << 7) | (self.ece << 6) | (self.urg << 5) | (self.ack << 4) | (self.psh << 3) | (self.rst << 2) | (self.fin << 0) | (self.syn << 1)).to_bytes(2, byteorder='big')
        header_bytes += b"\x50\x02\x71\x10"
        #header_bytes += self.win_size.to_bytes(2, byteorder='big')
        header_bytes += (0).to_bytes(2, byteorder='big')
        header_bytes += self.urg_pointer.to_bytes(2, byteorder='big')

        checksum = 0
        for i in range(0, len(header_bytes), 2):
            if i + 1 < len(header_bytes):
                checksum += (header_bytes[i] << 8) + header_bytes[i + 1]

        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = 0xFFFF - checksum
        print(f"Checksum TCP: {hex(checksum)}")
        return checksum

    def getValue(self):
        return self.source_port + self.dest_port + self.seq_num + self.ack_num + self.offset + self.ns + self.cwr + self.ece + self.urg + self.ack + self.psh + self.rst + self.fin + self.syn + self.win_size + self.checksum + self.urg_pointer


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("lo", 0))

ethernet_header = EthernetHeader(b"\x00\x0c\x29\xd3\xbe\xd6", b"\x00\x0c\x29\xe0\xc4\xaf", b"\x08\x00")
ip_header = IPHeader(4, 5, 0, 40, 43981, 0, 0, 64, 6, "10.10.10.2", "10.10.10.1")
tcp_header = TCPHeader(12345, 80, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1, 0, 28944, 0, ip_header)
print(ip_header.getValue())
'''
tcp_header = b"\x30\x39\x00\x50"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x00\x00\x00\x00"
tcp_header += b"\x50\x02\x71\x10"
tcp_header += b"\xe6\x32\x00\x00"
print(tcp_header)
'''

packet = ethernet_header.getValue() + ip_header.getValue().to_bytes(20, 'big') + tcp_header.getValue().to_bytes(20, 'big')
s.send(packet)
s.close()
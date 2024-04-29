from dataclasses import dataclass
from pprint import pprint
import struct
from zlib import crc32


@dataclass
class Packet:
    header: int
    src: int
    dst: int
    seq_no: int
    length: int
    data: bytes
    crc: int

    @property
    def correct(self):
        return self.expected_crc == self.crc

    @property
    def expected_crc(self):
        return crc32(self.src.to_bytes(2, "big") + self.dst.to_bytes(2, "big") + self.seq_no.to_bytes(1, "big") + self.length.to_bytes(1, "big") + self.data)


def parse_packet(bytestream):
    [h1, h2, s1, s2, d1, d2, no, l, *rest] = bytestream
    header = (h1 << 8) + h2
    src = (s1 << 8) + s2
    dst = (d1 << 8) + d2
    data = bytes(rest[:l])
    cs = rest[l:l+4]
    try:
        cs = struct.unpack('>I', bytes(cs))[0]
        packet = Packet(header, src, dst, no, l, data, cs)
    except struct.error:
        cs = None
        packet = Packet(header, src, dst, no, l, data, cs)
        packet.crc = packet.expected_crc
    return packet, rest[l+4:]


def bits_to_bytes(bitstring):
    return bytes([int(''.join(bitstring[i:i+8]), 2) for i in range(0, len(bitstring), 8)])


with open('bitstring', 'rt') as f:
    data = bits_to_bytes([x.strip() for x in f.read().strip().split(',') if x.strip() != ''])

packets = {}

while len(data) > 0:
    packet, data = parse_packet(data)
    seq_no = packet.seq_no
    if packet.correct:
        if packets.get(seq_no) is None:
            packets[seq_no] = []
        packets[seq_no].append(packet)

lo_seqno = min(packets.keys())
hi_seqno = max(packets.keys())
assert len(packets) == hi_seqno - lo_seqno + 1

flag = b''

options = [v for k, v in sorted(packets.items())]

for op in options:
    assert len(op) == 1
    flag += op[0].data

print(flag.decode())

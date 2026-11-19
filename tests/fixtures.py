"""Hand-built wire fixtures; deliberately independent of the decoder."""
import socket
import struct


def ethernet(body, kind=0x0800):
    return bytes.fromhex('00112233445566778899aabb') + struct.pack('!H', kind) + body


def ipv4(body, proto=6, src='192.0.2.1', dst='198.51.100.2', fragment=0):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(body), 1, fragment, 64,
                       proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + body


def tcp(data=b'', seq=100, ack=0, flags=0x18, sport=45678, dport=8080):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data


def udp(data=b'', sport=53000, dport=53):
    return struct.pack('!HHHH', sport, dport, 8+len(data), 0) + data


def ipv6(body, proto=17):
    return struct.pack('!IHBB16s16s', 6<<28, len(body), proto, 64,
                       socket.inet_pton(socket.AF_INET6, '2001:db8::1'), socket.inet_pton(socket.AF_INET6, '2001:db8::2')) + body


def dns_query():
    return bytes.fromhex('123401000001000000000000') + b'\x07example\x03com\x00\x00\x01\x00\x01'


def http_packet(data=b'GET /lab HTTP/1.1\r\nHost: example.test\r\n\r\n', **kwargs):
    return ethernet(ipv4(tcp(data, **kwargs)))

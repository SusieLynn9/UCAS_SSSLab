import struct
import unittest
from tests.fixtures import *
from sniffer.protocols import decode_packet

class ProtocolTests(unittest.TestCase):
    def decode(self, b, lt=1):
        return decode_packet(b, lt, 1.25, len(b))

    def test_http_detected_on_nonstandard_port(self):
        p=self.decode(http_packet())
        self.assertEqual((p['src'],p['dst'],p['sport'],p['dport']), ('192.0.2.1','198.51.100.2',45678,8080))
        self.assertEqual(p['protocol'],'HTTP')
        self.assertIn('GET /lab', p['info'])
        self.assertEqual(p['tcp_seq'],100)
        self.assertEqual(p['payload'], b'GET /lab HTTP/1.1\r\nHost: example.test\r\n\r\n')
        self.assertIn('IPv4',p['layers'])

    def test_ipv6_dns_uses_payload(self):
        p=self.decode(ethernet(ipv6(udp(dns_query(),dport=5353)),0x86dd))
        self.assertEqual(p['protocol'],'DNS')
        self.assertIn('example.com',p['info'])
        self.assertEqual(p['src'],'2001:db8::1')

    def test_vlan_and_loopback(self):
        b=ethernet(struct.pack('!HH',42,0x0800)+ipv4(tcp()),0x8100)
        self.assertIn('VLAN',self.decode(b)['layers'])
        p=self.decode(struct.pack('=I',2)+ipv4(tcp()),0)
        self.assertEqual(p['transport'],'TCP')

    def test_icmp_and_noninitial_fragment_not_tcp(self):
        self.assertEqual(self.decode(ethernet(ipv4(b'\x08\x00\x00\x00'+b'\x00'*4,1)))['protocol'],'ICMP')
        p=self.decode(ethernet(ipv4(tcp(),fragment=1)))
        self.assertNotIn('TCP',p['layers'])
        self.assertIn('fragment',p['info'].lower())

    def test_truncated_headers_and_bogus_lengths_never_crash(self):
        b=http_packet()
        for n in range(len(b)):
            p=self.decode(b[:n])
            self.assertIsInstance(p['warnings'],list)
        p=self.decode(ethernet(b'\x45\x00\x00\x01'+b'\x00'*16))
        self.assertTrue(p['warnings'])

    def test_dns_pointer_cycle_is_bounded(self):
        b=bytes.fromhex('123401000001000000000000c00c00010001')
        p=self.decode(ethernet(ipv4(udp(b),17)))
        self.assertTrue(p['warnings'])

    def test_ipv6_hop_by_hop_and_fragment(self):
        body=b'\x06\x00'+b'\x00'*6+tcp()
        p=self.decode(ethernet(ipv6(body,0),0x86dd))
        self.assertEqual(p['transport'],'TCP')
        body=b'\x06\x00\x00\x08'+b'\x00'*4+tcp()
        p=self.decode(ethernet(ipv6(body,44),0x86dd))
        self.assertNotIn('TCP',p['layers'])

    def test_tls_clienthello_sni(self):
        name=b'example.test'
        sni=struct.pack('!H',len(name)+3)+b'\x00'+struct.pack('!H',len(name))+name
        ext=struct.pack('!HH',0,len(sni))+sni
        hello=b'\x03\x03'+bytes(32)+b'\x00\x00\x02\x13\x01\x01\x00'+struct.pack('!H',len(ext))+ext
        handshake=b'\x01'+len(hello).to_bytes(3,'big')+hello
        record=b'\x16\x03\x01'+struct.pack('!H',len(handshake))+handshake
        p=self.decode(http_packet(record))
        self.assertEqual(p['protocol'],'TLS')
        self.assertIn('example.test',p['info'])

import tempfile
import unittest
from pathlib import Path
from sniffer.pcap import Pcap, PcapError, write_pcap
from tests.fixtures import http_packet, ethernet, ipv4, udp

class PcapTests(unittest.TestCase):
    def test_offline_roundtrip_and_real_bpf(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x.pcap'; packets=[(1.25,http_packet(),None),(2.5,ethernet(ipv4(udp(b'hi'),17)),None)]
            write_pcap(path,1,packets)
            with Pcap.offline(path,'tcp and port 8080') as cap:
                rows=list(cap)
                self.assertEqual(cap.linktype,1)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0][1],http_packet())
            self.assertAlmostEqual(rows[0][0],1.25,places=6)
            with self.assertRaises(PcapError):Pcap.offline(path,'tcp and (')
    def test_devices_enumerated_by_libpcap(self):
        self.assertIn('lo0',[v['name'] for v in Pcap.devices()])
    def test_bad_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad';p.write_bytes(b'not a pcap')
            with self.assertRaises(PcapError):Pcap.offline(p)

import unittest
from sniffer.flows import FlowTracker
from sniffer.protocols import decode_packet
from tests.fixtures import http_packet

class FlowTests(unittest.TestCase):
    def setUp(self): self.t=FlowTracker()
    def add(self,data=b'',seq=100,flags=0x18,reverse=False):
        p=decode_packet(http_packet(data,seq=seq,flags=flags),1,1.0,100)
        p['id']=len(self.t.packet_flows)+1
        if reverse:p['src'],p['dst']=p['dst'],p['src'];p['sport'],p['dport']=p['dport'],p['sport']
        return self.t.add(p)
    def test_bidirectional_out_of_order_overlap_retransmission(self):
        fid=self.add(b'',99,2)
        self.add(b'world',105);self.add(b'hello',100);self.add(b'hello',100)
        self.add(b'answer',500,reverse=True)
        f=self.t.detail(fid)
        self.assertEqual(f['directions'][0]['text'],'helloworld')
        self.assertEqual(f['directions'][1]['text'],'answer')
        self.assertEqual(f['directions'][0]['retransmitted_bytes'],5)
        self.assertEqual(f['packets'],5)
        self.assertEqual(len(self.t.summaries()),1)
    def test_gap_not_silently_joined_and_conflict_reported(self):
        fid=self.add(b'abc',100);self.add(b'xyz',110);self.add(b'ZZ',101)
        d=self.t.detail(fid)['directions'][0]
        self.assertEqual(len(d['chunks']),2)
        self.assertEqual(d['gaps'],[{'start':3,'end':10,'bytes':7}])
        self.assertEqual(d['conflicting_bytes'],2)
    def test_wraparound_and_syn_consumes_sequence_number(self):
        fid=self.add(b'',0xfffffffd,2);self.add(b'ab',0xfffffffe);self.add(b'cd',0)
        self.assertEqual(self.t.detail(fid)['directions'][0]['text'],'abcd')
    def test_new_syn_splits_port_reuse_but_syn_retransmit_does_not(self):
        fid=self.add(b'',99,2);self.assertEqual(self.add(b'',99,2),fid)
        self.add(b'abc',100);self.assertNotEqual(self.add(b'',500,2),fid)
    def test_segmented_http_recognized_after_reassembly(self):
        fid=self.add(b'GE',100);self.add(b'T / HTTP/1.1\r\nHost: demo\r\n\r\n',102)
        f=self.t.detail(fid)
        self.assertEqual(f['application'],'HTTP')
    def test_evicted_packets_do_not_stay_in_flows(self):
        fid=self.add(b'abc',100);self.t.remove(1)
        self.assertEqual(self.t.summaries(),[])

import unittest
from sniffer.processes import parse_lsof, associate

class ProcessTests(unittest.TestCase):
    def test_full_tuple_and_ipv6_and_listener_confidence(self):
        rows=parse_lsof('p123\ncPython\nf5\nPTCP\nn127.0.0.1:51300->127.0.0.1:8080\np124\nccurl\nf6\nPTCP\nn[::1]:51301->[::1]:8080\np125\ncserver\nf8\nPTCP\nn*:8081\n')
        p=dict(src='127.0.0.1',dst='127.0.0.1',sport=51300,dport=8080,transport='TCP')
        a=associate(p,rows)
        self.assertEqual((a['pid'],a['process'],a['confidence']),(123,'Python','exact'))
        p.update(src='::1',dst='::1',sport=51301)
        self.assertEqual(associate(p,rows)['pid'],124)
        p.update(src='192.0.2.1',dst='127.0.0.1',sport=52000,dport=8081)
        self.assertEqual(associate(p,rows)['confidence'],'listener')
    def test_wrong_peer_not_attributed_by_port_alone(self):
        rows=parse_lsof('p123\ncPython\nf5\nPTCP\nn127.0.0.1:51300->127.0.0.1:8080\n')
        self.assertIsNone(associate(dict(src='127.0.0.1',dst='192.0.2.8',sport=51300,dport=8080,transport='TCP'),rows))

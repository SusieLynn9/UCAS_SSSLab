import unittest
from sniffer.filters import compile_filter, FilterError

class FilterTests(unittest.TestCase):
    def setUp(self):
        self.p=dict(layers=['Ethernet','IPv4','TCP','HTTP'],protocol='HTTP',transport='TCP',src='192.0.2.1',dst='198.51.100.2',sport=45678,dport=8080,length=99,info='GET /lab',flow_id=4,process='curl',pid=123)
    def test_layers_logic_and_precedence(self):
        for expr in ['http','tcp and ipv4','udp or tcp and http','not udp and (http or dns)','tcp && !ipv6','ip.addr == 192.0.2.1 and tcp.port == 8080','length >= 90','info contains "GET /lab"','process == curl','pid == 123','flow == 4']:
            with self.subTest(expr=expr): self.assertTrue(compile_filter(expr)(self.p))
        for expr in ['udp','ipv6','not tcp','tcp.port == 53','tcp and (udp or dns)']:
            with self.subTest(expr=expr): self.assertFalse(compile_filter(expr)(self.p))
    def test_invalid_expressions_rejected(self):
        for expr in ['tcp and','unknown','(tcp','tcp or __import__("os")','length > x','info contains','tcp.port == 99999','tcp )']:
            with self.subTest(expr=expr):
                with self.assertRaises(FilterError): compile_filter(expr)
    def test_empty_matches_all(self):
        self.assertTrue(compile_filter('')(self.p))

"""Independent wire fixtures for application-layer analysis."""
import socket
import struct
import unittest
from sniffer.protocols import application,decode_packet
from tests.fixtures import ethernet,ipv4,udp,http_packet


def name(s):
    return b''.join(bytes([len(x)])+x.encode('ascii') for x in s.split('.'))+b'\x00'


def rr(owner,kind,data,ttl=300,cls=1):
    return owner+struct.pack('!HHIH',kind,cls,ttl,len(data))+data


def dns_response(records,questions=None):
    questions=questions if questions is not None else [(name('example.com'),1)]
    q=b''.join(n+struct.pack('!HH',kind,1) for n,kind in questions)
    return struct.pack('!6H',0x1234,0x8180,len(questions),len(records),0,0)+q+b''.join(records)


def extension(kind,data):return struct.pack('!HH',kind,len(data))+data


def alpn(*names):
    data=b''.join(bytes([len(n)])+n for n in names)
    return struct.pack('!H',len(data))+data


def hello_record(exts=b'',server=False,version=b'\x03\x03',declared_extlen=None,cipher=0x1301):
    body=version+bytes(32)+b'\x00'
    body+=struct.pack('!H',cipher)+b'\x00' if server else b'\x00\x02'+struct.pack('!H',cipher)+b'\x01\x00'
    if exts or declared_extlen is not None:
        body+=struct.pack('!H',len(exts) if declared_extlen is None else declared_extlen)+exts
    h=bytes([2 if server else 1])+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x03'+struct.pack('!H',len(h))+h


class NPATests(unittest.TestCase):
    def test_dns_compressed_a_aaaa_and_cname_answers(self):
        records=[rr(b'\xc0\x0c',5,name('edge.example.com')),rr(name('edge.example.com'),1,socket.inet_aton('192.0.2.99')),rr(b'\xc0\x0c',28,socket.inet_pton(socket.AF_INET6,'2001:db8::99'))]
        proto,info,f=application(dns_response(records),'UDP',53,53000)
        self.assertEqual(proto,'DNS')
        self.assertIn('edge.example.com',f['Answer 1'])
        self.assertIn('192.0.2.99',f['Answer 2'])
        self.assertIn('2001:db8::99',f['Answer 3'])
        self.assertIn('TTL=300',f['Answer 2'])
        self.assertIn('192.0.2.99',info)

    def test_dns_multiple_questions_and_mx_txt_soa(self):
        soa=name('ns.example.com')+name('hostmaster.example.com')+struct.pack('!5I',42,3600,600,86400,60)
        rows=[rr(b'\xc0\x0c',15,struct.pack('!H',10)+name('mail.example.com')),rr(b'\xc0\x0c',16,b'\x05hello\x05world'),rr(b'\xc0\x0c',6,soa)]
        _,_,f=application(dns_response(rows,[(name('example.com'),15),(name('example.com'),16)]),'UDP',53,53000)
        self.assertIn('TXT',f['Question 2'])
        self.assertIn('mail.example.com',f['Answer 1'])
        self.assertIn('hello',f['Answer 2'])
        self.assertIn('serial=42',f['Answer 3'])

    def test_dns_authority_and_additional_sections(self):
        question=name('example.com')+struct.pack('!HH',1,1)
        data=struct.pack('!6H',1,0x8180,1,0,1,1)+question+rr(b'\xc0\x0c',2,name('ns.example.com'))+rr(name('ns.example.com'),1,socket.inet_aton('192.0.2.53'))
        _,_,f=application(data,'UDP',53,53000)
        self.assertIn('ns.example.com',f['Authority 1'])
        self.assertIn('192.0.2.53',f['Additional 1'])

    def test_dns_unknown_record_preserves_type_and_hex(self):
        _,_,f=application(dns_response([rr(b'\xc0\x0c',65000,b'\x01\x02')]),'UDP',53,53000)
        self.assertIn('TYPE65000',f['Answer 1']);self.assertIn('0102',f['Answer 1'])

    def test_dns_bad_rdlength_and_name_boundaries_diagnosed(self):
        bad=[rr(b'\xc0\x0c',1,b'\x01\x02'),rr(b'\xc0\x0c',5,b'\x04ab'),rr(b'\xc0\x0c',16,b'\x09hi')]
        for record in bad:
            data=dns_response([record]);p=decode_packet(ethernet(ipv4(udp(data,sport=53,dport=53000),17)))
            with self.subTest(record=record):self.assertTrue(p['warnings'])

    def test_tls_client_offers_are_distinct_from_selection(self):
        record=hello_record(extension(43,b'\x04\x03\x04\x03\x03')+extension(16,alpn(b'h2',b'http/1.1')))
        _,_,f=application(record,'TCP')
        self.assertEqual(f['Supported versions'],'TLS 1.3, TLS 1.2')
        self.assertEqual(f['Offered ALPN'],'h2, http/1.1')
        self.assertNotIn('Selected ALPN',f)
        self.assertNotIn('Selected version',f)

    def test_tls13_serverhello_reports_selected_version_not_alpn(self):
        _,info,f=application(hello_record(extension(43,b'\x03\x04'),server=True),'TCP')
        self.assertEqual(f['Selected version'],'TLS 1.3');self.assertIn('ServerHello',info)
        self.assertNotIn('Selected ALPN',f)

    def test_tls12_serverhello_selected_alpn(self):
        _,_,f=application(hello_record(extension(16,alpn(b'http/1.1')),server=True,cipher=0xc02f),'TCP')
        self.assertEqual(f['Selected version'],'TLS 1.2')
        self.assertEqual(f['Selected ALPN'],'http/1.1')

    def test_tls_incomplete_record_does_not_invent_complete_handshake(self):
        record=hello_record(extension(43,b'\x02\x03\x04'))
        _,info,f=application(record[:-2],'TCP')
        self.assertIn('incomplete',info.lower())
        self.assertNotIn('Supported versions',f)

    def test_tls_extension_must_fit_declared_extension_block(self):
        record=hello_record(extension(16,alpn(b'h2')),declared_extlen=4)
        _,_,f=application(record,'TCP')
        self.assertIn('Note',f)
        self.assertNotIn('Offered ALPN',f)

    def test_http_headers_completeness_is_explicit(self):
        for data,want in [(b'GET / HTTP/1.1\r\nHost: demo\r\n',False),(b'GET / HTTP/1.1\r\nHost: demo\r\n\r\n',True)]:
            p=decode_packet(http_packet(data));f=p['details'][-1]['fields']
            self.assertEqual(f['Headers complete'],want)
            self.assertEqual(p['protocol'],'HTTP')

    def test_http_body_does_not_create_fake_headers(self):
        data=b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nX-F: hi'
        _,_,f=application(data,'TCP');self.assertNotIn('X-F',f)

    def test_dns_response_over_tcp_after_out_of_order_reassembly(self):
        from sniffer.capture import Session
        payload=dns_response([rr(b'\xc0\x0c',1,socket.inet_aton('192.0.2.99'))])
        wire=struct.pack('!H',len(payload))+payload
        s=Session()
        for i,(data,seq,flags) in enumerate([(b'',99,2),(wire[9:],109,0x18),(wire[:9],100,0x18)]):
            raw=http_packet(data,seq=seq,flags=flags,sport=53,dport=53000)
            s.ingest(i,raw,len(raw),1)
        f=s.flow_detail(1)
        self.assertEqual(f['application'],'DNS')
        self.assertIn('192.0.2.99',f['directions'][0]['application']['fields']['Answer 1'])

    def test_tls_clienthello_after_tcp_reassembly(self):
        from sniffer.capture import Session
        wire=hello_record(extension(43,b'\x02\x03\x04')+extension(16,alpn(b'h2')))
        s=Session()
        for i,(data,seq) in enumerate([(wire[:12],100),(wire[12:],112)]):
            raw=http_packet(data,seq=seq);s.ingest(i,raw,len(raw),1)
        fields=s.flow_detail(1)['directions'][0]['application']['fields']
        self.assertEqual(fields['Offered ALPN'],'h2')

    def test_npa_sample_has_dns_answers_tls_offers_and_server_selection(self):
        from scripts.generate_sample import build
        packets=[decode_packet(raw,1,t,n) for t,raw,n in build()]
        fields=[layer['fields'] for p in packets for layer in p['details']]
        self.assertTrue(any('Answer 1' in f for f in fields))
        self.assertTrue(any(f.get('Offered ALPN')=='h2, http/1.1' for f in fields))
        self.assertTrue(any(f.get('Selected version')=='TLS 1.3' for f in fields))
        self.assertTrue(any(f.get('Selected ALPN')=='http/1.1' for f in fields))

    def test_mdns_cache_flush_in_address_is_decoded(self):
        data=dns_response([rr(b'\xc0\x0c',1,socket.inet_aton('192.0.2.99'),cls=0x8001)])
        _,_,f=application(data,'UDP',5353,5353)
        self.assertIn('192.0.2.99',f['Answer 1'])
        self.assertIn('cache-flush',f['Answer 1'])

    def test_sample_tls12_cipher_is_tls12_compatible(self):
        from scripts.generate_sample import build
        fields=[layer['fields'] for t,raw,n in build() for layer in decode_packet(raw,1,t,n)['details']]
        selected=[f for f in fields if f.get('Selected version')=='TLS 1.2']
        self.assertTrue(selected)
        self.assertEqual(selected[0]['Cipher suite'],'0xc02f')

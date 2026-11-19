import json
import threading
import unittest
import urllib.error
import urllib.request
from sniffer.server import make_server
from sniffer.capture import Session
from tests.fixtures import http_packet

class ServerTests(unittest.TestCase):
    def setUp(self):
        self.session=Session();self.session.ingest(1,http_packet(),100,1)
        self.server=make_server(self.session,port=0,token='test-secret');self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def request(self,path,body=None,token='test-secret',origin=None):
        headers={'X-Prism-Token':token}
        if origin:headers['Origin']=origin
        if body is not None:headers['Content-Type']='application/json';body=json.dumps(body).encode()
        return urllib.request.urlopen(urllib.request.Request(self.base+path,data=body,headers=headers),timeout=5)
    def test_auth_origin_and_host(self):
        for token,origin in [('',None),('test-secret','http://evil.test')]:
            with self.assertRaises(urllib.error.HTTPError) as cm:self.request('/api/state',token=token,origin=origin)
            self.assertEqual(cm.exception.code,403)
            cm.exception.close()
    def test_state_detail_and_invalid_filter(self):
        self.assertEqual(json.load(self.request('/api/state'))['retained'],1)
        self.assertEqual(json.load(self.request('/api/packet?id=1'))['protocol'],'HTTP')
        with self.assertRaises(urllib.error.HTTPError) as cm:self.request('/api/state?filter=tcp%20and')
        self.assertEqual(cm.exception.code,400)
        cm.exception.close()
    def test_mutation_and_download(self):
        self.assertTrue(self.request('/api/export').read().startswith(b'\xd4\xc3\xb2\xa1'))
        self.request('/api/clear',{}).read()
        self.assertEqual(json.load(self.request('/api/state'))['retained'],0)

    def test_effective_capture_filter_excludes_gui_and_preserves_user_or(self):
        import tempfile
        from pathlib import Path
        from sniffer.server import capture_filter
        from sniffer.pcap import Pcap,write_pcap
        from tests.fixtures import ethernet,ipv4,tcp,udp
        gui=ethernet(ipv4(tcp(b'GET /api/state HTTP/1.1\r\nX-Prism-Token: SECRET\r\n\r\n',dport=8765),src='127.0.0.1',dst='127.0.0.1'))
        http=http_packet();dns=ethernet(ipv4(udp(b'abc'),17))
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x.pcap';write_pcap(path,1,[(1,gui,len(gui)),(2,http,len(http)),(3,dns,len(dns))])
            for expr in ('','tcp or udp'):
                with Pcap.offline(path,capture_filter(expr,8765)) as cap:
                    raws=[raw for t,raw,n in cap]
                self.assertEqual(raws,[http,dns])

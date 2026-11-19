import io
import tempfile
import unittest
from pathlib import Path
from tests.fixtures import http_packet
from sniffer.capture import Session
from sniffer.pcap import Pcap,write_pcap

class SessionTests(unittest.TestCase):
    def test_bounded_store_flow_eviction_and_clear(self):
        s=Session(max_packets=2,max_bytes=10000)
        for i in range(3):s.ingest(1+i,http_packet(seq=100+i),100,1)
        snap=s.snapshot()
        self.assertEqual(snap['retained'],2)
        self.assertEqual(snap['evicted'],1)
        self.assertEqual([p['id'] for p in snap['packets']],[2,3])
        self.assertEqual(s.flow_detail(1)['packets'],2)
        s.clear();self.assertEqual(s.snapshot()['total'],0)
        self.assertEqual(s.snapshot()['flows'],[])
    def test_filter_and_export_roundtrip(self):
        s=Session();s.ingest(1.25,http_packet(),100,1)
        self.assertEqual(s.snapshot('http')['matched'],1)
        self.assertEqual(s.snapshot('udp')['matched'],0)
        self.assertIn('GET /lab',s.packet_detail(1)['info'])
        b=s.export()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.pcap';p.write_bytes(b)
            t=Session();t.import_file(p)
            self.assertEqual(t.snapshot()['retained'],1)
            self.assertEqual(t.packet_detail(1)['hex'],http_packet().hex())
    def test_failed_import_preserves_session_and_mixed_links_rejected(self):
        s=Session();s.ingest(1,http_packet(),100,1)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad';p.write_bytes(b'junk')
            with self.assertRaises(Exception):s.import_file(p)
        self.assertEqual(s.snapshot()['retained'],1)
        with self.assertRaises(ValueError):s.ingest(2,b'abc',3,0)
    def test_byte_budget_covers_large_packets(self):
        s=Session(max_bytes=100)
        s.ingest(1,http_packet(b'a'*150),204,1)
        self.assertEqual(s.snapshot()['retained'],0)
        self.assertEqual(s.snapshot()['evicted'],1)

    def test_offline_packets_never_attributed_to_current_processes(self):
        from unittest.mock import patch
        s=Session()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.pcap';write_pcap(p,1,[(1,http_packet(),100)]);s.import_file(p)
        snap={'rows':[dict(pid=123,process='wrong-current-process',local=('192.0.2.1',45678),remote=('198.51.100.2',8080))],'timestamp':2,'note':'snapshot'}
        with patch('sniffer.capture.process_snapshot',return_value=snap):s.refresh_processes()
        self.assertNotIn('pid',s.packet_detail(1))

    def test_live_refresh_clears_expired_snapshot_attribution(self):
        from unittest.mock import patch
        s=Session();s.status='capturing';s.ingest(1,http_packet(),100,1)
        snap={'rows':[dict(pid=123,process='client',local=('192.0.2.1',45678),remote=('198.51.100.2',8080))],'timestamp':2,'note':'snapshot'}
        with patch('sniffer.capture.process_snapshot',return_value=snap):s.refresh_processes()
        self.assertEqual(s.packet_detail(1)['pid'],123)
        with patch('sniffer.capture.process_snapshot',return_value={'rows':[],'timestamp':3,'note':'empty'}):s.refresh_processes()
        self.assertNotIn('pid',s.packet_detail(1))

    def test_reset_does_not_reuse_old_process_snapshot(self):
        s=Session();s.process_snapshot={'rows':[dict(pid=123,process='old',local=('192.0.2.1',45678),remote=('198.51.100.2',8080))],'timestamp':2,'note':'old'}
        s.clear();s.status='capturing';s.ingest(3,http_packet(),100,1)
        self.assertNotIn('pid',s.packet_detail(1))

    def test_capture_helper_stops_even_when_final_output_fills_pipe(self):
        import base64,json,subprocess,sys,threading,time
        raw=http_packet();message=json.dumps({'t':1,'data':base64.b64encode(raw).decode(),'wirelen':len(raw)})
        code='import sys\nprint('+repr(message)+',flush=True)\nsys.stdin.buffer.read(1)\nsys.stdout.buffer.write(b"x"*524288)\nsys.stdout.buffer.flush()\n'
        proc=subprocess.Popen([sys.executable,'-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        s=Session();s.status='capturing';s.linktype=1
        s.thread=threading.Thread(target=s._capture,args=(None,proc),daemon=True);s.thread.start()
        deadline=time.monotonic()+2
        while s.total==0 and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(s.total,1)
        s.stop()
        self.assertEqual(proc.returncode,0)

    def test_old_import_cannot_override_newer_clear(self):
        from unittest.mock import patch
        import threading
        entered=threading.Event();release=threading.Event();errors=[]
        class SlowReader:
            linktype=1
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def __iter__(self):
                entered.set();release.wait(2);yield (1,http_packet(),95)
        s=Session()
        def load():
            try:s.import_file('slow.pcap')
            except RuntimeError as e:errors.append(str(e))
        with patch('sniffer.capture.Pcap.offline',return_value=SlowReader()):
            worker=threading.Thread(target=load);worker.start();self.assertTrue(entered.wait(1));s.clear();release.set();worker.join(3)
        self.assertFalse(worker.is_alive());self.assertEqual(s.snapshot()['status'],'idle');self.assertEqual(s.snapshot()['total'],0);self.assertTrue(errors)

    def test_invalid_capture_config_keeps_running_session(self):
        from unittest.mock import patch
        import threading
        s=Session();s.status='capturing';s.source='old-interface';s.thread=threading.Thread(target=s.stop_event.wait,daemon=True);s.thread.start()
        try:
            with patch('sniffer.capture.Pcap.live',side_effect=ValueError('invalid BPF')):
                with self.assertRaises(ValueError):s.start('new-interface','tcp and (')
            self.assertEqual(s.status,'capturing');self.assertTrue(s.thread.is_alive());self.assertEqual(s.source,'old-interface')
        finally:s.stop()

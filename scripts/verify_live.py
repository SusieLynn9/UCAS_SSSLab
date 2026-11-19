#!/usr/bin/env python3
"""Real loopback NPS acceptance test. Run with sudo in your own terminal.
Captures ONLY the ephemeral port used by this test, never unrelated traffic.
"""
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import time
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sniffer.pcap import Pcap,write_pcap
from sniffer.protocols import decode_packet

def main():
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def do_GET(self):
            data=b'UCAS lab 1A live capture verified\n';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*a):pass
    server=HTTPServer(('127.0.0.1',0),Handler);port=server.server_port
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    packets=[]
    try:
        interface='lo0' if sys.platform=='darwin' else 'lo'
        with Pcap.live(interface,f'tcp port {port}') as cap:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/lab-1a-live-test',timeout=3) as response:
                assert response.read()==b'UCAS lab 1A live capture verified\n'
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                row=cap.next()
                if row:packets.append(row)
                else:time.sleep(.01)
            decoded=[decode_packet(raw,cap.linktype,t,n) for t,raw,n in packets]
            requests=[p for p in decoded if p['protocol']=='HTTP' and 'GET /lab-1a-live-test' in p['info']]
            responses=[p for p in decoded if p['protocol']=='HTTP' and '200 OK' in p['info']]
            result={'passed':bool(requests and responses),'interface':interface,'bpf':f'tcp port {port}', 'packets':len(packets),'http_requests':len(requests),'http_responses':len(responses),'stats':cap.stats(),'timestamp':time.strftime('%Y-%m-%d %H:%M:%S %z')}
            print(json.dumps(result,ensure_ascii=False,indent=2))
            if not result['passed']:raise RuntimeError('Did not capture both real HTTP request and response')
            return 0
    finally:server.shutdown();server.server_close();thread.join()
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:print('LIVE CAPTURE NOT VERIFIED: '+str(e),file=sys.stderr);raise SystemExit(1)

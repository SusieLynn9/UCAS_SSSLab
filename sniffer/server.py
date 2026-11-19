"""Loopback-only GUI API; capability token, Origin/Host checks and bounded input."""
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import tempfile
from urllib.parse import urlparse,parse_qs
from .pcap import Pcap

WEB=Path(__file__).parent/'web'
MAX_UPLOAD=64*1024*1024


def capture_filter(user_bpf,server_port):
    """Never capture the local GUI control channel, including its capability token."""
    exclude=f'not (tcp and host 127.0.0.1 and port {int(server_port)})'
    return f'({user_bpf}) and ({exclude})' if user_bpf.strip() else exclude


def make_server(session,port=8765,token=None):
    token=token or secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send(self,status,data,kind='application/json; charset=utf-8',extra=None):
            if not isinstance(data,bytes):data=json.dumps(data,ensure_ascii=False).encode()
            self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            if extra:
                for k,v in extra.items():self.send_header(k,v)
            self.end_headers();self.wfile.write(data)
        def authorized(self):
            expected=f'127.0.0.1:{self.server.server_port}'
            if self.headers.get('Host')!=expected:return False
            origin=self.headers.get('Origin')
            if origin and origin!='http://'+expected:return False
            if self.headers.get('Sec-Fetch-Site')=='cross-site':return False
            return hmac.compare_digest(self.headers.get('X-Prism-Token',''),token)
        def do_GET(self):
            parsed=urlparse(self.path);q=parse_qs(parsed.query);path=parsed.path
            if not path.startswith('/api/'):
                names={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
                if path not in names:return self.send(404,{'error':'Not found'})
                content=(WEB/names[path]).read_bytes();kind={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path]
                return self.send(200,content,kind)
            if not self.authorized():return self.send(403,{'error':'Invalid local access token or origin'})
            try:
                if path=='/api/state':data=session.snapshot(q.get('filter',[''])[0],int(q.get('after',['0'])[0]))
                elif path=='/api/devices':data={'devices':Pcap.devices()}
                elif path=='/api/packet':data=session.packet_detail(q['id'][0])
                elif path=='/api/flow':data=session.flow_detail(q['id'][0])
                elif path=='/api/export':return self.send(200,session.export(q.get('filter',[''])[0]),'application/vnd.tcpdump.pcap',{'Content-Disposition':'attachment; filename="prism-capture.pcap"'})
                else:return self.send(404,{'error':'Not found'})
                self.send(200,data)
            except KeyError:self.send(404,{'error':'Packet or flow no longer retained'})
            except (ValueError,RuntimeError) as e:self.send(400,{'error':str(e)})
        def do_POST(self):
            if not self.authorized():return self.send(403,{'error':'Invalid local access token or origin'})
            path=urlparse(self.path).path
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<0 or n>MAX_UPLOAD:return self.send(413,{'error':'Upload limit: 64 MiB'})
                self.connection.settimeout(15)
                body=self.rfile.read(n)
                if len(body)!=n:raise ValueError('Incomplete request body')
                if path=='/api/import':
                    with tempfile.NamedTemporaryFile(suffix='.pcap') as f:
                        f.write(body);f.flush();session.import_file(f.name)
                    data={'ok':True}
                else:
                    if n>8192:raise ValueError('Control request too large')
                    obj=json.loads(body or b'{}')
                    if not isinstance(obj,dict):raise ValueError('JSON object required')
                    if path=='/api/start':
                        device=obj.get('device','');bpf=obj.get('bpf','')
                        if not isinstance(device,str) or not device or len(device)>512 or not isinstance(bpf,str) or len(bpf)>4096:raise ValueError('Invalid device/BPF')
                        effective=capture_filter(bpf,self.server.server_port)
                        session.start(device,effective,bool(obj.get('promiscuous',False)));data={'ok':True,'effective_bpf':effective}
                    elif path=='/api/stop':session.stop();data={'ok':True}
                    elif path=='/api/clear':session.clear();data={'ok':True}
                    elif path=='/api/processes':data=session.refresh_processes()
                    elif path=='/api/sample':session.import_file(Path(__file__).resolve().parents[1]/'samples'/'lab-demo.pcap');data={'ok':True}
                    else:return self.send(404,{'error':'Not found'})
                self.send(200,data)
            except (ValueError,RuntimeError,OSError) as e:self.send(400,{'error':str(e)})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler);server.daemon_threads=True;server.token=token;return server

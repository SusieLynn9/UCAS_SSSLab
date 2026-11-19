"""Thread-owned capture resources and a bounded, synchronized analysis session."""
import base64
from collections import Counter, OrderedDict
import io
import json
from pathlib import Path
import select
import subprocess
import sys
import threading
import time
from .filters import compile_filter
from .flows import FlowTracker
from .pcap import Pcap, PcapError, write_pcap
from .protocols import decode_packet
from .processes import snapshot as process_snapshot, associate

class Session:
    def __init__(self,max_packets=5000,max_bytes=32*1024*1024):
        self.lock=threading.RLock();self.control=threading.RLock();self.control_revision=0;self.thread=None;self.stop_event=threading.Event()
        self.max_packets=max_packets;self.max_bytes=max_bytes;self.process_snapshot={'rows':[],'timestamp':0,'note':'尚未读取进程快照'}
        self._reset()
    def _reset(self):
        self.packets=OrderedDict();self.tracker=FlowTracker();self.total=0;self.evicted=0;self.raw_bytes=0;self.linktype=None
        self.process_snapshot={'rows':[],'timestamp':0,'note':'尚未读取进程快照'}
        self.status='idle';self.error='';self.source='';self.stats=None;self.started=None;self.generation=time.time_ns();self.counters=Counter();self.wire_bytes=0
    def ingest(self,timestamp,raw,wirelen,linktype):
        p=decode_packet(raw,linktype,timestamp,wirelen)
        with self.lock:
            if self.linktype is not None and self.linktype!=linktype:raise ValueError('Mixed link types cannot be stored/exported as one classic PCAP')
            self.linktype=linktype;self.total+=1;p['id']=self.total;p['_raw']=raw
            p['_live']=self.status=='capturing'
            attr=associate(p,self.process_snapshot['rows']) if p['_live'] else None
            if attr:p.update(attr,process_snapshot_time=self.process_snapshot['timestamp'])
            self.packets[p['id']]=p;self.raw_bytes+=len(raw);self.wire_bytes+=wirelen;self.counters[p['protocol']]+=1;self.tracker.add(p)
            while len(self.packets)>self.max_packets or self.raw_bytes>self.max_bytes:
                ident,old=self.packets.popitem(last=False);self.raw_bytes-=len(old['_raw']);self.evicted+=1;self.tracker.remove(ident)
        return p
    def _stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=6)
            if self.thread.is_alive():raise RuntimeError('Capture worker is still stopping; retry shortly')
        self.thread=None
        with self.lock:
            if self.status in ('capturing','starting'):self.status='stopped'
    def stop(self):
        with self.control:
            self.control_revision+=1;self._stop()
    def clear(self):
        with self.control:
            self.control_revision+=1;self._stop()
            with self.lock:self._reset()
    def refresh_processes(self):
        with self.control:
            with self.lock:
                if self.status=='offline':
                    self.process_snapshot={'rows':[],'timestamp':0,'note':'离线 PCAP 不包含可信的本机进程来源，禁止使用当前 socket 快照标注历史报文'}
                    return {'timestamp':0,'sockets':0,'note':self.process_snapshot['note']}
            snap=process_snapshot()
            with self.lock:
                self.process_snapshot=snap
                for p in self.packets.values():
                    if not p.get('_live'):continue
                    for key in ('pid','process','confidence','process_snapshot_time'):p.pop(key,None)
                    attr=associate(p,snap['rows'])
                    if attr:p.update(attr,process_snapshot_time=snap['timestamp'])
            return {'timestamp':snap['timestamp'],'sockets':len(snap['rows']),'note':snap['note']}
    def _open_helper(self,device,bpf,promiscuous):
        if sys.platform!='darwin':raise PcapError('Capture permission denied. Grant libpcap capture permissions for your OS.')
        script=Path(__file__).resolve().parents[1]/'scripts'/'capture_helper.py'
        cmd=['/usr/bin/sudo','-n','/usr/bin/python3',str(script),'--interface',device,'--bpf',bpf]
        if promiscuous:cmd.append('--promiscuous')
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        try:
            if not select.select([proc.stdout],[],[],5)[0]:raise PcapError('Capture helper startup timed out')
            line=proc.stdout.readline(4096)
            if not line:
                err=proc.stderr.read(4096).decode(errors='replace')
                raise PcapError('实时抓包需要 BPF 权限。请先在启动本程序的终端运行 sudo -v，再点击开始。无需以 root 运行界面。 '+err.strip())
            hello=json.loads(line)
            if 'error' in hello:raise PcapError(hello['error'])
            return proc,hello['linktype']
        except Exception:
            proc.stdin.close()
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:proc.terminate()
            for stream in (proc.stdout,proc.stderr):stream.close()
            raise
    def start(self,device,bpf='',promiscuous=False):
        with self.control:
            cap=None;helper=None
            try:cap=Pcap.live(device,bpf,promiscuous)
            except PcapError as e:
                if 'permission' not in str(e).lower() and 'permitted' not in str(e).lower():raise
                helper,lt=self._open_helper(device,bpf,promiscuous)
            try:self._stop()
            except Exception:
                if cap:cap.close()
                if helper:self._close_helper(helper)
                raise
            self.control_revision+=1
            with self.lock:
                self._reset();self.status='capturing';self.source=device;self.started=time.time();self.linktype=cap.linktype if cap else lt
            self.stop_event=threading.Event()
            self.thread=threading.Thread(target=self._capture,args=(cap,helper),daemon=True,name='pcap-worker');self.thread.start()
    def _capture(self,cap,helper):
        try:
            next_stats=time.monotonic()+1
            while not self.stop_event.is_set():
                if cap:
                    row=cap.next()
                    if row:self.ingest(*row,cap.linktype)
                    else:self.stop_event.wait(.01)
                    if time.monotonic()>next_stats:
                        stats=cap.stats()
                        with self.lock:self.stats=stats
                        next_stats=time.monotonic()+1
                else:
                    if not select.select([helper.stdout],[],[],.1)[0]:continue
                    line=helper.stdout.readline(2*1024*1024)
                    if not line:
                        if not self.stop_event.is_set():raise PcapError('Capture helper exited unexpectedly')
                        break
                    msg=json.loads(line)
                    if 'error' in msg:raise PcapError(msg['error'])
                    if 'stats' in msg:
                        with self.lock:self.stats=msg['stats']
                    else:self.ingest(msg['t'],base64.b64decode(msg['data']),msg['wirelen'],self.linktype)
        except Exception as e:
            with self.lock:self.error=str(e);self.status='error'
        finally:
            if cap:
                with self.lock:self.stats=cap.stats()
                cap.close()
            if helper:self._close_helper(helper)
            with self.lock:
                if self.status=='capturing':self.status='stopped'
    @staticmethod
    def _close_helper(helper):
        helper.stdin.close()
        # Keep draining while the stdin watcher stops the privileged worker.
        # Otherwise a full stdout pipe could block its final packet write.
        deadline=time.monotonic()+3
        while helper.poll() is None and time.monotonic()<deadline:
            if select.select([helper.stdout],[],[],.1)[0]:
                if not __import__('os').read(helper.stdout.fileno(),65536):break
        try:helper.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:helper.terminate()
            except OSError:pass
        helper.stdout.close();helper.stderr.close()

    def import_file(self,path,bpf=''):
        # Decode transactionally into a bounded temporary session. Malformed input
        # never clears an existing capture. The HTTP upload itself is size-limited.
        with self.control:
            self.control_revision+=1;revision=self.control_revision
        temp=Session(self.max_packets,self.max_bytes)
        with Pcap.offline(path,bpf) as cap:
            temp.linktype=cap.linktype
            for row in cap:temp.ingest(*row,cap.linktype)
        with self.control:
            if revision!=self.control_revision:raise RuntimeError('Import cancelled by a newer session operation')
            self._stop()
            with self.lock:
                for key in ('packets','tracker','total','evicted','raw_bytes','linktype','generation','counters','wire_bytes'):
                    setattr(self,key,getattr(temp,key))
                self.process_snapshot={'rows':[],'timestamp':0,'note':'离线报文无进程来源；不与当前 socket 关联'}
                self.status='offline';self.source=Path(path).name;self.error='';self.stats=None;self.started=None
    @staticmethod
    def _summary(p):
        return {k:v for k,v in p.items() if k not in ('_raw','_live','payload','details')}
    def snapshot(self,expression='',after=0,limit=500):
        match=compile_filter(expression)
        with self.lock:
            matches=[p for p in self.packets.values() if match(p)]
            rows=[self._summary(p) for p in matches if p['id']>after][-min(max(1,limit),1000):]
            return {'generation':self.generation,'status':self.status,'error':self.error,'source':self.source,
                    'total':self.total,'retained':len(self.packets),'matched':len(matches),'evicted':self.evicted,'raw_bytes':self.raw_bytes,
                    'wire_bytes':self.wire_bytes,'max_packets':self.max_packets,'max_bytes':self.max_bytes,'stats':self.stats,
                    'protocols':dict(self.counters),'packets':rows,'flows':self.tracker.summaries(),'started':self.started,
                    'process_note':self.process_snapshot['note'],'process_snapshot_time':self.process_snapshot['timestamp']}
    def packet_detail(self,ident):
        with self.lock:
            p=self.packets[int(ident)];result=self._summary(p);result.update(details=p['details'],hex=p['_raw'].hex(),payload_hex=p['payload'].hex());return result
    def flow_detail(self,ident):
        with self.lock:return self.tracker.detail(int(ident))
    def export(self,expression=''):
        match=compile_filter(expression)
        with self.lock:
            if self.linktype is None:raise ValueError('No captured packets to export')
            rows=[(p['timestamp'],p['_raw'],p['length']) for p in self.packets.values() if match(p)];lt=self.linktype
        stream=io.BytesIO();write_pcap(stream,lt,rows);return stream.getvalue()

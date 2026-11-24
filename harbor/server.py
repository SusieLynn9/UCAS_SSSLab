"""Bounded mutually authenticated TLS server with persistent framed sessions."""
from collections import Counter,defaultdict,deque
import hashlib
import os
import socket
import ssl
import threading
import time
import uuid
from . import config as configuration
from .limits import Bandwidth
from .protocol import Frame,Opcode,ProtocolError,RESPONSE,ERROR,recv_frame,send_frame
from .storage import Storage,StorageError,integer

class Server:
    def __init__(self,config_path,host=None,port=None):
        self.config=configuration.load(config_path);self.host=host or self.config.get('host','127.0.0.1');self.port=self.config.get('port',9444) if port is None else port
        users=self.config['users']
        if not isinstance(users,list) or not 1<=len(users)<=64:raise ValueError('Configure 1..64 users')
        self.users={u['fingerprint']:u for u in users}
        if len(self.users)!=len(users) or len({u['name'] for u in users})!=len(users):raise ValueError('Duplicate user identity')
        self.budgets={u['name']:Bandwidth(u['rate_bps']) for u in users}
        for user in users:
            if len(user['fingerprint'])!=64 or any(c not in '0123456789abcdef' for c in user['fingerprint']):raise ValueError('Invalid certificate fingerprint')
            integer(user['quota_bytes'],'quota_bytes')
            for key in ('can_upload','can_download'):
                if type(user[key]) is not bool:raise ValueError('Permission flags must be boolean')
        self.context=configuration.context(self.config,server=True);self.store=Storage(self.config['root'],users)
        self.lock=threading.RLock();self.stop_event=threading.Event();self.listener=None;self.thread=None;self.workers=set();self.connections=set();self.ip_counts=Counter();self.admissions=defaultdict(deque);self.counts=Counter()
        self.max_connections=self.config.get('max_connections',32);self.max_per_ip=self.config.get('max_per_ip',min(16,self.max_connections))
        if type(self.max_connections) is not int or not 1<=self.max_connections<=128:raise ValueError('max_connections must be 1..128')
        if type(self.max_per_ip) is not int or not 1<=self.max_per_ip<=self.max_connections:raise ValueError('Invalid max_per_ip')
        self.slots=threading.BoundedSemaphore(self.max_connections)
    def start(self):
        self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.listener.bind((self.host,self.port));self.listener.listen(64);self.listener.settimeout(.3);self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self._accept,daemon=True,name='harbor-accept');self.thread.start();return self
    def _accept(self):
        while not self.stop_event.is_set():
            try:raw,address=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            ip=address[0];now=time.monotonic()
            with self.lock:
                history=self.admissions[ip]
                while history and history[0]<now-1:history.popleft()
                allowed=self.ip_counts[ip]<self.max_per_ip and len(history)<20 and self.slots.acquire(blocking=False)
                if allowed:
                    history.append(now);self.ip_counts[ip]+=1;self.connections.add(raw)
                else:self.counts['rejected']+=1
                # Bound idle per-IP rate history memory on long-lived servers.
                if len(self.admissions)>1024:
                    for key in list(self.admissions):
                        if not self.ip_counts[key] and (not self.admissions[key] or self.admissions[key][-1]<now-1):self.admissions.pop(key,None)
            if not allowed:raw.close();continue
            worker=threading.Thread(target=self._serve,args=(raw,ip),daemon=True,name='harbor-session')
            with self.lock:self.workers.add(worker)
            worker.start()
    def _hello(self,user,conn,owner):
        return {'username':user['name'],'tier':user.get('tier','Standard'),'rate_bps':user['rate_bps'],'quota_bytes':user['quota_bytes'],'connection_id':owner,'tls_version':conn.version(),'keep_alive':True,'heartbeat_seconds':15,'chunk_size':min(65536,max(256,user['rate_bps']//4)),'can_upload':user['can_upload'],'can_download':user['can_download']}
    def _serve(self,raw,ip):
        conn=None;owner=uuid.uuid4().hex;downloads={};uploads=set();greeted=False
        try:
            raw.settimeout(5);raw.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
            conn=self.context.wrap_socket(raw,server_side=True)
            with self.lock:self.connections.discard(raw);self.connections.add(conn)
            fingerprint=hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest();user=self.users.get(fingerprint)
            if not user:
                with self.lock:self.counts['rejected']+=1
                return
            name=user['name'];budget=self.budgets[name]
            with self.lock:self.counts['accepted']+=1
            conn.settimeout(120)
            while not self.stop_event.is_set():
                request=recv_frame(conn,timeout=120)
                if request.opcode&RESPONSE or request.flags:raise ProtocolError('Client request required')
                op=Opcode(request.opcode);m=request.metadata
                if request.payload and op!=Opcode.UPLOAD_CHUNK:raise ProtocolError('Unexpected payload for operation')
                payload=b''
                try:
                    if not greeted and op!=Opcode.HELLO:raise StorageError('HELLO required','STATE')
                    if op==Opcode.HELLO:result=self._hello(user,conn,owner);greeted=True
                    elif op==Opcode.PING:result={'connection_id':owner,'keep_alive':True}
                    elif op==Opcode.LIST:
                        offset=integer(m.get('offset',0),'offset',self.store.max_files);rows=self.store.list_files(name);result={'files':rows[offset:offset+32],'next_offset':offset+32 if offset+32<len(rows) else None}
                    elif op==Opcode.UPLOAD_BEGIN:
                        if uploads:raise StorageError('Finish or pause active upload first','STATE')
                        result=self.store.begin(name,m.get('name'),m.get('size'),m.get('sha256'),owner)
                        if not result.get('complete'):uploads.add(result['transfer_id'])
                    elif op==Opcode.UPLOAD_CHUNK:
                        budget.consume(len(request.payload),self.stop_event)
                        offset=self.store.write(name,m.get('transfer_id'),m.get('offset'),request.payload,owner);result={'offset':offset}
                        with self.lock:self.counts['uploaded_bytes']+=len(request.payload)
                    elif op==Opcode.UPLOAD_COMMIT:
                        tid=m.get('transfer_id');result=self.store.commit(name,tid,owner);uploads.discard(tid)
                    elif op==Opcode.DOWNLOAD_INFO:
                        if downloads:raise StorageError('Close active download first','STATE')
                        d=self.store.open_download(name,m.get('name'),m.get('offset',0));handle=uuid.uuid4().hex;downloads[handle]=d;result={**d.info,'download_id':handle}
                    elif op==Opcode.DOWNLOAD_CHUNK:
                        handle=m.get('download_id')
                        if not isinstance(handle,str) or handle not in downloads:raise StorageError('Unknown download handle','STATE')
                        offset=integer(m.get('offset'),'offset');length=integer(m.get('length',65536),'length',65536)
                        payload=downloads[handle].read(offset,length);budget.consume(len(payload),self.stop_event);result={'offset':offset,'length':len(payload)}
                        with self.lock:self.counts['downloaded_bytes']+=len(payload)
                    elif op==Opcode.CANCEL:
                        direction=m.get('direction')
                        if direction=='upload':
                            discard=m.get('discard',False)
                            if type(discard) is not bool:raise StorageError('Invalid discard flag')
                            tid=m.get('transfer_id');self.store.cancel(name,tid,owner,discard);uploads.discard(tid)
                        elif direction=='download':
                            handle=m.get('download_id')
                            if not isinstance(handle,str) or handle not in downloads:raise StorageError('Unknown download handle','STATE')
                            downloads.pop(handle).close()
                        else:raise StorageError('Invalid cancel direction')
                        result={'closed':True}
                    elif op==Opcode.QUIT:result={'closed':True}
                    else:raise ProtocolError('Unsupported operation')
                    send_frame(conn,Frame(op|RESPONSE,request.request_id,result,payload))
                    with self.lock:self.counts['requests']+=1
                except StorageError as e:send_frame(conn,Frame(op|RESPONSE,request.request_id,{'error':str(e),'code':e.code},flags=ERROR))
                except OSError:send_frame(conn,Frame(op|RESPONSE,request.request_id,{'error':'Storage operation failed','code':'IO'},flags=ERROR))
                if op==Opcode.QUIT:break
        except (OSError,ProtocolError,ValueError,RuntimeError):
            with self.lock:self.counts['connection_errors']+=1
        finally:
            for d in downloads.values():d.close()
            self.store.release_owner(owner)
            if conn:
                try:conn.close()
                except OSError:pass
            raw.close()
            with self.lock:
                self.connections.discard(conn);self.connections.discard(raw);self.ip_counts[ip]-=1
                if not self.ip_counts[ip]:self.ip_counts.pop(ip,None)
                self.workers.discard(threading.current_thread())
            self.slots.release()
    def metrics(self):
        with self.lock:return {**dict(self.counts),'accepted':self.counts['accepted'],'active':len(self.connections),'user_payload_bytes':{name:b.bytes for name,b in self.budgets.items()}}
    def stop(self):
        if self.stop_event.is_set():return
        self.stop_event.set()
        if self.listener:self.listener.close()
        with self.lock:connections=list(self.connections);workers=list(self.workers)
        for conn in connections:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:conn.close()
            except OSError:pass
        if self.thread:self.thread.join(2)
        deadline=time.monotonic()+6
        for worker in workers:worker.join(max(0,deadline-time.monotonic()))
        if any(worker.is_alive() for worker in workers):raise RuntimeError('Server workers still stopping')
        self.store.close()

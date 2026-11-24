"""Persistent mTLS client and resumable, integrity-checked transfer operations."""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import threading
from . import config as configuration
from .protocol import Frame,Opcode,ProtocolError,RESPONSE,ERROR,MAX_PAYLOAD,send_frame,recv_frame
from .storage import filename,StorageError,transaction_id

class ClientError(RuntimeError):
    def __init__(self,message,code='CLIENT'):super().__init__(message);self.code=code

def _hash(fd,limit=None):
    h=hashlib.sha256();offset=0
    while limit is None or offset<limit:
        data=os.pread(fd,1024*1024 if limit is None else min(1024*1024,limit-offset),offset)
        if not data:break
        h.update(data);offset+=len(data)
    return h.hexdigest()

def _regular(path,flags):
    fd=os.open(path,flags|os.O_NOFOLLOW,0o600);st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:os.close(fd);raise ClientError('Only private regular files are permitted')
    return fd

def _state_write(path,data):
    # Private, exclusive temporary output, then atomic replacement of our manifest.
    temporary=path.with_name(path.name+'.tmp-'+os.urandom(8).hex());fd=_regular(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
    finally:
        try:temporary.unlink()
        except FileNotFoundError:pass

class Client:
    def __init__(self,config_path,timeout=120):
        self.config_path=Path(config_path);self.config=configuration.load(config_path);self.timeout=timeout;self.sock=None;self.lock=threading.RLock();self.ident=0;self.info={};self.upload_ticket=None
    def connect(self):
        with self.lock:
            if self.sock is not None:return dict(self.info)
            try:
                ctx=configuration.context(self.config)
                raw=socket.create_connection((self.config['host'],self.config['port']),timeout=min(10,self.timeout));raw.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
                try:self.sock=ctx.wrap_socket(raw,server_hostname=self.config.get('server_hostname',self.config['host']))
                except Exception:raw.close();raise
                self.sock.settimeout(self.timeout);self.info=self._request(Opcode.HELLO)
                return dict(self.info)
            except (OSError,ValueError,ProtocolError,ClientError) as e:
                self._disconnect();raise ClientError('Connection/authentication failed: '+str(e)) from e
    def _disconnect(self):
        if self.sock:
            try:self.sock.close()
            except OSError:pass
        self.sock=None
    def _request(self,opcode,metadata=None,payload=b'',binary=False):
        with self.lock:
            if self.sock is None:
                if opcode==Opcode.HELLO:raise ClientError('Not connected')
                self.connect()
            self.ident=self.ident%0xffffffff+1
            try:
                send_frame(self.sock,Frame(opcode,self.ident,metadata or {},payload));reply=recv_frame(self.sock,self.timeout)
                if reply.request_id!=self.ident or reply.opcode!=int(opcode)|RESPONSE:raise ProtocolError('Response correlation mismatch')
                if reply.flags&ERROR:raise ClientError(reply.metadata.get('error','Server rejected request'),reply.metadata.get('code','SERVER'))
                if not binary and reply.payload:raise ProtocolError('Unexpected response payload')
                return (reply.metadata,reply.payload) if binary else reply.metadata
            except ClientError:raise
            except (OSError,ProtocolError,ValueError) as e:self._disconnect();raise ClientError('Connection interrupted: '+str(e)) from e
    def _block_size(self):
        size=self.info.get('chunk_size',MAX_PAYLOAD)
        if type(size) is not int or not 256<=size<=MAX_PAYLOAD:raise ClientError('Invalid negotiated block size')
        return size
    def ping(self):return self._request(Opcode.PING)
    def list_files(self):
        result=[];offset=0
        while True:
            page=self._request(Opcode.LIST,{'offset':offset});result.extend(page['files']);following=page['next_offset']
            if following is None:return result
            if type(following) is not int or following<=offset or len(result)>1024:raise ClientError('Invalid file listing pagination')
            offset=following
    def close(self):
        with self.lock:
            if self.sock:
                try:self._request(Opcode.QUIT)
                except ClientError:pass
                self._disconnect()
    @staticmethod
    def _intent(pause,cancel):
        return 'cancelled' if cancel and cancel.is_set() else 'paused' if pause and pause.is_set() else None
    def upload(self,local_path,remote_name=None,progress=None,pause_event=None,cancel_event=None):
        self.upload_ticket=None
        try:
            path=Path(local_path);name=filename(remote_name if remote_name is not None else path.name);fd=_regular(path,os.O_RDONLY)
        except (OSError,StorageError) as e:raise ClientError(str(e)) from e
        tid=None
        try:
            initial=os.fstat(fd);size=initial.st_size;sha256=_hash(fd)
            self.connect()
            self.upload_ticket={'transfer_id':transaction_id(self.info['username'],name,size,sha256),'name':name,'size':size,'sha256':sha256}
            response=self._request(Opcode.UPLOAD_BEGIN,{'name':name,'size':size,'sha256':sha256})
            if response.get('complete'):
                if response.get('sha256')!=sha256 or response.get('size')!=size:raise ClientError('Completed upload digest mismatch','INTEGRITY')
                self.upload_ticket=None
                if progress:progress(size,size)
                return {**response,'status':'complete','bytes':size,'total':size,'resumed_from':size}
            tid=response['transfer_id'];offset=response['offset'];resumed=offset
            if tid!=self.upload_ticket['transfer_id']:raise ClientError('Upload identity mismatch','INTEGRITY')
            self.upload_ticket={'transfer_id':tid,'name':name,'size':size,'sha256':sha256}
            if type(offset) is not int or not 0<=offset<=size or _hash(fd,offset)!=response['prefix_sha256']:raise ClientError('Upload resume prefix mismatch; cancel transaction and retry','INTEGRITY')
            if progress:progress(offset,size)
            while True:
                intent=self._intent(pause_event,cancel_event)
                if intent:
                    self._request(Opcode.CANCEL,{'direction':'upload','transfer_id':tid,'discard':intent=='cancelled'});tid=None
                    return {'status':intent,'bytes':offset,'total':size,'resumed_from':resumed,'upload_ticket':self.upload_ticket if intent=='paused' else None}
                if offset==size:break
                data=os.pread(fd,min(self._block_size(),size-offset),offset)
                if not data:raise ClientError('Local source changed during upload','INTEGRITY')
                ack=self._request(Opcode.UPLOAD_CHUNK,{'transfer_id':tid,'offset':offset},data)
                if ack.get('offset')!=offset+len(data):raise ClientError('Unexpected upload acknowledgment')
                offset=ack['offset']
                if progress:progress(offset,size)
            final=os.fstat(fd)
            if (final.st_size,final.st_mtime_ns)!=(initial.st_size,initial.st_mtime_ns):raise ClientError('Local source changed during upload','INTEGRITY')
            result=self._request(Opcode.UPLOAD_COMMIT,{'transfer_id':tid});tid=None;self.upload_ticket=None
            if result.get('sha256')!=sha256:raise ClientError('Server final digest mismatch','INTEGRITY')
            return {**result,'status':'complete','bytes':size,'total':size,'resumed_from':resumed}
        except (OSError,StorageError) as e:raise ClientError(str(e)) from e
        finally:
            os.close(fd)
            if tid and self.sock:
                try:self._request(Opcode.CANCEL,{'direction':'upload','transfer_id':tid,'discard':False})
                except ClientError:self._disconnect()
    def cancel_upload(self,ticket):
        if not isinstance(ticket,dict) or not isinstance(ticket.get('transfer_id'),str):raise ClientError('Upload cancellation ticket required')
        self._request(Opcode.CANCEL,{'direction':'upload','transfer_id':ticket['transfer_id'],'discard':True})
        self.upload_ticket=None
        return {'status':'cancelled','bytes':0,'total':ticket.get('size',0)}
    def cancel_download(self,local_path,remote_name=None):
        target=Path(local_path).absolute();target=target.parent.resolve(strict=True)/target.name
        part=target.with_name(target.name+'.part');manifest=target.with_name(target.name+'.part.json')
        try:
            if not os.path.lexists(part) and not os.path.lexists(manifest):
                return {'status':'cancelled','bytes':0,'total':0}
            if not os.path.lexists(manifest):raise ClientError('Refusing to remove an unowned partial file','CONFLICT')
            mfd=_regular(manifest,os.O_RDONLY)
            with os.fdopen(mfd,'r',encoding='utf-8') as stream:
                original_manifest=os.fstat(stream.fileno())
                if original_manifest.st_size>4096:raise ClientError('Invalid cleanup manifest','CONFLICT')
                saved=json.load(stream)
                if (not isinstance(saved,dict) or saved.get('format')!='harbor-download-v1'
                        or saved.get('target')!=target.name or not isinstance(saved.get('part_identity'),list)
                        or len(saved['part_identity'])!=2
                        or (remote_name is not None and saved.get('name')!=remote_name)):
                    raise ClientError('Refusing to remove files without matching download ownership','CONFLICT')
                if os.path.lexists(part):
                    fd=_regular(part,os.O_RDONLY)
                    try:
                        actual=os.fstat(fd);named=os.stat(part,follow_symlinks=False)
                        if ([actual.st_dev,actual.st_ino]!=saved['part_identity']
                                or (named.st_dev,named.st_ino)!=(actual.st_dev,actual.st_ino)):
                            raise ClientError('Partial file was replaced; preserving local files','CONFLICT')
                        part.unlink()
                    finally:os.close(fd)
                current=os.stat(manifest,follow_symlinks=False)
                if (current.st_dev,current.st_ino)!=(original_manifest.st_dev,original_manifest.st_ino):
                    raise ClientError('Resume manifest was replaced; preserving it','CONFLICT')
                manifest.unlink()
        except (OSError,ValueError) as e:raise ClientError('Local cleanup failed: '+str(e)) from e
        return {'status':'cancelled','bytes':0,'total':0}
    def _recover_download_publication(self,target,part,manifest,name):
        if not os.path.lexists(part) or not os.path.lexists(manifest):return None
        mfd=_regular(manifest,os.O_RDONLY)
        with os.fdopen(mfd,'r',encoding='utf-8') as f:
            if os.fstat(f.fileno()).st_size>4096:return None
            saved=json.load(f)
        if not isinstance(saved,dict) or saved.get('name')!=name:return None
        fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd);partial=os.stat(part,follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=2 or (st.st_dev,st.st_ino)!=(partial.st_dev,partial.st_ino):return None
            if st.st_size!=saved.get('size') or _hash(fd)!=saved.get('sha256'):return None
            current=os.stat(target,follow_symlinks=False)
            if (current.st_dev,current.st_ino,current.st_mtime_ns)!=(st.st_dev,st.st_ino,st.st_mtime_ns):return None
            part.unlink();manifest.unlink()
            return {'status':'complete','bytes':st.st_size,'total':st.st_size,'resumed_from':st.st_size,'sha256':saved['sha256'],'name':name}
        finally:os.close(fd)
    def download(self,remote_name,local_path,progress=None,pause_event=None,cancel_event=None):
        if cancel_event and cancel_event.is_set():return self.cancel_download(local_path,remote_name=remote_name)
        fd=None;handle=None;part=None;manifest=None;fresh_identity=None;manifest_ready=False
        try:
            name=filename(remote_name);target=Path(local_path).absolute();parent=target.parent.resolve(strict=True);target=parent/target.name
            part=target.with_name(target.name+'.part');manifest=target.with_name(target.name+'.part.json');saved=None
            if os.path.lexists(target):
                recovered=self._recover_download_publication(target,part,manifest,name)
                if recovered:return recovered
                raise ClientError('Local destination already exists; choose a new filename','CONFLICT')
            if os.path.lexists(manifest):
                mfd=_regular(manifest,os.O_RDONLY)
                with os.fdopen(mfd,'r',encoding='utf-8') as f:
                    if os.fstat(f.fileno()).st_size>4096:raise ClientError('Invalid resume manifest')
                    saved=json.load(f)
                if not isinstance(saved,dict) or saved.get('name')!=name:raise ClientError('Resume manifest belongs to another file','CONFLICT')
            if os.path.lexists(part) and saved is None:raise ClientError('Partial file has no trusted resume manifest','CONFLICT')
            fresh=not os.path.lexists(part)
            fd=_regular(part,os.O_RDWR|os.O_CREAT|(os.O_EXCL if fresh else 0));initial_part=os.fstat(fd);offset=initial_part.st_size
            if fresh:fresh_identity=(initial_part.st_dev,initial_part.st_ino)
            manifest_ready=saved is not None
            response=self._request(Opcode.DOWNLOAD_INFO,{'name':name,'offset':offset});handle=response['download_id'];size=response['size'];sha256=response['sha256'];resumed=offset
            if saved and (saved.get('sha256')!=sha256 or saved.get('size')!=size):raise ClientError('Remote version changed; cancel local partial and restart','CONFLICT')
            if _hash(fd,offset)!=response['prefix_sha256']:raise ClientError('Download resume prefix mismatch','INTEGRITY')
            _state_write(manifest,{'name':name,'size':size,'sha256':sha256,'format':'harbor-download-v1',
                                   'target':target.name,'part_identity':[initial_part.st_dev,initial_part.st_ino]});manifest_ready=True
            if progress:progress(offset,size)
            while True:
                intent=self._intent(pause_event,cancel_event)
                if intent:
                    self._request(Opcode.CANCEL,{'direction':'download','download_id':handle});handle=None
                    os.close(fd);fd=None
                    if intent=='cancelled':self.cancel_download(target,remote_name=name)
                    return {'status':intent,'bytes':offset,'total':size,'resumed_from':resumed}
                if offset==size:break
                meta,data=self._request(Opcode.DOWNLOAD_CHUNK,{'download_id':handle,'offset':offset,'length':min(self._block_size(),size-offset)},binary=True)
                if meta.get('offset')!=offset or meta.get('length')!=len(data) or not data or offset+len(data)>size:raise ClientError('Invalid download block')
                at=0
                while at<len(data):
                    n=os.pwrite(fd,data[at:],offset+at)
                    if n<=0:raise OSError('Short disk write')
                    at+=n
                offset+=len(data);os.fsync(fd)
                if progress:progress(offset,size)
            if os.fstat(fd).st_size!=size or _hash(fd)!=sha256:raise ClientError('Downloaded file failed SHA-256 verification','INTEGRITY')
            self._request(Opcode.CANCEL,{'direction':'download','download_id':handle});handle=None
            verified=os.fstat(fd);named=os.stat(part,follow_symlinks=False)
            if (verified.st_dev,verified.st_ino)!=(named.st_dev,named.st_ino):raise ClientError('Partial pathname changed before publication','INTEGRITY')
            os.link(part,target,follow_symlinks=False)
            published=os.stat(target,follow_symlinks=False)
            if (published.st_dev,published.st_ino)!=(verified.st_dev,verified.st_ino):
                target.unlink();raise ClientError('Publication identity mismatch','INTEGRITY')
            os.close(fd);fd=None;part.unlink();manifest.unlink()
            return {'status':'complete','bytes':size,'total':size,'resumed_from':resumed,'sha256':sha256,'name':name}
        except ClientError:raise
        except (OSError,ValueError,KeyError) as e:raise ClientError(str(e)) from e
        finally:
            if fd is not None:
                if fresh_identity is not None and not manifest_ready:
                    try:
                        current=os.stat(part,follow_symlinks=False)
                        if (current.st_dev,current.st_ino)==fresh_identity:part.unlink()
                    except FileNotFoundError:pass
                os.close(fd)
            if handle and self.sock:
                try:self._request(Opcode.CANCEL,{'direction':'download','download_id':handle})
                except ClientError:self._disconnect()

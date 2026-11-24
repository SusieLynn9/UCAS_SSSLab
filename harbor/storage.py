"""User-confined storage with descriptor-relative access and resumable transactions."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

class StorageError(ValueError):
    def __init__(self,message,code='INVALID'):super().__init__(message);self.code=code

def integer(value,name,maximum=2**40):
    if type(value) is not int or not 0<=value<=maximum:raise StorageError(f'Invalid {name}')
    return value

def filename(value):
    if not isinstance(value,str) or not value or len(value.encode('utf-8'))>200 or value.startswith('.') or value.endswith((' ','.')) or any(c in value for c in '/\\:') or any(ord(c)<32 or ord(c)==127 for c in value):raise StorageError('Invalid filename')
    if value.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}:raise StorageError('Reserved filename')
    return value

def digest(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise StorageError('Invalid SHA-256')
    return value

def transaction_id(user,name,size,sha256):
    return hashlib.sha256(json.dumps([user,name,size,sha256],separators=(',',':')).encode()).hexdigest()

def _open(directory,name,flags,mode=0o600):
    fd=os.open(name,flags|os.O_NOFOLLOW,mode,dir_fd=directory)
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:os.close(fd);raise StorageError('Only private regular files are permitted','DENIED')
    return fd

def _hash(fd,limit=None):
    h=hashlib.sha256();offset=0
    while limit is None or offset<limit:
        size=1024*1024 if limit is None else min(1024*1024,limit-offset)
        block=os.pread(fd,size,offset)
        if not block:break
        h.update(block);offset+=len(block)
    return h.hexdigest()

def _sync(fd):
    try:os.fsync(fd)
    except OSError:pass  # Some platforms reject directory fsync; file data sync is separate.

class Download:
    def __init__(self,fd,offset):
        self.fd=fd;self.before=os.fstat(fd);self.version=(self.before.st_ino,self.before.st_size,self.before.st_mtime_ns)
        self.info={'size':self.before.st_size,'sha256':_hash(fd),'offset':offset,'prefix_sha256':_hash(fd,offset)}
        self._check()
    def _check(self):
        s=os.fstat(self.fd)
        if (s.st_ino,s.st_size,s.st_mtime_ns)!=self.version:raise StorageError('File changed during download','CONFLICT')
    def read(self,offset,length):
        integer(offset,'offset',self.info['size']);integer(length,'length',65536);self._check()
        data=os.pread(self.fd,length,offset);self._check();return data
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None

class Storage:
    def __init__(self,root,users,max_transactions=16,max_files=256,ttl=86400):
        self.root=Path(root).absolute();self.users={u['name']:u for u in users};self.lock=threading.RLock();self.active={};self.dirs={};self.max_transactions=max_transactions;self.max_files=max_files;self.ttl=ttl
        if self.root.is_symlink():raise StorageError('Storage root must not be a symlink')
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(self.root,0o700)
        self.rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for name in self.users:
                if not re.fullmatch('[A-Za-z0-9_-]{1,32}',name):raise StorageError('Invalid configured user')
                try:os.mkdir(name,0o700,dir_fd=self.rootfd)
                except FileExistsError:pass
                ufd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.rootfd);os.fchmod(ufd,0o700)
                try:os.mkdir('.partial',0o700,dir_fd=ufd)
                except FileExistsError:pass
                pfd=os.open('.partial',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=ufd);os.fchmod(pfd,0o700);self.dirs[name]=(ufd,pfd)
            for name in self.users:self._recover_publication(name)
        except Exception:self.close();raise
    def close(self):
        for pair in self.dirs.values():
            for fd in pair:os.close(fd)
        self.dirs.clear()
        if getattr(self,'rootfd',None) is not None:os.close(self.rootfd);self.rootfd=None
    def _recover_publication(self,user):
        ufd,pfd=self.dirs[user]
        for entry in os.listdir(pfd):
            if not entry.endswith('.json'):continue
            fd=None
            try:
                tid=entry[:-5];m=self._manifest(pfd,tid)
                fd=os.open(m['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=ufd);st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink not in (1,2) or st.st_size!=m['size']:continue
                try:partial=os.stat(tid+'.part',dir_fd=pfd,follow_symlinks=False)
                except FileNotFoundError:partial=None
                if partial is not None and (partial.st_dev,partial.st_ino)!=(st.st_dev,st.st_ino):continue
                if _hash(fd)!=m['sha256']:continue
                current=os.stat(m['name'],dir_fd=ufd,follow_symlinks=False)
                if (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)!=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns):continue
                if partial is not None:os.unlink(tid+'.part',dir_fd=pfd)
                os.unlink(entry,dir_fd=pfd);_sync(ufd);_sync(pfd)
            except (OSError,StorageError):
                # Never delete ambiguous state; the owner can explicitly cancel it.
                continue
            finally:
                if fd is not None:os.close(fd)
    def _user(self,user,permission=None):
        if user not in self.users:raise StorageError('Unknown user','DENIED')
        if permission and not self.users[user].get(permission,False):raise StorageError('Permission denied','DENIED')
        return self.dirs[user]
    def list_files(self,user):
        with self.lock:
            ufd,_=self._user(user,'can_download');rows=[]
            for name in sorted(os.listdir(ufd)):
                if name.startswith('.'):continue
                try:
                    filename(name);s=os.stat(name,dir_fd=ufd,follow_symlinks=False)
                    if stat.S_ISREG(s.st_mode) and s.st_nlink==1:rows.append({'name':name,'size':s.st_size,'mtime':s.st_mtime})
                except (OSError,StorageError):continue
                if len(rows)>self.max_files:raise StorageError('Directory entry limit exceeded','QUOTA')
            return rows
    def _manifest(self,pfd,tid):
        digest(tid);fd=_open(pfd,tid+'.json',os.O_RDONLY)
        try:
            if os.fstat(fd).st_size>4096:raise StorageError('Invalid transaction state')
            obj=json.loads(os.read(fd,4097).decode('utf-8'))
            if not isinstance(obj,dict):raise StorageError('Invalid transaction state')
            filename(obj['name']);integer(obj['size'],'size');digest(obj['sha256'])
            if type(obj['created']) not in (int,float):raise StorageError('Invalid transaction time')
            return obj
        except (KeyError,ValueError,UnicodeError) as e:raise StorageError('Invalid transaction state') from e
        finally:os.close(fd)
    def _delete(self,pfd,tid):
        for suffix in ('.part','.json'):
            try:os.unlink(tid+suffix,dir_fd=pfd)
            except FileNotFoundError:pass
    def begin(self,user,name,size,sha256,owner):
        name=filename(name);integer(size,'size');digest(sha256)
        tid=transaction_id(user,name,size,sha256)
        with self.lock:
            ufd,pfd=self._user(user,'can_upload')
            try:os.stat(name,dir_fd=ufd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:
                fd=_open(ufd,name,os.O_RDONLY)
                try:
                    if os.fstat(fd).st_size==size and _hash(fd)==sha256:return {'complete':True,'name':name,'size':size,'sha256':sha256,'offset':size}
                finally:os.close(fd)
                raise StorageError('Target already exists with different content; choose a new filename','CONFLICT')
            reserved=0;count=0;existing=None
            for entry in os.listdir(pfd):
                if not entry.endswith('.json'):continue
                other=entry[:-5];m=self._manifest(pfd,other)
                if time.time()-m['created']>self.ttl and (user,other) not in self.active:self._delete(pfd,other);continue
                reserved+=m['size'];count+=1
                if other==tid:existing=m
                elif m['name']==name:raise StorageError('Another upload reserves this target','CONFLICT')
            if (user,tid) in self.active:raise StorageError('Upload already active','BUSY')
            # Published files and declared unfinished uploads both consume quota.
            used=0;files=0
            for entry in os.listdir(ufd):
                if entry.startswith('.'):continue
                st=os.stat(entry,dir_fd=ufd,follow_symlinks=False)
                if stat.S_ISREG(st.st_mode):used+=st.st_size;files+=1
            if existing is None:
                if count>=self.max_transactions or files+count>=self.max_files or used+reserved+size>self.users[user]['quota_bytes']:raise StorageError('Storage quota/transaction limit exceeded','QUOTA')
                fd=_open(pfd,tid+'.part',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                os.close(fd);m={'name':name,'size':size,'sha256':sha256,'created':time.time()}
                try:
                    fd=_open(pfd,tid+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                    with os.fdopen(fd,'wb') as f:f.write(json.dumps(m).encode());f.flush();os.fsync(f.fileno())
                except Exception:self._delete(pfd,tid);raise
            fd=_open(pfd,tid+'.part',os.O_RDONLY)
            try:
                offset=os.fstat(fd).st_size
                if offset>size:raise StorageError('Partial file exceeds declared length','CONFLICT')
                prefix=_hash(fd,offset)
            finally:os.close(fd)
            self.active[(user,tid)]=owner
            return {'transfer_id':tid,'offset':offset,'prefix_sha256':prefix,'size':size}
    def _owned(self,user,tid,owner):
        ufd,pfd=self._user(user,'can_upload');digest(tid)
        if self.active.get((user,tid))!=owner:raise StorageError('Upload not owned by this connection','DENIED')
        return ufd,pfd,self._manifest(pfd,tid)
    def write(self,user,tid,offset,data,owner):
        integer(offset,'offset')
        if not isinstance(data,bytes) or not 0<len(data)<=65536:raise StorageError('Invalid chunk')
        with self.lock:
            _,pfd,m=self._owned(user,tid,owner);fd=_open(pfd,tid+'.part',os.O_WRONLY)
            try:
                if os.fstat(fd).st_size!=offset or offset+len(data)>m['size']:raise StorageError('Unexpected upload offset/length','CONFLICT')
                os.lseek(fd,offset,os.SEEK_SET);view=memoryview(data)
                while view:
                    n=os.write(fd,view)
                    if n<=0:raise OSError('Short disk write')
                    view=view[n:]
                os.fsync(fd)
            finally:os.close(fd)
            return offset+len(data)
    def commit(self,user,tid,owner):
        with self.lock:
            ufd,pfd,m=self._owned(user,tid,owner);fd=_open(pfd,tid+'.part',os.O_RDONLY)
            try:
                if os.fstat(fd).st_size!=m['size'] or _hash(fd)!=m['sha256']:raise StorageError('Final length/SHA-256 mismatch','INTEGRITY')
                verified=os.fstat(fd);named=os.stat(tid+'.part',dir_fd=pfd,follow_symlinks=False)
                if (verified.st_dev,verified.st_ino)!=(named.st_dev,named.st_ino):raise StorageError('Partial file changed before publication','INTEGRITY')
                try:os.link(tid+'.part',m['name'],src_dir_fd=pfd,dst_dir_fd=ufd,follow_symlinks=False)
                except FileExistsError:raise StorageError('Target already exists','CONFLICT')
                published=os.stat(m['name'],dir_fd=ufd,follow_symlinks=False)
                if (published.st_dev,published.st_ino)!=(verified.st_dev,verified.st_ino):
                    os.unlink(m['name'],dir_fd=ufd);raise StorageError('Publication identity mismatch','INTEGRITY')
            finally:os.close(fd)
            os.unlink(tid+'.part',dir_fd=pfd);os.unlink(tid+'.json',dir_fd=pfd);_sync(ufd);_sync(pfd);self.active.pop((user,tid),None)
            return {'name':m['name'],'size':m['size'],'sha256':m['sha256']}
    def cancel(self,user,tid,owner,discard=False):
        with self.lock:
            _,pfd=self._user(user,'can_upload');digest(tid)
            active=self.active.get((user,tid))
            if active is not None and active!=owner:raise StorageError('Upload is active on another connection','BUSY')
            if not discard and active!=owner:raise StorageError('Upload not active on this connection','STATE')
            if discard:self._delete(pfd,tid)
            self.active.pop((user,tid),None)
    def release_owner(self,owner):
        with self.lock:
            for key,value in list(self.active.items()):
                if value==owner:self.active.pop(key,None)
    def open_download(self,user,name,offset=0):
        name=filename(name);integer(offset,'offset')
        with self.lock:
            ufd,_=self._user(user,'can_download')
            try:fd=_open(ufd,name,os.O_RDONLY)
            except OSError as e:raise StorageError('File unavailable','NOT_FOUND') from e
            try:
                if offset>os.fstat(fd).st_size:raise StorageError('Download offset exceeds file size','CONFLICT')
                return Download(fd,offset)
            except Exception:os.close(fd);raise

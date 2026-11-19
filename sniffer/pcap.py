"""Minimal typed libpcap ABI binding. A capture handle belongs to one worker."""
import ctypes as C
import ctypes.util
import os
from pathlib import Path
import struct
import sys

class PcapError(RuntimeError):
    pass

class Timeval(C.Structure):
    _fields_=[('tv_sec',C.c_int32 if sys.platform=='win32' else C.c_long),
              ('tv_usec',C.c_int32 if sys.platform in ('darwin','win32') else C.c_long)]
class Header(C.Structure):
    _fields_=[('ts',Timeval),('caplen',C.c_uint32),('length',C.c_uint32)]
class Device(C.Structure):pass
Device._fields_=[('next',C.POINTER(Device)),('name',C.c_char_p),('description',C.c_char_p),('addresses',C.c_void_p),('flags',C.c_uint)]
class Program(C.Structure):
    _fields_=[('length',C.c_uint),('insns',C.c_void_p)]
class Stats(C.Structure):
    # Extra space accommodates Windows/macOS extensions beyond the first three fields.
    _fields_=[('received',C.c_uint),('dropped',C.c_uint),('interface_dropped',C.c_uint),('_extra',C.c_uint*13)]


def _library():
    name=ctypes.util.find_library('pcap')
    try:
        if sys.platform=='win32':
            folder=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'/'Npcap'
            # Keep the directory handle alive for dependent DLL resolution.
            directory=os.add_dll_directory(str(folder)) if hasattr(os,'add_dll_directory') else None
            lib=C.CDLL(str(folder/'wpcap.dll'));lib._dll_directory=directory
        else:lib=C.CDLL(name or ('/usr/lib/libpcap.dylib' if sys.platform=='darwin' else 'libpcap.so.1'))
    except OSError as e:raise PcapError('libpcap unavailable. macOS: system libpcap; Linux: libpcap; Windows: install Npcap. '+str(e))
    defs={
        'pcap_findalldevs':(C.c_int,[C.POINTER(C.POINTER(Device)),C.c_char_p]),'pcap_freealldevs':(None,[C.POINTER(Device)]),
        'pcap_open_offline':(C.c_void_p,[C.c_char_p,C.c_char_p]),'pcap_create':(C.c_void_p,[C.c_char_p,C.c_char_p]),
        'pcap_set_snaplen':(C.c_int,[C.c_void_p,C.c_int]),'pcap_set_promisc':(C.c_int,[C.c_void_p,C.c_int]),
        'pcap_set_timeout':(C.c_int,[C.c_void_p,C.c_int]),'pcap_set_buffer_size':(C.c_int,[C.c_void_p,C.c_int]),
        'pcap_activate':(C.c_int,[C.c_void_p]),'pcap_datalink':(C.c_int,[C.c_void_p]),
        'pcap_setnonblock':(C.c_int,[C.c_void_p,C.c_int,C.c_char_p]),
        'pcap_next_ex':(C.c_int,[C.c_void_p,C.POINTER(C.POINTER(Header)),C.POINTER(C.POINTER(C.c_ubyte))]),
        'pcap_compile':(C.c_int,[C.c_void_p,C.POINTER(Program),C.c_char_p,C.c_int,C.c_uint32]),
        'pcap_setfilter':(C.c_int,[C.c_void_p,C.POINTER(Program)]),'pcap_freecode':(None,[C.POINTER(Program)]),
        'pcap_geterr':(C.c_char_p,[C.c_void_p]),'pcap_close':(None,[C.c_void_p]),'pcap_stats':(C.c_int,[C.c_void_p,C.POINTER(Stats)]),
        'pcap_lib_version':(C.c_char_p,[])}
    for fn,(restype,args) in defs.items():
        f=getattr(lib,fn);f.restype=restype;f.argtypes=args
    return lib

class Pcap:
    def __init__(self,lib,handle):
        self.lib,self.handle=lib,handle;self.linktype=lib.pcap_datalink(handle);self.warning=''
    @classmethod
    def devices(cls):
        lib=_library();head=C.POINTER(Device)();err=C.create_string_buffer(256)
        if lib.pcap_findalldevs(C.byref(head),err)!=0:raise PcapError(err.value.decode(errors='replace'))
        rows=[]
        try:
            ptr=head
            while ptr:
                d=ptr.contents;rows.append({'name':d.name.decode(errors='replace'),'description':(d.description or b'').decode(errors='replace'),'loopback':bool(d.flags&1),'up':bool(d.flags&2)})
                ptr=d.next
        finally:lib.pcap_freealldevs(head)
        return rows
    @classmethod
    def offline(cls,path,bpf=''):
        lib=_library();err=C.create_string_buffer(256);h=lib.pcap_open_offline(os.fsencode(path),err)
        if not h:raise PcapError(err.value.decode(errors='replace'))
        cap=cls(lib,h)
        try:cap.set_filter(bpf)
        except Exception:cap.close();raise
        return cap
    @classmethod
    def live(cls,device,bpf='',promiscuous=False,snaplen=65535):
        lib=_library();err=C.create_string_buffer(256);h=lib.pcap_create(device.encode(),err)
        if not h:raise PcapError(err.value.decode(errors='replace'))
        cap=cls(lib,h)
        try:
            for name,value in [('pcap_set_snaplen',snaplen),('pcap_set_promisc',int(promiscuous)),('pcap_set_timeout',100),('pcap_set_buffer_size',4*1024*1024)]:
                if getattr(lib,name)(h,value)!=0:raise PcapError(cap.error())
            status=lib.pcap_activate(h)
            if status<0:raise PcapError(cap.error())
            if status>0:cap.warning=cap.error() or f'libpcap activation warning {status}'
            cap.linktype=lib.pcap_datalink(h)
            if lib.pcap_setnonblock(h,1,err)!=0:raise PcapError(err.value.decode(errors='replace'))
            cap.set_filter(bpf)
            return cap
        except Exception:cap.close();raise
    def error(self):return (self.lib.pcap_geterr(self.handle) or b'libpcap error').decode(errors='replace')
    def set_filter(self,bpf):
        if not bpf:return
        prog=Program()
        if self.lib.pcap_compile(self.handle,C.byref(prog),bpf.encode(),1,0xffffffff)!=0:raise PcapError(self.error())
        try:
            if self.lib.pcap_setfilter(self.handle,C.byref(prog))!=0:raise PcapError(self.error())
        finally:self.lib.pcap_freecode(C.byref(prog))
    def next(self):
        hdr=C.POINTER(Header)();data=C.POINTER(C.c_ubyte)()
        status=self.lib.pcap_next_ex(self.handle,C.byref(hdr),C.byref(data))
        if status==0:return None
        if status==-2:raise StopIteration
        if status==-1:raise PcapError(self.error())
        h=hdr.contents
        if h.caplen>16*1024*1024:raise PcapError('Packet capture length exceeds safety limit')
        return (h.ts.tv_sec+h.ts.tv_usec/1e6,C.string_at(data,h.caplen),h.length)
    def stats(self):
        s=Stats()
        if self.lib.pcap_stats(self.handle,C.byref(s))!=0:return None
        return {'received':s.received,'dropped':s.dropped,'interface_dropped':s.interface_dropped}
    def __iter__(self):
        while True:
            try:row=self.next()
            except StopIteration:return
            if row is not None:yield row
    def close(self):
        if self.handle:self.lib.pcap_close(self.handle);self.handle=None
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def write_pcap(path,linktype,packets):
    """Write classic microsecond PCAP; caller may supply a binary stream."""
    own=not hasattr(path,'write');stream=open(path,'wb') if own else path
    try:
        stream.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,16*1024*1024,linktype))
        for timestamp,raw,wirelen in packets:
            sec=int(timestamp);usec=int(round((timestamp-sec)*1e6))
            if usec>=1000000:sec+=1;usec-=1000000
            stream.write(struct.pack('<IIII',sec,usec,len(raw),len(raw) if wirelen is None else wirelen));stream.write(raw)
    finally:
        if own:stream.close()

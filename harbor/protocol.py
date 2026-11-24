"""Harbor v1: bounded binary framing over a persistent authenticated TLS stream."""
from dataclasses import dataclass,field
from enum import IntEnum
import json
import socket
import struct
import time

HEADER=struct.Struct('!4sBBHIII')
MAGIC=b'HBR1';VERSION=1;MAX_METADATA=16384;MAX_PAYLOAD=65536
RESPONSE=0x80;ERROR=1
class Opcode(IntEnum):
    HELLO=1;LIST=2;UPLOAD_BEGIN=3;UPLOAD_CHUNK=4;UPLOAD_COMMIT=5;DOWNLOAD_INFO=6;DOWNLOAD_CHUNK=7;PING=8;CANCEL=9;QUIT=10
class ProtocolError(ValueError):pass
@dataclass
class Frame:
    opcode:int
    request_id:int
    metadata:dict=field(default_factory=dict)
    payload:bytes=b''
    flags:int=0

def _object(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:raise ProtocolError('Duplicate metadata key')
        obj[key]=value
    return obj

def encode_frame(frame):
    if type(frame.request_id) is not int or not 1<=frame.request_id<=0xffffffff:raise ProtocolError('Invalid request ID')
    if int(frame.opcode)&0x7f not in set(Opcode):raise ProtocolError('Unknown opcode')
    if frame.flags not in (0,ERROR) or (frame.flags and not int(frame.opcode)&RESPONSE):raise ProtocolError('Invalid frame flags')
    if not isinstance(frame.metadata,dict) or not isinstance(frame.payload,bytes):raise ProtocolError('Invalid metadata/payload')
    try:metadata=json.dumps(frame.metadata,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
    except (ValueError,TypeError,RecursionError) as e:raise ProtocolError('Invalid metadata') from e
    if len(metadata)>MAX_METADATA or len(frame.payload)>MAX_PAYLOAD:raise ProtocolError('Frame exceeds length limit')
    return HEADER.pack(MAGIC,VERSION,int(frame.opcode),frame.flags,frame.request_id,len(metadata),len(frame.payload))+metadata+frame.payload

def recv_exact(sock,size,deadline):
    chunks=[];remaining=size
    while remaining:
        left=deadline-time.monotonic()
        if left<=0:raise TimeoutError('Frame deadline exceeded')
        # Memory-backed test transports need no socket timeout. Real sockets are
        # deadline-limited across the entire frame, rather than per received byte.
        if hasattr(sock,'settimeout'):sock.settimeout(left)
        chunk=sock.recv(remaining)
        if not chunk:raise ProtocolError('Truncated frame / peer closed')
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

def recv_frame(sock,timeout=120):
    previous=sock.gettimeout() if hasattr(sock,'gettimeout') else None
    try:
        deadline=time.monotonic()+timeout
        magic,version,opcode,flags,ident,meta_size,payload_size=HEADER.unpack(recv_exact(sock,HEADER.size,deadline))
        if magic!=MAGIC or version!=VERSION:raise ProtocolError('Unsupported protocol magic/version')
        if opcode&0x7f not in set(Opcode) or flags not in (0,ERROR) or (flags and not opcode&RESPONSE) or ident==0:raise ProtocolError('Invalid frame header')
        if meta_size>MAX_METADATA or payload_size>MAX_PAYLOAD:raise ProtocolError('Frame exceeds length limit')
        raw=recv_exact(sock,meta_size,deadline)
        try:metadata=json.loads(raw.decode('utf-8'),object_pairs_hook=_object,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite number')))
        except (ValueError,UnicodeError,RecursionError) as e:raise ProtocolError('Invalid JSON metadata') from e
        if not isinstance(metadata,dict):raise ProtocolError('Metadata object required')
        return Frame(opcode,ident,metadata,recv_exact(sock,payload_size,deadline),flags)
    finally:
        if hasattr(sock,'settimeout'):sock.settimeout(previous)

def send_frame(sock,frame):sock.sendall(encode_frame(frame))

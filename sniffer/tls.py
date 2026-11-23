"""Visible TLS Hello metadata; offered values never imply negotiated values."""
import struct
from .errors import DecodeError

VERSIONS={0x0300:'SSL 3.0',0x0301:'TLS 1.0',0x0302:'TLS 1.1',0x0303:'TLS 1.2',0x0304:'TLS 1.3'}

def version_name(value):return VERSIONS.get(value,f'0x{value:04x}')

def parse_tls(data):
    n=int.from_bytes(data[3:5],'big');complete=len(data)>=5+n
    fields={'Record type':data[0],'Legacy version':f'{data[1]}.{data[2]}','Record length':n,'Record complete':complete}
    info={20:'ChangeCipherSpec',21:'Alert',22:'Handshake',23:'Encrypted application data'}[data[0]]
    if not complete:return info+' (incomplete record)',fields
    if data[0]!=22:return info,fields
    record=data[5:5+n]
    if len(record)<4:return 'Handshake (incomplete header)',fields
    kind=record[0];size=int.from_bytes(record[1:4],'big');fields['Handshake type']=kind
    if kind not in (1,2):return info,fields
    hello='ClientHello' if kind==1 else 'ServerHello';server=kind==2
    fields['Handshake complete']=len(record)>=4+size
    if not fields['Handshake complete']:
        fields['Note']='Handshake spans TLS records or is incomplete; cross-record handshake reassembly is not supported'
        return hello+' (incomplete handshake)',fields
    h=record[4:4+size];pos=0
    def take(n):
        nonlocal pos
        if pos+n>len(h):raise DecodeError('TLS Hello truncated')
        value=h[pos:pos+n];pos+=n;return value
    parsed={}
    try:
        legacy=int.from_bytes(take(2),'big');take(32)
        sid=take(1)[0]
        if sid>32:raise DecodeError('TLS session ID too long')
        take(sid)
        if server:
            parsed['Cipher suite']=f'0x{int.from_bytes(take(2),"big"):04x}'
            take(1)
        else:
            cipherlen=int.from_bytes(take(2),'big')
            if cipherlen<2 or cipherlen%2:raise DecodeError('Invalid TLS cipher suite vector')
            take(cipherlen);compressionlen=take(1)[0]
            if compressionlen<1:raise DecodeError('Empty TLS compression vector')
            take(compressionlen)
        extensions={}
        if pos<len(h):
            extlen=int.from_bytes(take(2),'big')
            if pos+extlen!=len(h):raise DecodeError('TLS extension block length mismatch')
            stop=pos+extlen
            while pos<stop:
                if pos+4>stop:raise DecodeError('TLS extension header truncated')
                extkind,length=struct.unpack('!HH',take(4))
                if pos+length>stop:raise DecodeError('TLS extension exceeds declared block')
                if extkind in extensions:raise DecodeError('Duplicate TLS extension')
                extensions[extkind]=take(length)
        selected=legacy
        if 43 in extensions:
            v=extensions[43]
            if server:
                if len(v)!=2:raise DecodeError('Invalid selected TLS version')
                selected=int.from_bytes(v,'big')
            else:
                if not v or v[0]!=len(v)-1 or v[0]<2 or v[0]%2:raise DecodeError('Invalid supported TLS versions')
                parsed['Supported versions']=', '.join(version_name(int.from_bytes(v[i:i+2],'big')) for i in range(1,len(v),2))
        if server:parsed['Selected version']=version_name(selected)
        if 0 in extensions and not server:
            v=extensions[0]
            if len(v)<2 or int.from_bytes(v[:2],'big')!=len(v)-2:raise DecodeError('Invalid TLS SNI list')
            at=2
            while at<len(v):
                if at+3>len(v):raise DecodeError('TLS SNI entry truncated')
                typ=v[at];length=int.from_bytes(v[at+1:at+3],'big');at+=3
                if length==0 or at+length>len(v):raise DecodeError('Invalid TLS SNI name length')
                if typ==0:parsed['SNI']=v[at:at+length].decode('ascii','backslashreplace')
                at+=length
        if 16 in extensions:
            v=extensions[16]
            if len(v)<3 or int.from_bytes(v[:2],'big')!=len(v)-2:raise DecodeError('Invalid TLS ALPN list')
            names=[];at=2
            while at<len(v):
                length=v[at];at+=1
                if not length or at+length>len(v):raise DecodeError('Invalid TLS ALPN name length')
                names.append(v[at:at+length].decode('ascii','backslashreplace'));at+=length
            if server:
                if selected==0x0304:raise DecodeError('TLS 1.3 ALPN selection is not carried in ServerHello')
                if len(names)!=1:raise DecodeError('Server ALPN must select exactly one protocol')
            parsed['Selected ALPN' if server else 'Offered ALPN']=', '.join(names)
        if server and selected==0x0304:parsed['ALPN visibility']='TLS 1.3 server ALPN is in encrypted EncryptedExtensions'
        fields.update(parsed);info=hello
        if parsed.get('SNI'):info+=' · '+parsed['SNI']
        if server:info+=' · '+parsed['Selected version']
    except DecodeError as exc:
        fields['Note']=str(exc);info=hello+' (malformed)'
    return info,fields

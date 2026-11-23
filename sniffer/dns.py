"""DNS question and common resource-record decoding (RFC 1035 wire format)."""
import ipaddress
import struct
from .errors import DecodeError

TYPES={1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',41:'OPT'}


def dns_name(data,offset):
    parts,seen,end=[],set(),None
    wire_size=1
    for _ in range(128):
        if offset>=len(data) or offset in seen:raise DecodeError('DNS name truncated or pointer cycle')
        seen.add(offset);n=data[offset]
        if n&0xc0==0xc0:
            if offset+1>=len(data):raise DecodeError('DNS pointer truncated')
            if end is None:end=offset+2
            offset=((n&63)<<8)|data[offset+1]
        elif n==0:return '.'.join(parts) or '.',end if end is not None else offset+1
        elif n>63 or offset+1+n>len(data):raise DecodeError('Invalid DNS label')
        else:
            wire_size+=n+1
            if wire_size>255:raise DecodeError('DNS expanded name exceeds 255 bytes')
            parts.append(data[offset+1:offset+1+n].decode('ascii','backslashreplace'));offset+=n+1
    raise DecodeError('DNS name exceeds pointer limit')


def parse_dns(data,mdns=False):
    ident,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12])
    if qd>128 or an+ns+ar>256:raise DecodeError('DNS question/resource record limit exceeded')
    fields={'Transaction ID':hex(ident),'Response':bool(flags&0x8000),'Questions':qd,'Answers':an,'Authority records':ns,'Additional records':ar,'RCode':flags&15,'Truncated':bool(flags&0x0200)}
    pos=12
    for i in range(qd):
        value,pos=dns_name(data,pos)
        if pos+4>len(data):raise DecodeError('DNS question truncated')
        kind,cls=struct.unpack('!HH',data[pos:pos+4]);pos+=4
        fields[f'Question {i+1}']=f'{value} | {TYPES.get(kind,"TYPE"+str(kind))} | CLASS{cls}'
        if i==0:fields.update(Name=value,Type=kind)
    summaries=[]
    for section,count in (('Answer',an),('Authority',ns),('Additional',ar)):
        for i in range(count):
            owner,pos=dns_name(data,pos)
            if pos+10>len(data):raise DecodeError('DNS resource record header truncated')
            kind,cls,ttl,n=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10;end=pos+n
            if end>len(data):raise DecodeError('DNS RDATA exceeds message length')
            raw=data[pos:end]
            cache_flush=mdns and bool(cls&0x8000)
            base_class=cls&0x7fff if mdns else cls
            def read_name(at):
                result,after=dns_name(data,at)
                if after>end:raise DecodeError('DNS name exceeds RDATA boundary')
                return result,after
            if kind in (1,28) and base_class==1:
                expected=4 if kind==1 else 16
                if n!=expected:raise DecodeError('Invalid DNS address RDLENGTH')
                value=str(ipaddress.ip_address(raw))
            elif kind in (2,5,12):
                value,after=read_name(pos)
                if after!=end:raise DecodeError('Trailing bytes in DNS name RDATA')
            elif kind==15:
                if n<3:raise DecodeError('DNS MX RDATA truncated')
                exchange,after=read_name(pos+2)
                if after!=end:raise DecodeError('Trailing bytes in DNS MX RDATA')
                value=f'preference={int.from_bytes(raw[:2],"big")} {exchange}'
            elif kind==16:
                chunks=[];at=0
                while at<n:
                    size=raw[at];at+=1
                    if at+size>n:raise DecodeError('DNS TXT string exceeds RDATA boundary')
                    chunks.append(repr(raw[at:at+size].decode('utf-8','replace')));at+=size
                value=' '.join(chunks)
            elif kind==6:
                primary,after=read_name(pos);mailbox,after=read_name(after)
                if after+20!=end:raise DecodeError('Invalid DNS SOA RDATA length')
                serial,refresh,retry,expire,minimum=struct.unpack('!5I',data[after:end])
                value=f'{primary} {mailbox} serial={serial} refresh={refresh} retry={retry} expire={expire} minimum={minimum}'
            else:value=raw[:256].hex()+('… (preview truncated)' if len(raw)>256 else '')
            label=TYPES.get(kind,'TYPE'+str(kind))
            fields[f'{section} {i+1}']=f'{owner} | {label} | {value} | CLASS{base_class} | TTL={ttl}' if kind!=41 else f'{owner} | OPT | UDP size={cls} | flags={ttl:#x} | {value}'
            if cache_flush:fields[f'{section} {i+1}']+=' | cache-flush'
            if section=='Answer' and len(summaries)<4:summaries.append(f'{label} {value}')
            pos=end
    info=('Response' if flags&0x8000 else 'Query')+' '+fields.get('Name','')
    if summaries:info+=' → '+'; '.join(summaries)
    if flags&15:info+=f' RCode={flags&15}'
    return info,fields

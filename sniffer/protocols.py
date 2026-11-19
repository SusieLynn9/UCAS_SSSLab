"""Bounds-checked, dependency-free wire decoding. No port-only application labels."""
import ipaddress
import re
import socket
import struct


class DecodeError(ValueError):
    pass


def dns_name(data, offset):
    parts, seen, end = [], set(), None
    for _ in range(128):
        if offset >= len(data) or offset in seen:
            raise DecodeError('DNS name truncated or pointer cycle')
        seen.add(offset)
        n = data[offset]
        if n & 0xc0 == 0xc0:
            if offset+1 >= len(data):
                raise DecodeError('DNS pointer truncated')
            if end is None:
                end = offset+2
            offset = ((n & 0x3f) << 8) | data[offset+1]
        elif n == 0:
            return '.'.join(parts), end if end is not None else offset+1
        elif n > 63 or offset+1+n > len(data):
            raise DecodeError('Invalid DNS label')
        else:
            parts.append(data[offset+1:offset+1+n].decode('ascii','replace'))
            offset += n+1
    raise DecodeError('DNS name exceeds pointer limit')


def application(data, transport, sport=0, dport=0):
    """Return a feature-based application label and fields for contiguous bytes."""
    if transport == 'TCP':
        first = data.split(b'\r\n',1)[0]
        if re.match(rb'^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n ]+ HTTP/1\.[01]$',first) or re.match(rb'^HTTP/1\.[01] [1-5][0-9]{2}(?: |$)',first):
            headers = {}
            for line in data[:65536].split(b'\r\n')[1:]:
                if not line: break
                if b':' in line:
                    k,v=line.split(b':',1)
                    headers[k.decode('latin1')]=v.strip().decode('latin1')
            return 'HTTP', first.decode('latin1'), {'Start line':first.decode('latin1'),**headers}
        if len(data)>=5 and data[0] in (20,21,22,23) and data[1]==3 and data[2]<=4 and int.from_bytes(data[3:5],'big')<=18432:
            fields={'Record type':data[0],'Legacy version':f'{data[1]}.{data[2]}','Record length':int.from_bytes(data[3:5],'big')}
            info={20:'ChangeCipherSpec',21:'Alert',22:'Handshake',23:'Encrypted application data'}[data[0]]
            # Parse only a complete ClientHello; fragmented handshakes are left to stream view.
            try:
                if data[0]==22 and len(data)>=9 and data[5]==1:
                    size=int.from_bytes(data[6:9],'big')
                    if len(data)<9+size: return 'TLS', 'ClientHello (incomplete)', fields
                    h=data[9:9+size]
                    def take(pos,n):
                        if pos+n>len(h): raise DecodeError('TLS ClientHello truncated')
                        return h[pos:pos+n]
                    pos=34; pos+=1+take(pos,1)[0]
                    pos+=2+int.from_bytes(take(pos,2),'big')
                    pos+=1+take(pos,1)[0]
                    total=int.from_bytes(take(pos,2),'big'); pos+=2; stop=pos+total
                    if stop>len(h): raise DecodeError('TLS extensions truncated')
                    while pos+4<=stop:
                        kind,n=struct.unpack('!HH',take(pos,4)); pos+=4
                        ext=take(pos,n); pos+=n
                        if kind==0 and len(ext)>=5:
                            namelen=int.from_bytes(ext[3:5],'big')
                            if ext[2]==0 and len(ext)>=5+namelen:
                                fields['SNI']=ext[5:5+namelen].decode('ascii','replace'); info='ClientHello · '+fields['SNI']
            except (IndexError,DecodeError):
                fields['Note']='Malformed or incomplete ClientHello'
            return 'TLS',info,fields
    dns = data
    if transport=='TCP' and len(data)>=2:
        n=int.from_bytes(data[:2],'big'); dns=data[2:2+n] if n<=len(data)-2 else b''
    if (sport in (53,5353) or dport in (53,5353)) and len(dns)>=12:
        ident,flags,qd,an,ns,ar=struct.unpack('!6H',dns[:12])
        if qd<=128 and (qd or an) and (flags>>11)&15 in (0,1,2,4,5):
            fields={'Transaction ID':hex(ident),'Response':bool(flags&0x8000),'Questions':qd,'Answers':an,'RCode':flags&15}
            if qd:
                name,pos=dns_name(dns,12)
                if pos+4>len(dns): raise DecodeError('DNS question truncated')
                fields['Name']=name; fields['Type']=int.from_bytes(dns[pos:pos+2],'big')
            return 'DNS',('Response' if flags&0x8000 else 'Query')+' '+fields.get('Name',''),fields
    return '', '', {}


def decode_packet(raw, linktype=1, timestamp=0.0, wirelen=None):
    p={'timestamp':timestamp,'length':len(raw) if wirelen is None else wirelen,'captured':len(raw),
       'src':'','dst':'','sport':None,'dport':None,'protocol':'Unknown','transport':'','layers':[],
       'details':[],'warnings':[],'info':'','payload':b'','linktype':linktype}
    if p['length']>len(raw): p['warnings'].append('Capture truncated: captured length < wire length')
    def layer(name,fields,offset=0,size=0):
        p['layers'].append(name); p['details'].append({'name':name,'fields':fields,'offset':offset,'size':size}); p['protocol']=name
    def need(pos,n,end=None):
        if pos<0 or pos+n>(len(raw) if end is None else min(end,len(raw))): raise DecodeError('Truncated header')
    def mac(b): return ':'.join(f'{v:02x}' for v in b)
    try:
        pos=0
        if linktype==1:
            need(0,14); kind=int.from_bytes(raw[12:14],'big');pos=14
            layer('Ethernet',{'Destination':mac(raw[:6]),'Source':mac(raw[6:12]),'EtherType':hex(kind)},0,14)
            p['src']=mac(raw[6:12]);p['dst']=mac(raw[:6])
            for _ in range(8):
                if kind not in (0x8100,0x88a8,0x9100): break
                need(pos,4); tag,kind=struct.unpack('!HH',raw[pos:pos+4]);layer('VLAN',{'ID':tag&4095,'Priority':tag>>13},pos,4);pos+=4
        elif linktype in (0,108):
            need(0,4); family=int.from_bytes(raw[:4],'little' if linktype==0 else 'big')
            # Some files use the other host byte order for DLT_NULL.
            if family not in (2,10,24,28,30): family=int.from_bytes(raw[:4],'big')
            kind=0x0800 if family==2 else 0x86dd if family in (10,24,28,30) else 0
            layer('Loopback',{'Family':family},0,4);pos=4
        elif linktype in (12,101,228,229):
            need(0,1); kind=0x0800 if raw[0]>>4==4 else 0x86dd if raw[0]>>4==6 else 0
            layer('Raw IP',{},0,0)
        elif linktype in (113,276):
            n=16 if linktype==113 else 20; need(0,n)
            kind=int.from_bytes(raw[14:16] if n==16 else raw[:2],'big');pos=n;layer('Linux cooked',{'Version':1 if n==16 else 2},0,n)
        else:
            p['warnings'].append(f'Unsupported link type {linktype}');return p
        if kind==0x0806:
            need(pos,8);ht,pt,hl,pl,op=struct.unpack('!HHBBH',raw[pos:pos+8]);need(pos+8,2*(hl+pl))
            fields={'Hardware':ht,'Protocol':hex(pt),'Operation':op}
            if hl==6 and pl==4:
                p['src']=str(ipaddress.ip_address(raw[pos+14:pos+18]));p['dst']=str(ipaddress.ip_address(raw[pos+24:pos+28]));fields.update(Sender=p['src'],Target=p['dst'])
            layer('ARP',fields,pos,8+2*(hl+pl));p['info']=f'ARP {op}: {p["src"]} → {p["dst"]}';return p
        end=len(raw);proto=0
        if kind==0x0800:
            need(pos,20);vihl=raw[pos];ihl=(vihl&15)*4;total=int.from_bytes(raw[pos+2:pos+4],'big')
            if vihl>>4!=4 or ihl<20 or total<ihl: raise DecodeError('Invalid IPv4 header/total length')
            need(pos,ihl);end=min(len(raw),pos+total)
            if pos+total>len(raw):p['warnings'].append('IPv4 payload truncated')
            proto=raw[pos+9];frag=int.from_bytes(raw[pos+6:pos+8],'big')
            p['src']=socket.inet_ntop(socket.AF_INET,raw[pos+12:pos+16]);p['dst']=socket.inet_ntop(socket.AF_INET,raw[pos+16:pos+20])
            layer('IPv4',{'Source':p['src'],'Destination':p['dst'],'Header length':ihl,'Total length':total,'TTL':raw[pos+8],'Protocol':proto,'Fragment offset':(frag&8191)*8,'More fragments':bool(frag&8192)},pos,ihl);pos+=ihl
            if frag&0x3fff:
                p['info']='IPv4 fragment (IP reassembly not supported)';p['warnings'].append('IP fragment: transport/application decoding skipped');return p
        elif kind==0x86dd:
            need(pos,40)
            if raw[pos]>>4!=6: raise DecodeError('Invalid IPv6 version')
            plen=int.from_bytes(raw[pos+4:pos+6],'big');end=min(len(raw),pos+40+plen);proto=raw[pos+6]
            if pos+40+plen>len(raw):p['warnings'].append('IPv6 payload truncated')
            p['src']=socket.inet_ntop(socket.AF_INET6,raw[pos+8:pos+24]);p['dst']=socket.inet_ntop(socket.AF_INET6,raw[pos+24:pos+40])
            layer('IPv6',{'Source':p['src'],'Destination':p['dst'],'Payload length':plen,'Next header':proto,'Hop limit':raw[pos+7]},pos,40);pos+=40
            for _ in range(16):
                if proto not in (0,43,44,51,60):break
                need(pos,2,end);n=8 if proto==44 else (raw[pos+1]+2)*4 if proto==51 else (raw[pos+1]+1)*8
                need(pos,n,end);old=proto;proto=raw[pos];layer('IPv6 extension',{'Type':old,'Next header':proto},pos,n)
                if old==44 and int.from_bytes(raw[pos+2:pos+4],'big')&0xfff9:
                    p['info']='IPv6 fragment (IP reassembly not supported)';p['warnings'].append('IP fragment: transport/application decoding skipped');return p
                pos+=n
            else:raise DecodeError('IPv6 extension chain limit')
        else:
            p['info']=f'EtherType {kind:#06x}';return p
        if proto==6:
            need(pos,20,end);sp,dp,seq,ack=struct.unpack('!HHII',raw[pos:pos+12]);n=(raw[pos+12]>>4)*4
            if n<20:raise DecodeError('Invalid TCP data offset')
            need(pos,n,end);flags=raw[pos+13];names=[name for bit,name in ((1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),(16,'ACK'),(32,'URG'),(64,'ECE'),(128,'CWR')) if flags&bit]
            p.update(sport=sp,dport=dp,transport='TCP',tcp_seq=seq,tcp_ack=ack,tcp_flags=flags)
            layer('TCP',{'Source port':sp,'Destination port':dp,'Sequence':seq,'Acknowledgment':ack,'Flags':' '.join(names),'Window':int.from_bytes(raw[pos+14:pos+16],'big'),'Header length':n},pos,n)
            p['info']=f'{sp} → {dp} [{", ".join(names)}] Seq={seq} Ack={ack} Len={end-pos-n}';pos+=n
        elif proto==17:
            need(pos,8,end);sp,dp,n,checksum=struct.unpack('!4H',raw[pos:pos+8])
            if n<8:raise DecodeError('Invalid UDP length')
            if pos+n>end:p['warnings'].append('UDP payload truncated')
            end=min(end,pos+n);p.update(sport=sp,dport=dp,transport='UDP');layer('UDP',{'Source port':sp,'Destination port':dp,'Length':n,'Checksum':hex(checksum)},pos,8);pos+=8;p['info']=f'{sp} → {dp} Len={end-pos}'
        elif proto in (1,58):
            need(pos,4,end);name='ICMP' if proto==1 else 'ICMPv6';p['transport']=name
            layer(name,{'Type':raw[pos],'Code':raw[pos+1],'Checksum':hex(int.from_bytes(raw[pos+2:pos+4],'big'))},pos,4)
            types={1:{0:'Echo reply',3:'Destination unreachable',8:'Echo request',11:'Time exceeded'},58:{1:'Destination unreachable',128:'Echo request',129:'Echo reply',135:'Neighbor solicitation',136:'Neighbor advertisement'}}
            p['info']=types[proto].get(raw[pos],f'Type {raw[pos]}')+f' Code={raw[pos+1]}';pos+=4
        else:p['info']=f'IP protocol {proto}';return p
        p['payload']=raw[pos:end];p['payload_offset']=pos
        if p['transport'] in ('TCP','UDP'):
            app,info,fields=application(p['payload'],p['transport'],p['sport'],p['dport'])
            if app:layer(app,fields,pos,len(p['payload']));p['info']=info
    except (DecodeError,struct.error,ValueError,IndexError) as exc:
        p['warnings'].append(str(exc));p['info']=p['info'] or 'Malformed / truncated packet'
    return p

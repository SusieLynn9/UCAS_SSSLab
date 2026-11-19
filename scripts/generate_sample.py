#!/usr/bin/env python3
"""Generate deterministic, synthetic packets; no traffic or personal data collected."""
import ipaddress
from pathlib import Path
import socket
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sniffer.pcap import write_pcap

def frame(body,kind=0x0800):return bytes.fromhex('020000000002020000000001')+struct.pack('!H',kind)+body
def ip(body,proto=6,reverse=False):
    a,b=('192.0.2.10','198.51.100.20')
    if reverse:a,b=b,a
    return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),7,0,64,proto,0,socket.inet_aton(a),socket.inet_aton(b))+body
def tcp(data=b'',seq=100,ack=0,flags=0x18,reverse=False,port=8080,sport=51432):
    a,b=(sport,port) if not reverse else (port,sport)
    return frame(ip(struct.pack('!HHIIBBHHH',a,b,seq,ack,0x50,flags,32768,0,0)+data,reverse=reverse))
def udp(data,sport=53000,dport=53):return struct.pack('!HHHH',sport,dport,len(data)+8,0)+data

def build():
    rows=[];t=1795089600.0
    def add(raw,delta=.008):
        nonlocal t
        t+=delta;rows.append((t,raw,len(raw)))
    # Ethernet ARP request; IPv4 echo; IPv6 DNS + echo.
    add(frame(struct.pack('!HHBBH',1,0x0800,6,4,1)+bytes.fromhex('020000000001')+socket.inet_aton('192.0.2.10')+bytes(6)+socket.inet_aton('192.0.2.1'),0x0806))
    query=bytes.fromhex('713901000001000000000000')+b'\x04ucas\x03edu\x02cn\x00\x00\x01\x00\x01'
    add(frame(ip(udp(query),17)))
    v6body=udp(query,53001,53)
    v6=struct.pack('!IHBB16s16s',6<<28,len(v6body),17,64,ipaddress.IPv6Address('2001:db8::10').packed,ipaddress.IPv6Address('2001:db8::53').packed)+v6body
    add(frame(v6,0x86dd));add(frame(ip(b'\x08\x00\x00\x00\x00\x01\x00\x01prism',1)))
    echo=b'\x80\x00\x00\x00\x00\x01\x00\x01'
    add(frame(struct.pack('!IHBB16s16s',6<<28,len(echo),58,64,ipaddress.IPv6Address('2001:db8::10').packed,ipaddress.IPv6Address('2001:db8::1').packed)+echo,0x86dd))
    add(tcp(seq=1000,flags=2));add(tcp(seq=7000,ack=1001,flags=0x12,reverse=True));add(tcp(seq=1001,ack=7001,flags=16))
    req=b'GET /lab/1a HTTP/1.1\r\nHost: prism.test\r\nUser-Agent: UCAS-Lab/1.0\r\n\r\n'
    add(tcp(req,1001,7001));add(tcp(seq=7001,ack=1001+len(req),flags=16,reverse=True))
    body=b'Prism: see the packets, understand the connection.\n'
    response=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    split=72
    add(tcp(response[split:],7001+split,1001+len(req),reverse=True));add(tcp(response[:split],7001,1001+len(req),reverse=True));add(tcp(response[:split],7001,1001+len(req),reverse=True))
    add(tcp(seq=1001+len(req),ack=7001+len(response),flags=16));add(tcp(seq=7001+len(response),ack=1001+len(req),flags=17,reverse=True));add(tcp(seq=1001+len(req),ack=7002+len(response),flags=17))
    # A second HTTP connection intentionally contains a capture gap.
    add(tcp(seq=2000,flags=2,sport=51433));add(tcp(b'GET /missing HTTP/1.1\r\n',2001,sport=51433));add(tcp(b'Host: capture-gap.test\r\n\r\n',2060,sport=51433))
    # A complete TLS ClientHello with SNI, emitted on 8443.
    name=b'www.ucas.ac.cn';sni=struct.pack('!H',len(name)+3)+b'\x00'+struct.pack('!H',len(name))+name;ext=struct.pack('!HH',0,len(sni))+sni
    hello=b'\x03\x03'+bytes(32)+b'\x00\x00\x02\x13\x01\x01\x00'+struct.pack('!H',len(ext))+ext
    handshake=b'\x01'+len(hello).to_bytes(3,'big')+hello
    add(tcp(seq=3000,flags=2,port=8443,sport=51434));add(tcp(b'\x16\x03\x01'+struct.pack('!H',len(handshake))+handshake,3001,port=8443,sport=51434))
    return rows

def main():
    path=Path(__file__).resolve().parents[1]/'samples'/'lab-demo.pcap';path.parent.mkdir(exist_ok=True)
    rows=build();write_pcap(path,1,rows);print(f'Generated {len(rows)} synthetic packets: {path}')
if __name__=='__main__':main()

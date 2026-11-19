#!/usr/bin/env python3
"""Start Prism with Python 3.9+, no pip dependencies required."""
import argparse
import sys
import webbrowser
from sniffer.capture import Session
from sniffer.server import make_server

def main():
    p=argparse.ArgumentParser(description='Prism | UCAS Lab 1A packet sniffer')
    p.add_argument('--port',type=int,default=8765);p.add_argument('--no-browser',action='store_true');p.add_argument('--read',metavar='PCAP');p.add_argument('--max-packets',type=int,default=5000)
    args=p.parse_args()
    if not 100<=args.max_packets<=50000:p.error('--max-packets must be 100..50000')
    session=Session(max_packets=args.max_packets)
    if args.read:session.import_file(args.read)
    try:server=make_server(session,args.port)
    except OSError as e:p.exit(1,str(e)+'\nTry --port 8767\n')
    url=f'http://127.0.0.1:{server.server_port}/#token={server.token}'
    print('Prism · 本地网络嗅探器\n'+url,flush=True)
    print('实时抓包如提示 BPF 权限不足，请在本终端运行 sudo -v 后重试。Ctrl+C 退出。',flush=True)
    if not args.no_browser:webbrowser.open(url)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:session.stop();server.server_close()
if __name__=='__main__':main()

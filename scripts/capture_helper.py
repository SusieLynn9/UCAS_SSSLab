#!/usr/bin/env python3
"""Privileged capture-only helper. No HTTP, no shell, no filesystem writes.

Invoked with sudo -n by the ordinary-user UI after the user runs sudo -v.
EOF on stdin stops capture. Stdout is a newline-delimited packet channel.
"""
import argparse
import base64
import json
from pathlib import Path
import signal
import sys
import threading
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sniffer.pcap import Pcap

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--interface',required=True);parser.add_argument('--bpf',default='');parser.add_argument('--promiscuous',action='store_true');args=parser.parse_args()
    stop=threading.Event()
    def input_stop():
        sys.stdin.buffer.read(1);stop.set()
    threading.Thread(target=input_stop,daemon=True).start()
    signal.signal(signal.SIGTERM,lambda *a:stop.set())
    def emit(obj):print(json.dumps(obj,separators=(',',':')),flush=True)
    try:
        with Pcap.live(args.interface,args.bpf,args.promiscuous) as cap:
            emit({'linktype':cap.linktype});tick=time.monotonic()
            while not stop.is_set():
                row=cap.next()
                if row:
                    t,raw,n=row;emit({'t':t,'data':base64.b64encode(raw).decode('ascii'),'wirelen':n})
                else:stop.wait(.01)
                if time.monotonic()-tick>=1:emit({'stats':cap.stats()});tick=time.monotonic()
    except BrokenPipeError:pass
    except Exception as e:emit({'error':str(e)});return 1
    return 0
if __name__=='__main__':raise SystemExit(main())

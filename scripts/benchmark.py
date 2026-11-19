#!/usr/bin/env python3
"""Reproducible CPU/offline microbenchmark, NOT a live line-rate claim."""
import argparse
import json
from pathlib import Path
import platform
import statistics
import sys
import time
import tracemalloc
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sniffer.capture import Session
from sniffer.pcap import Pcap
from sniffer.protocols import decode_packet

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--packets',type=int,default=10000);parser.add_argument('--output');args=parser.parse_args()
    if not 100<=args.packets<=1000000:parser.error('--packets must be 100..1000000')
    root=Path(__file__).resolve().parents[1]
    with Pcap.offline(root/'samples'/'lab-demo.pcap') as cap:rows=list(cap);lt=cap.linktype
    timings=[]
    for _ in range(3):
        start=time.perf_counter()
        for i in range(args.packets):
            t,raw,n=rows[i%len(rows)];decode_packet(raw,lt,t,n)
        timings.append(time.perf_counter()-start)
    tracemalloc.start();session=Session();start=time.perf_counter()
    for i in range(args.packets):
        t,raw,n=rows[i%len(rows)];session.ingest(t,raw,n,lt)
    elapsed=time.perf_counter()-start;current,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    result={'platform':platform.platform(),'python':platform.python_version(),'packets':args.packets,'decode_runs_seconds':timings,'decode_packets_per_second':round(args.packets/statistics.median(timings)),
            'session_seconds_with_tracemalloc':elapsed,'session_packets_per_second_with_tracemalloc':round(args.packets/elapsed),'retained':len(session.packets),'evicted':session.evicted,'traced_peak_bytes':peak,
            'scope':'Synthetic offline CPU benchmark; excludes live libpcap/helper IPC, GUI, NIC throughput and OS drop rate'}
    text=json.dumps(result,ensure_ascii=False,indent=2);print(text)
    if args.output:Path(args.output).write_text(text+'\n')
if __name__=='__main__':main()

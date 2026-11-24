#!/usr/bin/env python3
"""Measure server-enforced user payload budgets over actual local mTLS."""
import argparse,json,os,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.init_demo import initialize
from harbor.server import Server
from harbor.client import Client

def main():
    p=argparse.ArgumentParser();p.add_argument('--size-mib',type=int,default=2,choices=range(1,17));p.add_argument('--output',type=Path,default=ROOT/'output/benchmark.json');a=p.parse_args();results=[]
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);paths=initialize(root/'runtime');cfg=Path(paths['server_config']);settings=json.loads(cfg.read_text());settings['port']=0;cfg.write_text(json.dumps(settings));server=Server(cfg);server.start()
        source=root/'benchmark.bin';source.write_bytes(os.urandom(a.size_mib*1024*1024))
        try:
            for name in ('alice','bob'):
                path=Path(paths[name+'_config']);config=json.loads(path.read_text());config['port']=server.port;path.write_text(json.dumps(config));client=Client(path)
                try:
                    info=client.connect();start=time.monotonic();result=client.upload(source);elapsed=time.monotonic()-start
                    results.append({'user':name,'tier':info['tier'],'configured_payload_bytes_per_second':info['rate_bps'],'bytes':source.stat().st_size,'seconds':elapsed,'observed_bytes_per_second':source.stat().st_size/elapsed,'sha256':result['sha256'],'status':result['status']})
                finally:client.close()
        finally:server.stop()
    evidence={'scope':'Loopback mTLS upload measurement, each user gets a separate shared bucket; burst=max(64KiB,rate/4), metadata/TLS overhead excluded; not an Internet/NIC throughput or DDoS claim','results':results,'timestamp':time.strftime('%Y-%m-%d %H:%M:%S %z')}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n');print(json.dumps(evidence,ensure_ascii=False,indent=2))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Run the Harbor mutually authenticated TLS file service."""
import argparse,json,signal,threading
from pathlib import Path
from harbor.server import Server

def main():
    parser=argparse.ArgumentParser(description='Harbor 安全文件传输服务端')
    parser.add_argument('--config',type=Path,default=Path(__file__).resolve().parent/'runtime/server.json')
    parser.add_argument('--host');parser.add_argument('--port',type=int);args=parser.parse_args()
    if not args.config.is_file():parser.exit(1,'请先运行 ./setup_demo.command 生成本机证书与配置。\n')
    try:server=Server(args.config,args.host,args.port);server.start()
    except (OSError,ValueError,KeyError) as e:parser.exit(1,'服务端启动失败：'+str(e)+'\n')
    stopped=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *a:stopped.set())
    print(f'Harbor TLS server listening at {server.host}:{server.port}',flush=True)
    print('mTLS required · persistent connections · per-user storage and payload budgets',flush=True)
    try:stopped.wait()
    finally:
        server.stop();print(json.dumps(server.metrics(),ensure_ascii=False),flush=True)
if __name__=='__main__':main()

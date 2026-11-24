#!/usr/bin/env python3
"""Scriptable client for repeatable verification and deployment checks."""
import argparse,json
from pathlib import Path
from harbor.client import Client,ClientError

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,default=Path('runtime/alice.json'));sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('list');ping=sub.add_parser('ping');ping.add_argument('--count',type=int,default=3)
    up=sub.add_parser('upload');up.add_argument('paths',nargs='+',type=Path)
    down=sub.add_parser('download');down.add_argument('name');down.add_argument('destination',type=Path)
    a=p.parse_args();c=None
    try:
        c=Client(a.config);print(json.dumps(c.connect(),ensure_ascii=False))
        if a.command=='list':print(json.dumps(c.list_files(),ensure_ascii=False,indent=2))
        elif a.command=='ping':
            if not 1<=a.count<=100:p.error('--count must be 1..100')
            for _ in range(a.count):print(json.dumps(c.ping(),ensure_ascii=False))
        elif a.command=='upload':
            for path in a.paths:print(json.dumps(c.upload(path),ensure_ascii=False))
        else:print(json.dumps(c.download(a.name,a.destination),ensure_ascii=False))
    except (ClientError,OSError,ValueError) as e:p.exit(1,str(e)+'\n')
    finally:
        if c:c.close()
if __name__=='__main__':main()

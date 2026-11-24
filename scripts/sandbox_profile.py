#!/usr/bin/env python3
"""Generate a macOS service sandbox profile; no system settings are changed."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from harbor.config import load

def profile(config_path):
    config_path=Path(config_path).resolve();config=load(config_path)
    quote=lambda p:json.dumps(str(Path(p).resolve()),ensure_ascii=False)
    read_dirs=['/System','/usr','/Library/Developer/CommandLineTools','/Library/Apple','/private/etc',ROOT/'harbor',config['root']]
    read_files=[ROOT/'run_server.py',config_path,config['certfile'],config['keyfile'],config['cafile'],'/dev/null','/dev/urandom','/dev/random']
    rules=['(version 1)','(deny default)','(import "system.sb")','(allow process-exec process-fork signal sysctl-read mach-lookup)','(allow network-inbound network-outbound)','(allow file-read-metadata)','(allow file-read-data (literal '+quote(ROOT)+'))']
    rules.append('(allow file-read-data file-map-executable '+ ' '.join('(subpath '+quote(p)+')' for p in read_dirs)+' '+ ' '.join('(literal '+quote(p)+')' for p in read_files)+')')
    rules.append('(allow file-write* (subpath '+quote(config['root'])+') (literal "/dev/null") (regex #"^/dev/tty"))')
    return '\n'.join(rules)+'\n'

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,default=ROOT/'runtime/server.json');p.add_argument('--output',type=Path,default=ROOT/'output/server.sb');a=p.parse_args()
    text=profile(a.config);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text);a.output.chmod(0o600);print(a.output)
if __name__=='__main__':main()

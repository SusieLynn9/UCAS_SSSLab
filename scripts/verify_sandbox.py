#!/usr/bin/env python3
"""Check isolation using only newly generated probe files, never private user data."""
import argparse,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.sandbox_profile import profile
from harbor.config import load

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,default=ROOT/'runtime/server.json');p.add_argument('--output',type=Path,default=ROOT/'output/sandbox-verification.json');a=p.parse_args();cfg=load(a.config)
    if not Path('/usr/bin/sandbox-exec').exists():p.exit(1,'sandbox-exec unavailable; isolation not verified\n')
    inside=Path(cfg['root'])/'sandbox-probe.txt'
    with tempfile.TemporaryDirectory(prefix='harbor-isolation-') as temporary:
        folder=Path(temporary);outside=folder/'outside.txt';outside.write_text('generated outside test marker')
        sb=folder/'server.sb';sb.write_text(profile(a.config))
        code='''import json,sys
from pathlib import Path
inside,outside=map(Path,sys.argv[1:])
inside.write_text("inside allowed")
result={"inside_write":inside.read_text()=="inside allowed"}
for operation in ("read","write"):
    try:
        outside.read_text() if operation=="read" else outside.write_text("blocked")
        result["outside_"+operation+"_denied"]=False
    except PermissionError:result["outside_"+operation+"_denied"]=True
print(json.dumps(result))
'''
        result=subprocess.run(['/usr/bin/sandbox-exec','-f',str(sb),sys.executable,'-B','-c',code,str(inside),str(outside)],capture_output=True,text=True,timeout=10)
        if result.returncode:p.exit(1,'Sandbox check did not run successfully (exit '+str(result.returncode)+'): '+result.stderr+'\n')
        data=json.loads(result.stdout);data['passed']=all(data.values());a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(data,indent=2)+'\n');print(json.dumps(data,indent=2))
        if not data['passed']:p.exit(1,'Isolation boundary check failed\n')
    inside.unlink(missing_ok=True)
if __name__=='__main__':main()

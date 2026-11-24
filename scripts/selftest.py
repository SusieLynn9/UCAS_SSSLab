#!/usr/bin/env python3
"""Run real TLS and storage checks; save only aggregate verification evidence."""
import argparse,io,json,platform,ssl,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'output/verification.json');a=p.parse_args()
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),top_level_dir=str(ROOT));stream=io.StringIO();start=time.monotonic()
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite);print(stream.getvalue())
    evidence={'passed':result.wasSuccessful(),'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'seconds':time.monotonic()-start,'python':platform.python_version(),'platform':platform.platform(),'ssl':ssl.OPENSSL_VERSION,'timestamp':time.strftime('%Y-%m-%d %H:%M:%S %z'),'scope':'Real loopback mTLS, file transfer/resume/concurrency, permissions, frame validation, private certificate generation and headless GUI worker coordination; no GUI visual acceptance claim'}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n');print(json.dumps(evidence,ensure_ascii=False,indent=2));return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())

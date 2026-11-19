"""Best-effort local TCP attribution. Socket snapshots are not packet provenance."""
import ipaddress
import shutil
import subprocess
import sys
import time


def endpoint(value):
    if ':' not in value:return None
    host,port=value.rsplit(':',1);host=host.strip('[]').split('%')[0]
    try:return (host,int(port))
    except ValueError:return None


def parse_lsof(text):
    rows=[];pid=None;name='';proto=''
    for line in text.splitlines():
        if not line:continue
        tag,value=line[0],line[1:]
        if tag=='p':
            try:pid=int(value)
            except ValueError:pid=None
            name='';proto=''
        elif tag=='c':name=value
        elif tag=='f':proto=''
        elif tag=='P':proto=value
        elif tag=='n' and pid is not None and proto=='TCP':
            ends=value.split('->',1);local=endpoint(ends[0]);remote=endpoint(ends[1]) if len(ends)>1 else None
            if local:rows.append({'pid':pid,'process':name,'local':local,'remote':remote})
    return rows


def associate(p,rows):
    if p.get('transport')!='TCP':return None
    a=(p['src'].split('%')[0],p['sport']);b=(p['dst'].split('%')[0],p['dport'])
    for r in rows:
        if (r['local'],r['remote']) in ((a,b),(b,a)):
            return {'pid':r['pid'],'process':r['process'],'confidence':'exact'}
    for r in rows:
        if r['remote'] is None and any(r['local'][1]==x[1] and r['local'][0] in ('*','0.0.0.0','::',x[0]) for x in (a,b)):
            return {'pid':r['pid'],'process':r['process'],'confidence':'listener'}
    return None


def snapshot():
    exe=shutil.which('lsof') or ('/usr/sbin/lsof' if sys.platform=='darwin' else None)
    if not exe:return {'rows':[],'timestamp':time.time(),'note':'lsof unavailable; process attribution unsupported on this platform'}
    try:
        result=subprocess.run([exe,'-nP','-iTCP','-FpcfPn'],capture_output=True,text=True,timeout=4)
        return {'rows':parse_lsof(result.stdout),'timestamp':time.time(),'note':'Current-user socket snapshot; exact tuple > listener; races and permission limits apply'}
    except (OSError,subprocess.TimeoutExpired) as e:return {'rows':[],'timestamp':time.time(),'note':str(e)}

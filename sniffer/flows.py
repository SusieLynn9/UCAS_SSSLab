"""Bidirectional TCP flow index with on-demand sequence-aware reassembly."""
from collections import OrderedDict
from .protocols import application, DecodeError


def _endpoint(p,side):return (p[side],p['sport' if side=='src' else 'dport'])
def _delta(seq,base):return ((seq-base+0x80000000)&0xffffffff)-0x80000000


def reassemble(packets,limit=1024*1024):
    segments=[];syns=[p for p in packets if p.get('tcp_flags',0)&2]
    base=((syns[0]['tcp_seq']+1)&0xffffffff) if syns else next((p['tcp_seq'] for p in packets if p['payload']),0)
    for p in packets:
        data=p['payload']
        if data:
            seq=(p['tcp_seq']+bool(p.get('tcp_flags',0)&2))&0xffffffff
            segments.append((_delta(seq,base),p['id'],data))
    # First-observed bytes win. Sparse intervals avoid allocating sequence-sized gaps.
    pieces=[];retrans=conflicts=stored=0;truncated=False
    for start,ident,data in sorted(segments,key=lambda x:x[1]):
        stop=start+len(data);pending=[(start,data)]
        for old,olddata in pieces:
            oldstop=old+len(olddata);new=[]
            for a,b in pending:
                z=a+len(b);lo=max(a,old);hi=min(z,oldstop)
                if lo>=hi:new.append((a,b));continue
                retrans+=hi-lo;conflicts+=sum(x!=y for x,y in zip(b[lo-a:hi-a],olddata[lo-old:hi-old]))
                if a<lo:new.append((a,b[:lo-a]))
                if hi<z:new.append((hi,b[hi-a:]))
            pending=new
            if not pending:break
        for a,b in pending:
            room=limit-stored
            if len(b)>room:b=b[:room];truncated=True
            if b:pieces.append((a,b));stored+=len(b)
    merged=[]
    for a,b in sorted(pieces):
        if merged and merged[-1][0]+len(merged[-1][1])==a:merged[-1]=(merged[-1][0],merged[-1][1]+b)
        else:merged.append((a,b))
    gaps=[]
    if syns and merged and merged[0][0]>0:gaps.append({'start':0,'end':merged[0][0],'bytes':merged[0][0]})
    for (a,b),(c,d) in zip(merged,merged[1:]):gaps.append({'start':a+len(b),'end':c,'bytes':c-a-len(b)})
    chunks=[{'offset':a,'length':len(b),'text':b.decode('utf-8','replace'),'hex':b.hex()} for a,b in merged]
    return {'chunks':chunks,'gaps':gaps,'text':'\n[CAPTURE GAP]\n'.join(c['text'] for c in chunks),
            'retransmitted_bytes':retrans,'conflicting_bytes':conflicts,'truncated':truncated,'bytes':stored,
            'prefix_known':bool(syns),'base_sequence':base},merged


class FlowTracker:
    def __init__(self):
        self.flows=OrderedDict();self.active={};self.packet_flows={};self.next_id=1
    def add(self,p):
        if p.get('transport')!='TCP':return None
        a,b=_endpoint(p,'src'),_endpoint(p,'dst');key=tuple(sorted((a,b)));fid=self.active.get(key)
        syn=bool(p['tcp_flags']&2 and not p['tcp_flags']&16)
        if fid and syn:
            f=self.flows[fid]
            if f.get('syn')!=(a,p['tcp_seq']):fid=None
        if fid is None:
            fid=self.next_id;self.next_id+=1;self.active[key]=fid
            self.flows[fid]={'id':fid,'a':a,'b':b,'items':OrderedDict(),'key':key,'syn':(a,p['tcp_seq']) if syn else None}
        f=self.flows[fid];f['items'][p['id']]=p;self.packet_flows[p['id']]=fid;p['flow_id']=fid
        return fid
    def remove(self,packet_id):
        fid=self.packet_flows.pop(packet_id,None)
        if fid is None:return
        f=self.flows[fid];f['items'].pop(packet_id,None)
        if not f['items']:
            del self.flows[fid]
            if self.active.get(f['key'])==fid:del self.active[f['key']]
    def _summary(self,f):
        ps=list(f['items'].values());processes={(p.get('pid'),p.get('process'),p.get('confidence')) for p in ps if p.get('pid')}
        return {'id':f['id'],'a':list(f['a']),'b':list(f['b']),'packets':len(ps),'bytes':sum(p['length'] for p in ps),
                'start':ps[0]['timestamp'],'end':ps[-1]['timestamp'],'application':next((p['protocol'] for p in ps if p['protocol'] in ('HTTP','DNS','TLS')),'TCP'),
                'processes':[{'pid':pid,'process':name,'confidence':confidence} for pid,name,confidence in sorted(processes)],
                'state':'Reset' if any(p['tcp_flags']&4 for p in ps) else 'FIN observed' if any(p['tcp_flags']&1 for p in ps) else 'SYN observed' if any(p['tcp_flags']&2 for p in ps) else 'Midstream'}
    def summaries(self):return [self._summary(f) for f in self.flows.values()]
    def detail(self,fid):
        f=self.flows[int(fid)];result=self._summary(f);directions=[]
        for source,target in ((f['a'],f['b']),(f['b'],f['a'])):
            ps=[p for p in f['items'].values() if _endpoint(p,'src')==source]
            d,merged=reassemble(ps);d.update(source=list(source),target=list(target));directions.append(d)
            for _,data in merged:
                try:app,info,fields=application(data,'TCP',source[1],target[1])
                except DecodeError:continue
                if app:result['application']=app;d['application']={'protocol':app,'info':info,'fields':fields};break
        result['directions']=directions
        result['timeline']=[{'id':p['id'],'timestamp':p['timestamp'],'direction':0 if _endpoint(p,'src')==f['a'] else 1,
                             'seq':p['tcp_seq'],'ack':p['tcp_ack'],'flags':p['tcp_flags'],'bytes':len(p['payload']),'info':p['info']} for p in f['items'].values()][:2000]
        result['timeline_truncated']=len(f['items'])>2000
        return result

'use strict';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const params=new URLSearchParams(location.hash.slice(1));
const token=params.get('token')||sessionStorage.getItem('prism-token')||'';
if(token)sessionStorage.setItem('prism-token',token);
if(location.hash)history.replaceState(null,'',location.pathname);
let state=null, selected=null, paused=false, filter='', busy=false, currentView='packets', generation=null, lastSignature='', flowId=null;
const el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
const format=n=>Number(n).toLocaleString('en-US');
const bytes=n=>n>=1048576?(n/1048576).toFixed(2)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':n+' B';
const endpoint=a=>a[0].includes(':')?'['+a[0]+']:'+a[1]:a.join(':');
function notice(message){$('#notice').textContent=message;$('#notice').hidden=!message;}
let toastTimer;
function toast(message){$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,4000);}
async function api(path,body,raw=false){
 const options={headers:{'X-Prism-Token':token}};
 if(body!==undefined){options.method='POST';if(body instanceof ArrayBuffer){options.body=body;options.headers['Content-Type']='application/octet-stream';}else{options.body=JSON.stringify(body);options.headers['Content-Type']='application/json';}}
 const r=await fetch('/api/'+path,options);
 if(!r.ok){let message;try{message=(await r.json()).error;}catch{message='请求失败 '+r.status;}throw new Error(message);}
 return raw?r.blob():r.json();
}
async function action(fn){try{await fn();notice('');await refresh(true);}catch(e){notice(e.message);}}
function badge(p){return el('span','badge '+p.toLowerCase(),p);}
function switchView(name){currentView=name;$$('.view').forEach(n=>n.hidden=n.id!=='view-'+name);$$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===name));if(state)renderViews();}
$$('.nav').forEach(n=>n.onclick=()=>switchView(n.dataset.view));
function renderMetrics(){
 $('#total').textContent=format(state.total);$('#retained').textContent='保留 '+format(state.retained)+' · 淘汰 '+format(state.evicted);$('#bytes').textContent=bytes(state.wire_bytes);$('#flow-count').textContent=format(state.flows.length);
 const processes=new Set(state.flows.flatMap(f=>f.processes.map(p=>p.pid)));$('#process-count').textContent=processes.size?processes.size+' 个关联进程':'暂无进程关联';
 const modes={idle:'就绪',capturing:'● 实时捕获',stopped:'已停止',offline:'离线分析',error:'捕获错误'};
 $('#mode').textContent=paused?'Ⅱ 显示已暂停':modes[state.status]||state.status;$('#mode').classList.toggle('live',state.status==='capturing');
 $('#start').disabled=state.status==='capturing';$('#stop').disabled=state.status!=='capturing';
 $('#source').textContent=state.source?(state.status==='offline'?'离线 PCAP · ':'接口 · ')+state.source:'尚未开始捕获';
 $('#capacity').textContent='最多 '+format(state.max_packets)+' 包 / '+bytes(state.max_bytes)+' 原始报文 · 当前 '+bytes(state.raw_bytes);
 const s=state.stats;$('#health').textContent=s?format(s.dropped+s.interface_dropped)+' 丢包':state.status==='offline'?'离线':'—';
 $('#drops').textContent=s?'libpcap recv '+format(s.received)+' · drop '+format(s.dropped)+' · ifdrop '+format(s.interface_dropped):'捕获丢包统计暂不可用';
 const bars=$('#mini-bars');bars.replaceChildren();Object.entries(state.protocols).sort((a,b)=>b[1]-a[1]).slice(0,3).forEach(([name,n])=>{const group=el('div');const label=el('div','mini-label');label.append(el('span','',name),el('span','',Math.round(n/Math.max(1,state.total)*100)+'%'));const track=el('div','mini-bar');const fill=el('i');fill.style.width=(n/Math.max(1,state.total)*100)+'%';track.append(fill);group.append(label,track);bars.append(group);});
}
function renderPackets(force=false){
 $('#match-count').textContent=format(state.matched)+' 条匹配';$('#empty').hidden=state.packets.length>0;
 const sig=state.generation+':'+filter+':'+state.packets.map(p=>p.id+':'+(p.process||'')).join(',');
 if(sig===lastSignature&&!force)return;lastSignature=sig;
 const body=$('#packets');body.replaceChildren();const origin=state.packets[0]?.timestamp||0;
 state.packets.forEach(p=>{const row=el('tr');row.dataset.id=p.id;row.tabIndex=0;row.classList.toggle('selected',selected===p.id);
  const cells=[p.id,(p.timestamp-origin).toFixed(6),p.src+(p.sport!==null?':'+p.sport:''),p.dst+(p.dport!==null?':'+p.dport:''),null,p.length,p.info];
  cells.forEach((text,i)=>{const td=el('td');if(i===4)td.append(badge(p.protocol));else td.textContent=text;td.title=i===6?(p.warnings.length?p.warnings.join('; ')+' · ':'')+p.info:String(text||'');row.append(td);});
  row.onclick=()=>selectPacket(p.id);row.onkeydown=e=>{if(e.key==='Enter')selectPacket(p.id);};body.append(row);
 });
 if(selected&&!state.packets.some(p=>p.id===selected)){selected=null;$('#follow').disabled=true;$('#details').textContent='所选报文已不在当前筛选窗口。';$('#hex').textContent='';}
}
async function selectPacket(id){
 try{const p=await api('packet?id='+id);selected=id;$$('#packets tr').forEach(r=>r.classList.toggle('selected',Number(r.dataset.id)===id));
 const target=$('#details');target.classList.remove('empty-detail');target.replaceChildren();
 p.warnings.forEach(w=>target.append(el('div','warning','⚠ '+w)));
 p.details.forEach((layer,i)=>{const d=el('details');d.open=i>=p.details.length-2;const summary=el('summary','',layer.name);const dl=el('dl');Object.entries(layer.fields).forEach(([k,v])=>dl.append(el('dt','',k),el('dd','',typeof v==='boolean'?String(v):v)));d.append(summary,dl);target.append(d);});
 if(p.process)target.append(el('div','hint','进程 '+p.process+' / '+p.pid+' · '+p.confidence));
 $('#byte-info').textContent=p.captured+' CAPTURED / '+p.length+' ON WIRE';
 const hex=$('#hex');hex.replaceChildren();const raw=p.hex.match(/.{2}/g)||[];
 for(let i=0;i<Math.min(raw.length,8192);i+=16){const line=el('span','hex-row');line.append(el('em','',i.toString(16).padStart(4,'0')));const b=raw.slice(i,i+16);line.append(document.createTextNode(b.join(' ').padEnd(47)+'  '));const ascii=el('b','',b.map(v=>{const n=parseInt(v,16);return n>=32&&n<127?String.fromCharCode(n):'.';}).join(''));line.append(ascii);hex.append(line);}
 if(raw.length>8192)hex.append(el('span','warning','界面仅预览前 8192 字节；导出保留完整捕获内容。'));
 $('#follow').disabled=!p.flow_id;$('#follow').onclick=()=>openFlow(p.flow_id);
 }catch(e){notice(e.message);}
}
function renderFlows(){const body=$('#flows');body.replaceChildren();state.flows.slice(-500).reverse().forEach(f=>{const row=el('tr');[f.id,endpoint(f.a),endpoint(f.b),f.application,f.packets+' / '+bytes(f.bytes),f.state,f.processes.map(p=>p.process+' ('+p.pid+', '+p.confidence+')').join(',')||'未知','追踪 ↗'].forEach(v=>row.append(el('td','',v)));row.onclick=()=>openFlow(f.id);body.append(row);});}
function renderProcesses(){
 $('#process-note').textContent=state.process_note+'。快照匹配并非逐包来源证明；未知进程不会被推断为已知。';
 const groups=new Map();state.flows.forEach(f=>f.processes.forEach(p=>{if(!groups.has(p.pid))groups.set(p.pid,{p,flows:[]});groups.get(p.pid).flows.push(f);}));
 const panel=$('#processes');panel.replaceChildren();if(!groups.size)panel.append(el('p','hint','尚无关联进程。实时捕获时点击“刷新进程快照”，并保持测试连接打开。离线样例不含进程来源。'));
 groups.forEach(({p,flows})=>{const card=el('article','process-card');card.append(el('h3','',p.process),el('small','','PID '+p.pid+' · '+flows.length+' 条 TCP 流 · '+p.confidence));flows.forEach(f=>{const b=el('button','',endpoint(f.a)+' ⇄ '+endpoint(f.b));b.onclick=()=>openFlow(f.id);card.append(b);});panel.append(card);});
}
function renderStats(){const target=$('#protocol-chart');target.replaceChildren();Object.entries(state.protocols).sort((a,b)=>b[1]-a[1]).forEach(([name,n])=>{const row=el('div','chart-row'),label=el('div','chart-label');label.append(el('span','',name),el('span','',format(n)+' · '+(n/Math.max(1,state.total)*100).toFixed(1)+'%'));const track=el('div','chart-track'),fill=el('i');fill.style.width=(n/Math.max(1,state.total)*100)+'%';track.append(fill);row.append(label,track);target.append(row);});}
function renderViews(){if(currentView==='flows')renderFlows();if(currentView==='processes')renderProcesses();if(currentView==='stats')renderStats();}
async function refresh(force=false){if(busy||paused&&!force)return;busy=true;try{const next=await api('state?filter='+encodeURIComponent(filter));state=next;if(generation!==state.generation){selected=null;lastSignature='';generation=state.generation;$('#details').textContent='选择一个报文，查看分层协议字段。';$('#hex').textContent='选择报文后显示原始字节。';$('#follow').disabled=true;}renderMetrics();renderPackets(force);renderViews();if(state.error)notice(state.error);}catch(e){notice(e.message);}finally{busy=false;}}
async function applyFilter(){const value=$('#filter').value;try{const next=await api('state?filter='+encodeURIComponent(value));filter=value;state=next;$('#filter').classList.remove('error-input');notice('');renderPackets(true);$$('[data-filter]').forEach(n=>n.classList.toggle('selected',n.dataset.filter===value));}catch(e){$('#filter').classList.add('error-input');notice(e.message);}}
$('#apply').onclick=applyFilter;$('#filter').onkeydown=e=>{if(e.key==='Enter')applyFilter();};$$('[data-filter]').forEach(b=>b.onclick=()=>{$('#filter').value=b.dataset.filter;applyFilter();});
$('#start').onclick=()=>action(async()=>{const result=await api('start',{device:$('#device').value,bpf:$('#bpf').value,promiscuous:$('#promisc').checked});$('#bpf').title='实际 BPF：'+result.effective_bpf;toast('实时捕获已开始 · 已排除界面自身连接');});
$('#stop').onclick=()=>action(()=>api('stop',{}));$('#clear').onclick=()=>action(()=>api('clear',{}));
$('#pause').onclick=()=>{paused=!paused;$('#pause').textContent=paused?'▶ 继续显示':'Ⅱ 暂停显示';if(!paused)refresh(true);else if(state)renderMetrics();};
$('#sample').onclick=()=>action(async()=>{paused=false;$('#pause').textContent='Ⅱ 暂停显示';filter='';$('#filter').value='';await api('sample',{});toast('已载入合成报文 · 当前是离线演示');});
$('#file').onchange=()=>action(async()=>{const file=$('#file').files[0];if(!file)return;if(file.size>64*1024*1024)throw new Error('导入上限为 64 MiB');await api('import',await file.arrayBuffer());$('#file').value='';toast('离线报文导入完成');});
$('#export').onclick=()=>action(async()=>{const blob=await api('export?filter='+encodeURIComponent(filter),undefined,true),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download='prism-capture.pcap';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('已导出当前筛选下的保留报文');});
$$('.refresh-processes').forEach(b=>b.onclick=()=>action(async()=>{const r=await api('processes',{});toast('已读取 '+r.sockets+' 个 socket');}));
function svgNode(tag,attrs,text){const n=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attrs||{}).forEach(([k,v])=>n.setAttribute(k,v));if(text!==undefined)n.textContent=text;return n;}
function drawTimeline(f){const target=$('#flow-timeline');target.replaceChildren();const rows=f.timeline.slice(0,160),svg=svgNode('svg',{viewBox:'0 0 940 '+(65+rows.length*31)});svg.append(svgNode('line',{x1:210,y1:42,x2:210,y2:65+rows.length*31,stroke:'#25465a'}),svgNode('line',{x1:735,y1:42,x2:735,y2:65+rows.length*31,stroke:'#25465a'}),svgNode('text',{x:210,y:26,'text-anchor':'middle',class:'endpoint'},endpoint(f.a)),svgNode('text',{x:735,y:26,'text-anchor':'middle',class:'endpoint'},endpoint(f.b)));
 const first=rows[0]?.timestamp||0;
 rows.forEach((p,i)=>{const y=58+i*31,right=p.direction===0,x1=right?210:735,x2=right?735:210,color=right?'#53dbc4':'#b8a2ef';svg.append(svgNode('text',{x:12,y:y+4},'+'+(p.timestamp-first).toFixed(6)+'s'),svgNode('line',{x1,y1:y,x2,y2:y,stroke:color,'stroke-width':1.2}),svgNode('path',{d:right?`M ${x2-7} ${y-4} L ${x2} ${y} L ${x2-7} ${y+4}`:`M ${x2+7} ${y-4} L ${x2} ${y} L ${x2+7} ${y+4}`,fill:'none',stroke:color}),svgNode('text',{x:470,y:y-5,'text-anchor':'middle'},'#'+p.id+' '+flags(p.flags)+' · Seq '+p.seq+' · '+p.bytes+' B'));});target.append(svg);if(f.timeline.length>160)target.append(el('p','hint','时序图预览前 160 个报文；完整报文可在列表/导出中查看。'));}
function flags(n){return [[1,'FIN'],[2,'SYN'],[4,'RST'],[8,'PSH'],[16,'ACK']].filter(([b])=>n&b).map(([,s])=>s).join(' ');}
async function openFlow(id){try{const f=await api('flow?id='+id);flowId=id;$('#flow-title').textContent='TCP 流 #'+id+' · '+f.application;$('#flow-meta').textContent=f.packets+' 个保留报文 · '+bytes(f.bytes)+' · '+f.state+' · 双向四元组 '+endpoint(f.a)+' ⇄ '+endpoint(f.b);const panel=$('#stream-directions');panel.replaceChildren();f.directions.forEach((d,i)=>{const section=el('section','stream-panel');section.append(el('h3','',(i===0?'A → B':'B → A')+' · '+endpoint(d.source)),el('p','',d.bytes+' B 重组 · 重传 '+d.retransmitted_bytes+' B · 冲突 '+d.conflicting_bytes+' B · 缺口 '+d.gaps.length+' · '+(d.prefix_known?'已观察 SYN':'捕获前缀未知')+(d.truncated?' · 预览超限已截断':'')));if(d.application)section.append(el('p','',d.application.protocol+' · '+d.application.info));d.gaps.forEach(g=>section.append(el('p','warning','缺失相对序号 ['+g.start+', '+g.end+')：'+g.bytes+' 字节')));section.append(el('pre','',d.text||'此方向未捕获有效载荷。'));panel.append(section);});drawTimeline(f);if(!$('#flow-dialog').open)$('#flow-dialog').showModal();}catch(e){notice(e.message);}}
$('#close-flow').onclick=()=>$('#flow-dialog').close();$('#filter-help').onclick=()=>$('#help-dialog').showModal();$('#close-help').onclick=()=>$('#help-dialog').close();
document.addEventListener('keydown',e=>{if((e.metaKey||e.ctrlKey)&&e.key==='f'){e.preventDefault();switchView('packets');$('#filter').focus();}});
async function init(){try{const r=await api('devices');const select=$('#device');select.replaceChildren();r.devices.forEach(d=>{const o=el('option','',d.name+(d.loopback?' · 回环接口':d.description?' · '+d.description:''));o.value=d.name;select.append(o);});if(r.devices.some(d=>d.name==='lo0'))select.value='lo0';await refresh(true);}catch(e){notice(e.message);}setInterval(()=>refresh(),750);}
init();

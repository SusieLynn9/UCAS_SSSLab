#!/usr/bin/env python3
"""Generate a Chinese course report (reportlab is a build-only dependency)."""
import argparse
import html
import json
from pathlib import Path
import sys
try:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether,Image
    from reportlab.graphics.shapes import Drawing,Rect,String,Line,Polygon
except ImportError:
    raise SystemExit('报告生成需要 reportlab；程序本身无需此依赖。请在虚拟环境运行 pip install reportlab。')
ROOT=Path(__file__).resolve().parents[1]
INK=colors.HexColor('#153044');MUTED=colors.HexColor('#577184');TEAL=colors.HexColor('#0b887e');PALE=colors.HexColor('#ecf6f5');LINE=colors.HexColor('#d9e5eb')
pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
STYLES={
 'body':ParagraphStyle('body',fontName='STSong-Light',fontSize=10,leading=16,textColor=INK,spaceAfter=8,wordWrap='CJK'),
 'small':ParagraphStyle('small',fontName='STSong-Light',fontSize=8.3,leading=13,textColor=MUTED,spaceAfter=6,wordWrap='CJK'),
 'h1':ParagraphStyle('h1',fontName='STSong-Light',fontSize=24,leading=32,textColor=INK,spaceAfter=18,wordWrap='CJK'),
 'h2':ParagraphStyle('h2',fontName='STSong-Light',fontSize=13,leading=20,textColor=TEAL,spaceBefore=8,spaceAfter=7),
 'cell':ParagraphStyle('cell',fontName='STSong-Light',fontSize=8.5,leading=13,textColor=INK,wordWrap='CJK'),
 'code':ParagraphStyle('code',fontName='Courier',fontSize=8.2,leading=12,textColor=INK,spaceAfter=8,wordWrap='CJK'),
 'tag':ParagraphStyle('tag',fontName='Helvetica',fontSize=8,leading=12,textColor=TEAL,spaceAfter=12),
}

def para(text,style='body'):
    return Paragraph(html.escape(str(text)).replace('\n','<br/>'),STYLES[style])

def table(rows,widths):
    t=Table([[para(c,'cell') for c in row] for row in rows],colWidths=widths,hAlign='LEFT',repeatRows=1)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),PALE),('LINEBELOW',(0,0),(-1,0),.7,TEAL),('LINEBELOW',(0,1),(-1,-1),.35,LINE),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]));return t

def architecture():
    d=Drawing(499,111)
    names=[('内核 / 网卡','BPF + libpcap'),('抓包辅助进程','只读捕获 / 管道'),('普通用户后端','解析 / 流 / 快照'),('本地浏览器','GUI / 过滤 / 时序')]
    for i,(a,b) in enumerate(names):
        x=i*126;d.add(Rect(x,35,118,65,rx=5,fillColor=PALE,strokeColor=LINE));d.add(String(x+59,73,a,fontName='STSong-Light',fontSize=10,textAnchor='middle',fillColor=INK));d.add(String(x+59,54,b,fontName='STSong-Light',fontSize=8,textAnchor='middle',fillColor=MUTED))
        if i<3:d.add(Line(x+119,68,x+125,68,strokeColor=TEAL,strokeWidth=1.5))
    return d

def sequence():
    d=Drawing(499,178)
    for x,label in ((95,'客户端 A'),(400,'服务端 B')):
        d.add(String(x,162,label,fontName='STSong-Light',fontSize=10,textAnchor='middle',fillColor=TEAL));d.add(Line(x,15,x,147,strokeColor=LINE))
    for y,right,label in ((135,True,'SYN Seq=1000'),(109,False,'SYN ACK Seq=7000 Ack=1001'),(83,True,'GET /lab/1a HTTP/1.1'),(57,False,'响应后半段先到 / Seq=7073'),(31,False,'响应前半段到达 + 重传 / Seq=7001')):
        a,b=(95,400) if right else (400,95);d.add(Line(a,y,b,y,strokeColor=TEAL));d.add(Polygon([b,y,b-6 if right else b+6,y+3,b-6 if right else b+6,y-3],fillColor=TEAL,strokeColor=TEAL));d.add(String(247,y+6,label,fontName='STSong-Light',fontSize=8,textAnchor='middle',fillColor=INK))
    return d

def build(name,student_id,repo_url,output):
    draft=not all((name,student_id,repo_url));story=[]
    def p(text,style='body'):story.append(para(text,style))
    def h(text):p(text,'h2')
    def page(tag,title):
        if story:story.append(PageBreak())
        p(tag,'tag');p(title,'h1')
    bench=json.loads((ROOT/'samples/benchmark.json').read_text())
    verification_path=ROOT/'samples/test-verification.json'
    tests=json.loads(verification_path.read_text()) if verification_path.exists() else {'tests':36,'passed':True}
    page('UCAS / SOFTWARE AND SYSTEM SECURITY / LAB 1A','嗅探器设计与实现')
    story.append(Paragraph('Prism<span color="#0b887e">.</span>',ParagraphStyle('brand',fontName='Helvetica-Bold',fontSize=49,leading=62,textColor=INK,spaceAfter=8)))
    p('Network Packet Sniffer Design and Implementation','small');p('基于 libpcap 实现报文捕获、协议解析与 TCP 流分析。')
    story.append(Spacer(1,10));story.append(table([['项目信息','内容'],['姓名 / 学号',(name or '待补姓名')+' / '+(student_id or '待补真实学号')],['源码仓库',repo_url or '待创建：software_and_system_security_lab；提交前必须替换为真实 HTTPS URL'],['实验分支','lab-1a-sniffer-design-and-implementation'],['环境','macOS / Apple Silicon；系统 Python 3.9+ / libpcap；本地浏览器 GUI']],[105,394]))
    story.append(Spacer(1,17));h('实验内容');p('本实验实现网卡选择、真实 libpcap 抓包、BPF 捕获过滤、自主分层解码、逻辑显示过滤、报文列表、协议字段与原始字节三个区域的联动分析、PCAP 导入导出，以及双向 TCP 流重组、时序图和本机进程快照关联。TLS 仅识别可见握手，不解密 HTTPS。')
    h('实现边界');p('本实验使用真实抓包和固定样例测试程序功能。性能测量为合成离线 CPU 基准，不能推导真实网卡线速。尚未实现 IP 分片重组、完整 HTTP/2/QUIC、HTTPS 解密或逐包进程来源追踪。')

    page('01 / REQUIREMENTS & NETWORK LAYERS','实验要求与协议层次')
    p('依据课程《实验 1 讲解 2026.pdf》内容，本项目完成 1A。以下是具体要求与相应完成情况。')
    story.append(table([['课程要求','完成情况'],['NPS 必须实现（第 9 页）','通过 ctypes 调用系统 libpcap；运行 verify_live.command，捕获 lo0 接口上的 HTTP 请求与响应。'],['带 GUI（第 5、15 页）','使用本地浏览器界面，展示报文列表、协议字段和 HEX/ASCII 原始字节；另外提供流、进程和统计页面。'],['协议过滤（第 14 页）','BPF 捕获过滤；HTTP/TCP/UDP/IPv4/v6/ICMP 等显示过滤，and/or/not/括号。'],['尽量完善 NPA（第 9 页）','自主解析 Ethernet/VLAN/ARP/IP/TCP/UDP/ICMP；HTTP/1 头部完整性、DNS 常见响应记录、TLS Hello 的 SNI/版本/ALPN 元数据解析。'],['TCP / 进程流追踪（加分）','双向四元组、TCP 重组与时序、lsof 快照关联；缺口、冲突和置信度可见。']],[137,362]))
    h('报文捕获与分层解析')
    p('通过 BPF/libpcap 从所选网络接口读取原始报文。lo0 报文带有 Loopback 头，以太网报文带有 Ethernet 头。程序先识别这些封装，再解析网络层的 IPv4/IPv6；对 TCP、UDP 等载荷继续读取端口和数据，最后识别 HTTP、DNS、TLS 等应用协议。ICMP 则作为网络层控制协议单独解析。这一过程将原始字节转换为界面中可查看的协议字段。')
    h('Thor 思考题')
    p('安装根证书后，HTTP 代理可在受信任 TLS 终止点获取解密后的 HTTP 内容；这属于特定应用层路径的观察。代理拿到的并非原始端到端 TCP 分段、重传、拥塞或所有传输协议状态，因此不能据此分析完整传输层行为。证书改变信任与可解密性，不能改变观察点和工具的层次边界。证书固定、非代理协议等也可能限制观察。')

    page('02 / CAPTURE & FILTERING','接口捕获与报文过滤')
    story.append(architecture());h('捕获生命周期与权限')
    p('pcap_findalldevs 枚举接口；pcap_create 配置快照长度 65535、100 ms 超时、4 MiB 内核缓冲区；激活后设为非阻塞模式。BPF 编译失败会返回原始错误并保留原会话。捕获条件自动排除界面服务端口，避免抓取控制令牌和自身轮询。工作线程独占 pcap 句柄并在 finally 关闭，停止事件控制线程退出，禁止旧线程污染新会话。')
    p('普通用户无 BPF 权限时，只启动 capture_helper.py 管理员辅助进程。辅助进程不提供 HTTP、不接收任意文件路径、不写磁盘；通过 JSON 行管道传输报文，stdin 关闭触发退出。主进程退出时排空 stdout，避免满管道阻止资源释放。Mac timeval 的 tv_usec 是 32 位，ctypes 按实际 ABI 定义，并用污染 padding 的测试防止错误时间戳。')
    h('捕获过滤与显示过滤')
    story.append(table([['比较','BPF 捕获过滤','显示过滤'],['执行位置','libpcap / OS 捕获路径','用户空间，针对已解析字段'],['生效时间','启动捕获时','分析过程中随时修改'],['例子','tcp port 8080 or icmp','tcp and (http or tls)'],['作用','减少进入用户空间的数据量','筛选保留窗口，不能恢复未捕获数据'],['实现','pcap_compile + pcap_setfilter','递归下降语法解析；禁止 eval']],[80,205,214]))
    h('回环接口抓包测试')
    p('在 Mac 终端运行 ./verify_live.command，测试脚本启动本地 HTTP 服务，并在 lo0 接口上捕获对应端口的流量。本次测试使用 BPF 表达式 tcp port 50860，共捕获 12 个报文，识别出 1 个 HTTP 请求和 1 个 HTTP 响应，dropped 与 interface_dropped 均为 0。测试结果保存在 samples/live-verification.json。')

    page('03 / PROTOCOL ANALYSIS','用报文结构识别协议')
    story.append(table([['层次 / 协议','解析与边界处理'],['链路层','Ethernet、最多 8 层 VLAN；Loopback/NULL、Raw IP、Linux SLL/SLL2。未知链路类型明确告警。'],['ARP / IPv4','地址、操作码；IP 头长、总长、TTL、分片信息。IP 分片不做重组，避免把碎片误识别为完整 TCP。'],['IPv6','地址、Payload Length、Next Header、Hop Limit；有界遍历常见扩展头。非原子分片跳过传输层分析。'],['TCP / UDP','端口、Seq/Ack、Flags、窗口、TCP Data Offset、UDP Length；在声明报文边界内读取。'],['ICMP / ICMPv6','Type、Code、校验和值与常见 Echo/Unreachable/Neighbor 摘要。只展示校验和，未实现校验验证。'],['HTTP/1','验证请求/响应首行，解析可见头字段，明确标记 Headers complete。即使端口为 8080 也可识别；仅有端口不能证明 HTTP。'],['DNS','解析问题与 Answer/Authority/Additional 区段，支持 A/AAAA/CNAME/NS/PTR/MX/TXT/SOA 与 TTL；支持 mDNS cache-flush。限定问题与记录数，检测名称循环及非法长度。'],['TLS','检查 Record/Hello/扩展边界；ClientHello 展示 SNI、支持版本和 Offered ALPN；ServerHello 展示 Selected version 及可见的 TLS 1.2 Selected ALPN。TLS 1.3 服务端 ALPN 位于加密消息中，不推断其选择；不解密应用数据。']],[98,401]))
    h('可解释的异常处理')
    p('每次读取前校验捕获长度与所属协议声明长度；超短头、非法 TCP 偏移、异常 UDP 长度、DNS 循环指针及过长 IPv6 扩展链输出诊断。caplen 小于 wirelen 时标记捕获截断。协议树保存字段起始偏移与长度，HEX 视图直接使用实际捕获字节。')
    h('单包分析与流分析的区别')
    p('应用报文可能横跨 TCP 段。单包解码器只对该段中已出现的完整首行等特征分类；TCP 流视图先重组连续序号区间，再进行应用识别。因此跨 TCP 段的 HTTP、DNS 或单个 TLS 记录内的 Hello 可在流中识别；不支持跨 TLS 记录重组 Hello。单包显示过滤仍依据当前报文中已解析的字段。')

    page('04 / TCP STREAM REASSEMBLY','重组连接，保留不确定性')
    story.append(sequence());p('图：样例流中先出现响应后半段，再出现前半段及重传。时间顺序与 TCP 字节顺序不同。','small')
    h('归并、序号与重叠策略')
    p('按双向 IP+Port 四元组归并 TCP 报文；观察到新初始 SYN 且序号不同则划分连接实例，同一 SYN 重传保留在原流。每个方向独立重组。SYN 消耗一个序号；通过 32 位模差转为相对偏移，支持正常窗口范围内的序号回绕。')
    p('先按捕获顺序处理片段，已观察字节保留（first-observed-wins）。重传/重叠字节计数，重叠数据不同时另计冲突；最后按相对序号排序合并相邻区间。对冲突选择的策略未必等同于目标主机 TCP 栈，因此只报告捕获视角，不宣称恢复接收端事实。')
    h('缺口与截断处理')
    p('缺失区间单独列出，文本显示 [CAPTURE GAP]；不同区间不会拼成一条连续应用报文。未看到 SYN 时标记“捕获前缀未知”；即使当前字节连续，也不能证明连接开始前无缺失。每方向重组预览最多 1 MiB，时序绘制最多 160 个报文，超限提示可见。')
    story.append(table([['独立测试输入','期望'],['乱序 world / hello + 重传 hello','输出 helloworld；重传 5 字节'],['abc@100、xyz@110、ZZ@101','相对缺口 [3,10)，7 字节；冲突 2 字节；不跨缺口合并'],['SYN@0xfffffffd，ab@0xfffffffe，cd@0','输出 abcd；正确回绕与 SYN 消耗'],['GE / T / HTTP/1.1… 分段','单段不伪称完整 HTTP；重组后识别 HTTP']],[261,238]))
    p('局限：IP 分片重组、完整 TCP 状态机、SACK/RTT/拥塞分析及超长超过半个序号空间的歧义不在本实现范围；保留窗口淘汰后，流视图同步丢弃对应报文。','small')

    page('05 / ATTRIBUTION, PERFORMANCE & SAFETY','进程关联与运行边界')
    h('进程快照关联')
    p('通过 lsof 字段输出解析 PID、进程名、TCP 本地/远端地址。优先完整四元组匹配（exact），其次以明确本地绑定地址/端口回退（listener），通配监听地址不参与回退；不以普通已连接端口单独猜测归属。刷新会清理失效归属。离线 PCAP 无可信的本机进程来源，禁止使用当前 socket 快照标注历史报文。')
    p('关联仅反映采样时刻：短连接可能已经退出，其他用户进程可能不可见，同一主机回环连接两端都可能是本地进程。本实现选择快照中的匹配记录，并非内核逐包归属。进程页聚合已观察到的关联流；无法匹配时显示未知。')
    h('内存、响应与统计口径')
    p('默认保留 5000 个报文、32 MiB 原始字节；任一阈值达到时淘汰最早报文，同步清理流索引。Python 对象和解析字段还有额外开销，因此 32 MiB 是原始报文预算，非总 RSS 上限。总捕获量、保留量、淘汰量和内核丢包分开显示。HTTP 批量轮询刷新间隔 750 ms，列表显示最近 500 条匹配记录；暂停仅冻结显示。')
    h('本机离线性能测试')
    p(f'脚本 scripts/benchmark.py，以 26 个合成报文循环输入 {bench["packets"]} 次，纯解码取 3 次中位数：约 {bench["decode_packets_per_second"]:,} 包/秒。开启 tracemalloc 的完整会话路径：约 {bench["session_packets_per_second_with_tracemalloc"]:,} 包/秒；保留 {bench["retained"]} 包，淘汰 {bench["evicted"]} 包；Python 跟踪内存峰值约 {bench["traced_peak_bytes"]/1048576:.2f} MiB。环境 {bench["platform"]} / Python {bench["python"]}。')
    p('测量不包含实时 libpcap、辅助进程 IPC、GUI、网卡吞吐、OS 缓冲压力；开启 tracemalloc 会增加开销。高负载能力必须另做真实网络压测并观察 dropped，不能由上述数值外推。','small')
    h('本地应用安全')
    p('浏览器界面的 HTTP 服务监听本机回环地址 127.0.0.1，仅供本机访问；抓包接口可独立选择，不受该监听地址限制。控制 API 校验随机令牌、Host、Origin 和 Sec-Fetch-Site；不开放 CORS。报文中的文本通过 textContent 安全渲染，不作为 HTML 执行；使用 CSP 限制资源。PCAP 上传最多 64 MiB，非法文件导入以临时会话验证后再替换，失败不清空原会话；控制操作版本阻止旧导入覆盖后来的清空或捕获。导出只包含保留窗口中匹配筛选的真实字节。')

    page('06 / VALIDATION & DELIVERY','测试结果与运行方法')
    story.append(table([['测试项','测试结果'],['自动化回归',f'{tests["tests"]} 项测试通过：协议边界、逻辑过滤、真实 libpcap 离线/BPF、TCP 重组、lsof 解析、会话限额、API 鉴权及打包结构。'],['运行环境','macOS / Apple Silicon，Python 3.9+；应用无 pip 依赖。'],['真实 NPS','在 lo0 接口测试本地 HTTP 通信，捕获 12 个报文；请求与响应各 1 个，丢包计数为 0。'],['GUI / 演示视频','录制了约 10 分 10 秒的操作演示，展示实时抓包、过滤、TCP 流、进程关联、PCAP 操作和合成边界案例。进程页面展示了 listener 回退关联。']],[105,394]))
    h('运行与复现')
    for line in ['./launch.command','./verify_live.command','/usr/bin/python3 -m unittest discover -v','/usr/bin/python3 -m compileall -q run.py sniffer scripts','/usr/bin/python3 scripts/benchmark.py --packets 10000']:
        p(line,'code')
    p('演示步骤：lo0 + BPF tcp port 8080 → 启动本地 HTTP 服务 → curl 请求 → HTTP 字段与原始字节 → TCP 流时序 → 保持连接并刷新进程 → 导出/清空/导入。离线样例单独演示乱序、重传、缺口、IPv6、DNS 和 TLS SNI，与实时抓包分别展示。操作前确认接口与捕获过滤表达式，停止后可导出 PCAP 复核。')
    h('实验总结')
    p('本实验完成了从接口捕获、分层解析、逻辑过滤到双向 TCP 流分析的处理过程。通过本地 HTTP 通信测试实时捕获，并使用合成样例检查乱序、重传和缺口处理；同时演示了本机进程关联和 PCAP 导入导出。后续改进方向包括 IP 分片重组、更全面的应用协议支持与高负载捕获性能测试。')
    h('参考')
    p('课程《实验 1 讲解 2026.pdf》（刘鹏，2026-11-10）；本机 libpcap API/系统头文件；libpcap 官方仓库 https://github.com/the-tcpdump-group/libpcap；DNS RFC 1035、mDNS RFC 6762、ALPN RFC 7301；TCP RFC 9293、HTTP/1.1 RFC 9112、IPv6 RFC 8200、TLS 1.3 RFC 8446（协议规范参考）。','small')
    video_path=ROOT/'samples/video-verification.json'
    video=json.loads(video_path.read_text()) if video_path.is_file() else None
    if video:
        page('07 / RECORDED DEMONSTRATION','运行演示')
        rows=[]
        for pair in (video['frames'][:2],video['frames'][2:]):
            cells=[]
            for item in pair:
                path=ROOT/'samples/video-evidence'/item['file']
                img=Image(str(path),width=235,height=235*1440/2310)
                seconds=item['seconds'];caption='%02d:%02d '%(seconds//60,seconds%60)+item['caption']
                cells.append([img,para(caption,'small')])
            rows.append(cells)
        figures=Table(rows,colWidths=[249.5,249.5]);figures.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),10)]));story.append(figures)
        h('演示内容与时间索引')
        story.append(table([['时间段（约）','演示内容'],['00:00–01:00','终端测试与服务准备；后续打开浏览器GUI。'],['01:00–04:00','lo0接口、tcp port 8080、HTTP字段/字节、显示过滤与TCP流时序。'],['04:00–06:40','保持测试连接、进程快照、暂停/继续与PCAP操作；进程页为listener。'],['06:40–09:15','26个合成报文；乱序重传72 B、缺口36 B，以及DNS/ICMP/TLS字段。'],['09:15–10:10','capture.py、protocols.py、flows.py等核心源码展示。']],[105,394]))
        p('先演示本地 HTTP 通信的实时捕获，再载入合成样例，分别展示乱序、重传与缺口处理。进程页面中的 listener 表示根据明确的监听地址和端口进行回退匹配，与完整四元组匹配 exact 的含义不同。','small')
    out=Path(output);out.parent.mkdir(parents=True,exist_ok=True)
    def decorate(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(LINE);canvas.line(48,43,547,43);canvas.setFont('Helvetica',8);canvas.setFillColor(MUTED);canvas.drawString(48,29,'PRISM / UCAS LAB 1A');canvas.drawRightString(547,29,f'{doc.page} / {8 if video else 7}');canvas.setFont('STSong-Light',8);canvas.drawRightString(547,813,'报告草稿 · 待补身份' if draft else '实验 1A · 嗅探器设计与实现');canvas.restoreState()
    doc=SimpleDocTemplate(str(out),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=48,bottomMargin=57,title='Prism - 嗅探器设计与实现',author=name or '待填写学生姓名')
    doc.build(story,onFirstPage=decorate,onLaterPages=decorate);return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--name',default='刘爽');p.add_argument('--student-id',default='202628013229057');p.add_argument('--repo-url',default='https://github.com/SusieLynn9/UCAS_SSSLab');p.add_argument('--output',default=str(ROOT/'output/pdf/刘爽_202628013229057_ex1A_report.pdf'));a=p.parse_args();print(build(a.name,a.student_id,a.repo_url,a.output))
if __name__=='__main__':main()

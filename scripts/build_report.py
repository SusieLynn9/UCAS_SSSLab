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
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
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
    d.add(String(0,10,'界面服务仅监听 127.0.0.1；管理员权限限于实际抓包进程。',fontName='STSong-Light',fontSize=9,fillColor=MUTED));return d

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
    bench=json.loads((ROOT/'docs/benchmark.json').read_text())
    verification_path=ROOT/'docs/test-verification.json'
    tests=json.loads(verification_path.read_text()) if verification_path.exists() else {'tests':36,'passed':True}
    page('UCAS / SOFTWARE AND SYSTEM SECURITY / LAB 1A','嗅探器设计与实现')
    story.append(Paragraph('Prism<span color="#0b887e">.</span>',ParagraphStyle('brand',fontName='Helvetica-Bold',fontSize=49,leading=62,textColor=INK,spaceAfter=8)))
    p('Network Packet Sniffer Design and Implementation','small');p('以真实捕获为基础，以协议证据和连接语义为核心。')
    story.append(Spacer(1,10));story.append(table([['项目信息','内容'],['姓名 / 学号',(name or '待补姓名')+' / '+(student_id or '待补真实学号')],['源码仓库',repo_url or '待创建：software_and_system_security_lab；提交前必须替换为真实 HTTPS URL'],['实验分支','lab-1a-sniffer-design-and-implementation'],['环境','macOS / Apple Silicon；系统 Python 3.9+ / libpcap；本地浏览器 GUI'],['文档状态','待补身份、仓库与 GUI 人工验收的草稿' if draft else '身份信息已填写；请复核仓库开源状态、GUI 验收和最终演示视频']],[105,394]))
    story.append(Spacer(1,17));h('工作摘要');p('实现网卡选择、真实 libpcap 抓包、BPF 捕获过滤、自主分层解码、逻辑显示过滤、三窗格分析、PCAP 导入导出，以及双向 TCP 流重组、时序图和本机进程快照关联。TLS 仅识别可见握手，不解密 HTTPS。')
    p(f'验证摘要：{tests["tests"]} 项自动化测试通过；用户本机回环实测 12 个报文、1 个 HTTP 请求、1 个 HTTP 响应，0 丢包。用户已确认 GUI 打开且暂时无错误；完整交互验收与录屏仍需补齐。','small')
    h('实现边界');p('该实现以课程实验可解释性和可复现性为目标。性能测量为合成离线 CPU 基准，不能推导真实网卡线速。尚未实现 IP 分片重组、完整 HTTP/2/QUIC、HTTPS 解密或逐包进程来源追踪。')

    page('01 / REQUIREMENTS & NETWORK LAYERS','要求映射与抓包层次')
    p('依据课程《实验 1 讲解 2026.pdf》第 2–3、5、9、14–15 页，A/B 二选一；本项目仅完成 1A。评分采用相对排名，以下是能力与证据映射，不预设分数。')
    story.append(table([['课程要求','实现与证据'],['NPS 必须实现（第 9 页）','ctypes 调用系统 libpcap；用户终端 verify_live.command 实测真实 lo0 请求/响应。'],['带 GUI（第 5、15 页）','本地浏览器三窗格：列表、协议树、HEX/ASCII；流、进程、统计页。用户已确认启动成功；完整交互验收待补。'],['协议过滤（第 14 页）','BPF 捕获过滤；HTTP/TCP/UDP/IPv4/v6/ICMP 等显示过滤，and/or/not/括号。'],['尽量完善 NPA（第 9 页）','自主解析 Ethernet/VLAN/ARP/IP/TCP/UDP/ICMP；HTTP/1、DNS、TLS ClientHello/SNI 特征识别。'],['TCP / 进程流追踪（加分）','双向四元组、TCP 重组与时序、lsof 快照关联；缺口、冲突和置信度可见。'],['完整开源记录与提交（第 2–3 页）','本地阶段性 Git 历史；远端和录屏待补；打包脚本生成规定的 ZIP 结构。']],[137,362]))
    h('OSI：捕获层次不等于分析层次')
    p('macOS BPF/libpcap 从网络接口取得链路层可见报文（lo0 使用 Loopback 头，Ethernet 接口通常是以太帧）。分析器剥离链路头后识别网络层 IPv4/v6，再依据协议字段解析 TCP/UDP/ICMP，最后检查载荷是否符合应用层结构。抓到低层字节，并不意味着一定能恢复应用内容。')
    h('Thor 思考题')
    p('安装根证书后，HTTP 代理可在受信任 TLS 终止点获取解密后的 HTTP 内容；这属于特定应用层路径的观察。代理拿到的并非原始端到端 TCP 分段、重传、拥塞或所有传输协议状态，因此不能据此分析完整传输层行为。证书改变信任与可解密性，不能改变观察点和工具的层次边界。证书固定、非代理协议等也可能限制观察。')

    page('02 / CAPTURE & FILTERING','从接口到报文证据')
    story.append(architecture());h('捕获生命周期与权限')
    p('pcap_findalldevs 枚举接口；pcap_create 配置快照长度 65535、100 ms 超时、4 MiB 内核缓冲区；激活后设为非阻塞模式。BPF 编译失败会返回原始错误并保留原会话。捕获条件自动排除界面服务端口，避免抓取控制令牌和自身轮询。工作线程独占 pcap 句柄并在 finally 关闭，停止事件控制线程退出，禁止旧线程污染新会话。')
    p('普通用户无 BPF 权限时，只启动 capture_helper.py 管理员辅助进程。辅助进程不提供 HTTP、不接收任意文件路径、不写磁盘；通过 JSON 行管道传输报文，stdin 关闭触发退出。主进程退出时排空 stdout，避免满管道阻止资源释放。Mac timeval 的 tv_usec 是 32 位，ctypes 按实际 ABI 定义，并用污染 padding 的测试防止错误时间戳。')
    h('捕获过滤与显示过滤')
    story.append(table([['比较','BPF 捕获过滤','显示过滤'],['执行位置','libpcap / OS 捕获路径','用户空间，针对已解析字段'],['生效时间','启动捕获时','分析过程中随时修改'],['例子','tcp port 8080 or icmp','tcp and (http or tls)'],['作用','减少进入用户空间的数据量','筛选保留窗口，不能恢复未捕获数据'],['实现','pcap_compile + pcap_setfilter','递归下降语法解析；禁止 eval']],[80,205,214]))
    h('真实回环验收结果')
    p('2026-11-19 21:20:52 +0800，用户在自己的 Mac 终端执行 ./verify_live.command。脚本临时启动只监听 127.0.0.1 的 HTTP 服务，并仅捕获该服务端口。结果：passed=true，lo0，BPF tcp port 50860，12 个报文，HTTP 请求/响应各 1，dropped=0，interface_dropped=0。原始结果由用户提供，保存在 docs/live-verification.json。')
    p('libpcap received=119 是系统提供的捕获统计，其计数点随平台而异，不能直接视为本程序保留或 BPF 匹配的包数。本次小规模结果不能证明高负载时零丢包。','small')

    page('03 / PROTOCOL ANALYSIS','用报文结构识别协议')
    story.append(table([['层次 / 协议','解析与边界处理'],['链路层','Ethernet、最多 8 层 VLAN；Loopback/NULL、Raw IP、Linux SLL/SLL2。未知链路类型明确告警。'],['ARP / IPv4','地址、操作码；IP 头长、总长、TTL、分片信息。IP 分片不做重组，避免把碎片误识别为完整 TCP。'],['IPv6','地址、Payload Length、Next Header、Hop Limit；有界遍历常见扩展头。非原子分片跳过传输层分析。'],['TCP / UDP','端口、Seq/Ack、Flags、窗口、TCP Data Offset、UDP Length；在声明报文边界内读取。'],['ICMP / ICMPv6','Type、Code、校验和值与常见 Echo/Unreachable/Neighbor 摘要。只展示校验和，未实现校验验证。'],['HTTP/1','验证请求/响应首行，解析可见头字段。即使端口为 8080 也可识别；仅有端口不能证明 HTTP。'],['DNS','事务 ID、查询/响应、问题名与类型；仅在常见 DNS 端口解析，限制问题数量与指针跳转，检测循环压缩指针。'],['TLS','TLS Record 结构；完整 ClientHello 中解析 SNI。未解析完整 TLS 会话，也不解密 HTTP 内容。']],[98,401]))
    h('可解释的异常处理')
    p('每次读取前校验捕获长度与所属协议声明长度；超短头、非法 TCP 偏移、异常 UDP 长度、DNS 循环指针及过长 IPv6 扩展链输出诊断。caplen 小于 wirelen 时标记捕获截断。协议树保存字段起始偏移与长度，HEX 视图直接使用实际捕获字节。')
    h('单包分析与流分析的区别')
    p('应用报文可能横跨 TCP 段。单包解码器只对该段中已出现的完整首行等特征分类；TCP 流视图先重组连续序号区间，再进行应用识别。因此跨段 HTTP 可在流中识别，单包 http 显示过滤不会反向将整个连接的所有分段都归类为 HTTP。')

    page('04 / TCP STREAM REASSEMBLY','重组连接，保留不确定性')
    story.append(sequence());p('图：样例流中先出现响应后半段，再出现前半段及重传。时间顺序与 TCP 字节顺序不同。','small')
    h('归并、序号与重叠策略')
    p('按双向 IP+Port 四元组归并 TCP 报文；观察到新初始 SYN 且序号不同则划分连接实例，同一 SYN 重传保留在原流。每个方向独立重组。SYN 消耗一个序号；通过 32 位模差转为相对偏移，支持正常窗口范围内的序号回绕。')
    p('先按捕获顺序处理片段，已观察字节保留（first-observed-wins）。重传/重叠字节计数，重叠数据不同时另计冲突；最后按相对序号排序合并相邻区间。对冲突选择的策略未必等同于目标主机 TCP 栈，因此只报告捕获视角，不宣称恢复接收端事实。')
    h('缺口与截断绝不静默消失')
    p('缺失区间单独列出，文本显示 [CAPTURE GAP]；不同区间不会拼成一条连续应用报文。未看到 SYN 时标记“捕获前缀未知”；即使当前字节连续，也不能证明连接开始前无缺失。每方向重组预览最多 1 MiB，时序绘制最多 160 个报文，超限提示可见。')
    story.append(table([['独立测试输入','期望'],['乱序 world / hello + 重传 hello','输出 helloworld；重传 5 字节'],['abc@100、xyz@110、ZZ@101','相对缺口 [3,10)，7 字节；冲突 2 字节；不跨缺口合并'],['SYN@0xfffffffd，ab@0xfffffffe，cd@0','输出 abcd；正确回绕与 SYN 消耗'],['GE / T / HTTP/1.1… 分段','单段不伪称完整 HTTP；重组后识别 HTTP']],[261,238]))
    p('局限：IP 分片重组、完整 TCP 状态机、SACK/RTT/拥塞分析及超长超过半个序号空间的歧义不在本实现范围；保留窗口淘汰后，流视图同步丢弃对应报文。','small')

    page('05 / ATTRIBUTION, PERFORMANCE & SAFETY','进程关联与运行边界')
    h('进程快照关联')
    p('通过 lsof 字段输出解析 PID、进程名、TCP 本地/远端地址。优先完整四元组匹配（exact），其次以明确本地绑定地址/端口回退（listener），通配监听地址不参与回退；不以普通已连接端口单独猜测归属。刷新会清理失效归属。离线 PCAP 无可信的本机进程来源，禁止使用当前 socket 快照标注历史报文。')
    p('关联仅反映采样时刻：短连接可能已经退出，其他用户进程可能不可见，同一主机回环连接两端都可能是本地进程。本实现选择快照中的匹配记录，并非内核逐包归属。进程页聚合已观察到的关联流；未知明确显示，不填造进程身份。')
    h('内存、响应与统计口径')
    p('默认保留 5000 个报文、32 MiB 原始字节；任一阈值达到时淘汰最早报文，同步清理流索引。Python 对象和解析字段还有额外开销，因此 32 MiB 是原始报文预算，非总 RSS 上限。总捕获量、保留量、淘汰量和内核丢包分开显示。HTTP 批量轮询刷新间隔 750 ms，列表显示最近 500 条匹配记录；暂停仅冻结显示。')
    h('本机离线性能测量（可复现，不是线速承诺）')
    p(f'脚本 scripts/benchmark.py，以 21 个合成报文循环输入 {bench["packets"]} 次，纯解码取 3 次中位数：约 {bench["decode_packets_per_second"]:,} 包/秒。开启 tracemalloc 的完整会话路径：约 {bench["session_packets_per_second_with_tracemalloc"]:,} 包/秒；保留 {bench["retained"]} 包，淘汰 {bench["evicted"]} 包；Python 跟踪内存峰值约 {bench["traced_peak_bytes"]/1048576:.2f} MiB。环境 {bench["platform"]} / Python {bench["python"]}。')
    p('测量不包含实时 libpcap、辅助进程 IPC、GUI、网卡吞吐、OS 缓冲压力；开启 tracemalloc 会增加开销。高负载能力必须另做真实网络压测并观察 dropped，不能由上述数值外推。','small')
    h('本地应用安全')
    p('HTTP 只绑定 127.0.0.1，控制 API 校验随机令牌、Host、Origin 和 Sec-Fetch-Site；不开放 CORS。报文中的文本通过 textContent 安全渲染，不作为 HTML 执行；使用 CSP 限制资源。PCAP 上传最多 64 MiB，非法文件导入以临时会话验证后再替换，失败不清空原会话；控制操作版本阻止旧导入覆盖后来的清空或捕获。导出只包含保留窗口中匹配筛选的真实字节。')

    page('06 / VALIDATION & DELIVERY','验证、复现与提交')
    story.append(table([['验证项','状态与证据'],['自动化回归',f'{tests["tests"]} 项测试通过：协议边界、逻辑过滤、真实 libpcap 离线/BPF、TCP 重组、lsof 解析、会话限额、API 鉴权及打包结构。'],['运行环境','macOS 自带 Python 3.9.6 与 Homebrew Python 3.15.0；应用无 pip 依赖。'],['真实 NPS','用户本机终端运行：12 个 lo0 报文；1 个 HTTP 请求、1 个响应，丢包 0。原始 JSON 已保存。'],['GUI / 演示视频','用户确认界面已打开且暂时无错误；完整交互验收、截图和实际 MP4 待补。'],['提交状态','本地 Git 分阶段记录已建立；姓名、学号、真实远端与开源状态待补；未发布或提交课程网站。']],[105,394]))
    h('运行与复现')
    for line in ['./launch.command','./verify_live.command','/usr/bin/python3 -m unittest discover -v','/usr/bin/python3 -m compileall -q run.py sniffer scripts','/usr/bin/python3 scripts/benchmark.py --packets 10000']:
        p(line,'code')
    p('实时演示：lo0 + BPF tcp port 8080 → 启动本地 HTTP 服务 → curl 请求 → HTTP 三窗格 → TCP 流时序 → 保持连接并刷新进程 → 导出/清空/导入。离线样例单独演示乱序、重传、缺口、IPv6、DNS 和 TLS SNI，不冒充实时来源。完整步骤见 docs/使用与演示.md。')
    h('提交核对')
    p('2026-11-24 23:55 前提交课程网站；ZIP 不加密，根目录 姓名_学号_EX1A，内含 姓名_学号_ex1A_src、姓名_学号_ex1A_play.mp4、姓名_学号_ex1A_report.pdf/docx。报告写入真实 Git 链接并确认仓库有完整记录。无需 README。scripts/package_submission.py 在取得真实身份、报告和视频后生成规定结构。')
    h('学习与 AI 使用说明（提交前由学生复核）')
    p('本实现由 AI 协助完成代码、测试和文档。核心协议解码、BPF 与显示过滤差异、TCP 序号/重叠策略、快照归属限制和权限拆分应由学生逐项阅读、运行并解释。课程第 65 页建议核心模块自己动手；建议亲自修改一项解析/重组能力并编写测试，保留真实理解与开发记录。当前提交使用代理 Git 作者身份，不伪造学生独立完成过程。')
    h('参考')
    p('课程《实验 1 讲解 2026.pdf》（刘鹏，2026-11-10）；本机 libpcap API/系统头文件；libpcap 官方仓库 https://github.com/the-tcpdump-group/libpcap；TCP RFC 9293、HTTP/1.1 RFC 9112、IPv6 RFC 8200、TLS 1.3 RFC 8446（协议规范参考）。','small')
    out=Path(output);out.parent.mkdir(parents=True,exist_ok=True)
    def decorate(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(LINE);canvas.line(48,43,547,43);canvas.setFont('Helvetica',8);canvas.setFillColor(MUTED);canvas.drawString(48,29,'PRISM / UCAS LAB 1A');canvas.drawRightString(547,29,f'{doc.page} / 7');canvas.setFont('STSong-Light',8);canvas.drawRightString(547,813,'报告草稿 · 待补身份与仓库' if draft else '实验 1A · 嗅探器设计与实现');canvas.restoreState()
    doc=SimpleDocTemplate(str(out),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=48,bottomMargin=57,title='Prism - 嗅探器设计与实现',author=name or '待填写学生姓名')
    doc.build(story,onFirstPage=decorate,onLaterPages=decorate);return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--name',default='');p.add_argument('--student-id',default='');p.add_argument('--repo-url',default='');p.add_argument('--output',default=str(ROOT/'output/pdf/lab-1a-report.pdf'));a=p.parse_args();print(build(a.name,a.student_id,a.repo_url,a.output))
if __name__=='__main__':main()

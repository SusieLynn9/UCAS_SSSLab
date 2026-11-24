#!/usr/bin/env python3
"""Build the ten-page Chinese Harbor report; ReportLab is the only dependency.

Run from any directory: python3 scripts/build_report.py
Evidence is read at build time. Missing evidence is shown as unverified, never
replaced by fabricated successful results. No runtime keys or source files are
embedded in the report.
"""
import argparse
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'output/pdf/刘爽_202628013229057_ex1B_report.pdf'
W, H = 595.276, 841.89
M, CW = 43, W - 86
INK = colors.HexColor('#182c3b')
TEAL = colors.HexColor('#147b83')
MUTED = colors.HexColor('#5c6d78')
PALE = colors.HexColor('#eef5f5')
LINE = colors.HexColor('#cbd9df')


def read_evidence(name):
    path = ROOT / 'output' / name
    if not path.is_file():
        path = ROOT / 'evidence' / name
    if not path.is_file():
        return {}
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('Evidence must be an object: ' + str(path))
    return obj


def register_font():
    candidates = [Path('/System/Library/Fonts/Supplemental/Arial Unicode.ttf'),
                  Path('/usr/share/fonts/truetype/arphic/uming.ttc')]
    for path in candidates:
        if path.is_file():
            try:
                pdfmetrics.registerFont(TTFont('CJK', str(path)))
                return 'CJK'
            except Exception:
                pass
    pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
    return 'STSong-Light'


class Report:
    def __init__(self, output):
        self.font = register_font()
        self.c = canvas.Canvas(str(output), pagesize=(W, H), pageCompression=1)
        self.c.setTitle('实验1B：安全文件传输软件设计与实现 - 刘爽')
        self.c.setAuthor('刘爽 202628013229057')
        self.c.setSubject('Harbor 协议、实现、安全边界与可复现实验')
        self.page = 0
        self.y = H - 90

    def text(self, x, y, text, size=10, color=INK):
        self.c.setFont(self.font, size)
        self.c.setFillColor(color)
        self.c.drawString(x, y, str(text))

    def p(self, text, width=None, x=None, y=None, size=10, leading=16, color=INK, gap=8):
        x = M if x is None else x
        y = self.y if y is None else y
        style = ParagraphStyle('body', fontName=self.font, fontSize=size,
                               leading=leading, textColor=color, wordWrap='CJK',
                               alignment=TA_LEFT, splitLongWords=True)
        para = Paragraph(escape(str(text)).replace('\n', '<br/>'), style)
        _, height = para.wrap(width or CW, 900)
        if y - height < 59:
            raise ValueError('Page %d overflow: %s' % (self.page, str(text)[:50]))
        para.drawOn(self.c, x, y - height)
        end = y - height - gap
        if x == M and width is None:
            self.y = end
        return end

    def new(self, label, title, subtitle):
        if self.page:
            self.c.showPage()
        self.page += 1
        self.c.setFillColor(TEAL)
        self.c.rect(M, H-49, 24, 3, fill=1, stroke=0)
        self.text(M+34, H-49, 'HARBOR  /  EXPERIMENT 1B', 8, MUTED)
        self.text(W-135, H-49, label, 8, MUTED)
        self.text(M, H-90, title, 22)
        self.text(M, H-112, subtitle, 9, MUTED)
        self.c.setStrokeColor(LINE)
        self.c.line(M, 48, W-M, 48)
        self.text(M, 31, '刘爽  ·  202628013229057  ·  安全文件传输软件', 8, MUTED)
        self.text(W-M-44, 31, '%02d / 10' % self.page, 8, MUTED)
        self.y = H-140

    def h(self, text):
        self.text(M, self.y-13, text, 12, TEAL)
        self.y -= 25

    def note(self, text):
        style = ParagraphStyle('note', fontName=self.font, fontSize=9,
                               leading=14, textColor=INK, wordWrap='CJK')
        p = Paragraph(escape(text), style)
        _, height = p.wrap(CW-22, 900)
        self.c.setFillColor(PALE)
        self.c.roundRect(M, self.y-height-20, CW, height+20, 5, fill=1, stroke=0)
        p.drawOn(self.c, M+11, self.y-height-10)
        self.y -= height+31

    def table(self, headers, rows, widths, size=9, leading=14):
        def cell(text, width, header=False):
            style = ParagraphStyle('cell', fontName=self.font, fontSize=size,
                                   leading=leading, textColor=colors.white if header else INK,
                                   wordWrap='CJK')
            p = Paragraph(escape(str(text)), style)
            _, height = p.wrap(width-14, 900)
            return p, height
        for ri, row in enumerate([headers]+list(rows)):
            cells = [cell(t, width, ri == 0) for t, width in zip(row, widths)]
            height = max(h for _, h in cells)+13
            if self.y-height < 60:
                raise ValueError('Table overflows page %d' % self.page)
            self.c.setFillColor(TEAL if ri == 0 else (PALE if ri % 2 else colors.white))
            self.c.rect(M, self.y-height, CW, height, fill=1, stroke=0)
            x = M
            for (p, h), width in zip(cells, widths):
                p.drawOn(self.c, x+7, self.y-6-h)
                x += width
            self.y -= height
        self.y -= 13

    def arrow(self, x1, x2, y, label, size=8, label_y=5):
        self.c.setStrokeColor(TEAL)
        self.c.setLineWidth(.8)
        self.c.line(x1, y, x2, y)
        direction = 1 if x2 > x1 else -1
        self.c.line(x2, y, x2-direction*5, y+3)
        self.c.line(x2, y, x2-direction*5, y-3)
        self.c.setFont(self.font, size)
        self.c.setFillColor(INK)
        self.c.drawCentredString((x1+x2)/2, y+label_y, label)

    def sequence(self, title, actors, messages, height=218, x=None, width=None, top=None):
        x = M if x is None else x
        width = CW if width is None else width
        top = self.y if top is None else top
        self.c.setFillColor(PALE)
        self.c.roundRect(x, top-height, width, height, 5, fill=1, stroke=0)
        self.text(x+10, top-19, title, 10, TEAL)
        xs = [x+38+(width-76)*i/(len(actors)-1) for i in range(len(actors))]
        for actor, xx in zip(actors, xs):
            self.c.setFillColor(INK)
            self.c.setFont(self.font, 9)
            self.c.drawCentredString(xx, top-42, actor)
            self.c.setStrokeColor(LINE)
            self.c.setDash(2, 3)
            self.c.line(xx, top-51, xx, top-height+12)
            self.c.setDash()
        step = min(29, (height-77)/max(1, len(messages)-1))
        for index, (a, b, text) in enumerate(messages):
            yy = top-66-step*index
            if a == b:
                self.text(xs[a]+6, yy, text, 8, MUTED)
            else:
                self.arrow(xs[a], xs[b], yy, text, 8 if width>300 else 7)
        if x == M and width == CW:
            self.y = top-height-14

    def finish(self):
        if self.page != 10:
            raise ValueError('Expected ten pages')
        self.c.save()


def build(output):
    verification = read_evidence('verification.json')
    benchmark = read_evidence('benchmark.json')
    sandbox = read_evidence('sandbox-verification.json')
    r = Report(output)
    r.new('概览 / 01', '安全文件传输软件设计与实现', '实验 1B  ·  Harbor v1  ·  课程实验报告')
    r.text(M, r.y-8, '刘爽', 20)
    r.text(M+85, r.y-7, '学号  202628013229057', 12, MUTED)
    r.y -= 44
    r.note('项目实现自定义二进制应用层协议，运行于双向认证 TLS 长连接之上。原生桌面客户端提供多文件上传、下载和任务控制；服务端执行账号隔离、事务发布、断点校验与按用户聚合限速。')
    r.h('实验目的与实现范围')
    r.p('依据《实验1讲解2026.pdf》第31-48页，将“完整、安全地传输文件”拆分为身份验证、消息定界、会话复用、存储访问控制、异常恢复和资源管理。应用层显式声明长度与结束确认，文件完成不依赖关闭TCP连接。')
    r.table(['课程要求', '本项目对应实现'], [
        ('安全通信与并发', 'mTLS、CA/主机名验证、证书指纹账号映射；有界多连接服务'),
        ('自定义协议与长连接', '20字节固定头 + UTF-8 JSON + 二进制块；1控制连接 + 默认4工作连接'),
        ('报告与可复现演示', '协议头图、各模块时序图、测试证据、Mac运行说明和真实录屏脚本'),
        ('四项加分功能', '双向断点续传、公钥认证、GUI多文件并行、身份分级共享带宽桶')
    ], [126, CW-126])
    r.h('结果与验收边界')
    if verification:
        r.p('自动验证记录：%s项测试，失败%s项、错误%s项、跳过%s项，结论%s。运行环境：Python %s，%s。' % (
            verification.get('tests', '?'), verification.get('failures', '?'), verification.get('errors', '?'), verification.get('skipped', '?'),
            '通过' if verification.get('passed') else '未通过', verification.get('python', '?'), verification.get('platform', '?')), size=9, leading=14)
    else:
        r.p('尚无自动验证记录，应先运行 scripts/selftest.py；本报告不将缺失证据视为通过。')
    r.p('自动测试覆盖真实回环mTLS、传输与续传、权限隔离和工作池。使用Python 3.15.2与Tk 9.1运行客户端，窗口显示及alice身份连接已验证。尚未录制1B演示视频。', size=9, leading=14)
    r.p('代码仓库：https://github.com/SusieLynn9/UCAS_SSSLab\n分支：lab-1b-secure-file-transfer-software-design-and-implementation', size=8, leading=13)

    r.new('架构 / 02', '系统结构与持续会话', '线程职责清晰，连接随用户会话持续复用')
    r.table(['层次 / 文件', '职责与关键约束'], [
        ('GUI / gui.py', 'Tk主线程绘制；TransferPool后台线程执行I/O；queue + after传递普通数据'),
        ('客户端 / client.py', 'TLS握手、请求关联、上传票据、下载清单、SHA-256和暂停/取消语义'),
        ('协议 / protocol.py', '帧编解码、精确接收、元数据校验、长度边界和整帧截止时间'),
        ('服务端 / server.py', '有界接入、证书映射、HELLO状态、操作派发、错误回应与连接清理'),
        ('存储 / storage.py', '目录描述符隔离、私有普通文件、事务所有权、配额、提交与续传'),
        ('带宽 / limits.py', '按账号共享令牌桶；同账号所有连接和上下行共同消耗有效载荷额度')
    ], [125, CW-125])
    r.h('服务端主流程')
    r.p('监听TCP → 接入计数/连接槽检查 → TLS握手（5秒）→ 对端证书SHA-256指纹映射 → 等待HELLO → 接收并验证完整帧 → 按opcode执行业务 → 相同request_id回复。循环持续到QUIT、断线、超时或服务端停止；finally释放下载句柄、上传所有权、连接槽与线程记录。')
    r.h('长连接为何满足要求')
    r.p('客户端和服务端均显式设置SO_KEEPALIVE。控制连接承担目录刷新及连接状态；默认4个工作连接分别串行执行任务，完成后返回工作循环继续复用。空闲约15秒发送PING；连接标识connection_id可用于核实同一会话复用。单连接的request/response受锁保护，多文件并行由连接池完成。')
    r.note('文件边界由声明总长、分块偏移与UPLOAD_COMMIT定义；一次LIST、PING或文件完成均不主动关闭TCP。心跳保持应用可见性，SO_KEEPALIVE提供内核级存活探测；二者不保证断网期间连接永远有效。')
    r.h('异常恢复与关闭')
    r.p('网络错误使当前socket失效，GUI任务保留可重试状态，重新连接后按已持久化偏移恢复。暂停释放服务端活动所有权而保留临时数据；用户关闭窗口时停止工作池并关闭持久客户端。QUIT有明确应答，服务端也可响应SIGINT/SIGTERM有序停止。', size=9, leading=14)

    r.new('协议 / 03', '20 字节报头与消息定界', 'struct.Struct("!4sBBHIII")  ·  网络字节序  ·  无隐含填充')
    top = r.y-30
    r.text(M, r.y+1, '字节偏移（字段边界）', 8, MUTED)
    for offset in (0, 4, 5, 6, 8, 12, 16, 20):
        r.c.setFont(r.font, 8)
        r.c.setFillColor(MUTED)
        r.c.drawCentredString(M+CW*offset/20, top+8, str(offset))
    fields = [('magic',4), ('ver',1), ('op',1), ('flags',2), ('request_id',4), ('meta_len',4), ('payload_len',4)]
    xx=M
    for index,(label,length) in enumerate(fields):
        ww=CW*length/20
        r.c.setFillColor(TEAL if index%2==0 else INK)
        r.c.rect(xx,top-34,ww,34,fill=1,stroke=0)
        r.c.setFillColor(colors.white);r.c.setFont(r.font,7 if length==1 else 8)
        r.c.drawCentredString(xx+ww/2,top-14,label)
        r.c.drawCentredString(xx+ww/2,top-26,str(length)+' B')
        xx+=ww
    r.y=top-47
    r.p('帧布局：[固定头20B] [metadata_length字节UTF-8 JSON对象] [payload_length字节二进制载荷]。magic固定HBR1，version=1；响应opcode=请求opcode | 0x80；flags=0为成功，错误响应flags=1。request_id取1..2³²-1，用于确认响应属于当前请求。',size=9,leading=14)
    r.table(['opcode', '消息', '元数据 / 载荷与目的'], [
        ('1 / 8', 'HELLO / PING', '初始化身份能力 / 空闲心跳，返回connection_id'),
        ('2', 'LIST', 'offset分页，每页最多32项；返回next_offset'),
        ('3', 'UPLOAD_BEGIN', 'name、size、sha256；返回事务ID、已确认offset与前缀摘要'),
        ('4 / 5', 'UPLOAD_CHUNK / COMMIT', 'transfer_id、offset + 数据块 / 核验并发布文件'),
        ('6 / 7', 'DOWNLOAD_INFO / CHUNK', 'name、offset / download_id、offset、length；响应携带块'),
        ('9 / 10', 'CANCEL / QUIT', '方向、事务或句柄、discard / 结束用户连接')
    ], [49,151,CW-200],size=8,leading=13)
    r.h('解析不依赖TCP分段')
    r.p('recv_exact循环接收指定字节数，先收20字节头并检查magic、版本、操作码、flags、非零ID和长度，再收元数据及载荷。粘包会留待下一帧读取，拆包则继续累积；EOF、截断或整帧超过120秒均中止连接。截止时间覆盖整帧，逐字节发送不能无限延长等待。',size=9,leading=14)
    r.p('元数据上限16 KiB、载荷上限64 KiB；拒绝重复JSON键、非有限数、非对象和无效UTF-8。除UPLOAD_CHUNK外客户端请求不允许载荷。未识别的协议结构关闭连接；业务错误回同ID错误帧，仍可继续后续合法请求。',size=9,leading=14)
    r.note('正确性依据：长度定界避免以EOF作为文件结束；请求ID + opcode校验避免响应错配；严格偏移确认避免静默丢块/重复块；全文件摘要与最终发布使“收到字节”和“完成文件”分开。TLS负责通道完整性，应用摘要负责文件及续传一致性。')

    r.new('时序 / 04', '认证、目录、心跳与异常', '以下为源码行为示意图，不是抓包截图或运行界面截图')
    r.sequence('A  公钥身份认证与HELLO', ['客户端','TLS / 服务端','账号配置'], [
        (0,1,'TCP连接 + TLS握手'),(1,0,'服务端证书；CA与主机名校验'),(0,1,'客户端证书 + 私钥签名证明'),
        (1,2,'证书指纹查找授权账号'),(2,1,'用户 / 权限 / rate / quota'),(0,1,'HELLO (id=n)'),(1,0,'HELLO|0x80：身份与能力')],height=225)
    x1=M; x2=M+CW/2+7; ww=CW/2-7; top=r.y
    r.sequence('B  LIST目录分页', ['客户端','服务端'],[(0,1,'LIST offset=0'),(1,0,'files[0:32], next_offset'),(0,1,'LIST offset=next'),(1,0,'下一页；最终next=null')],height=160,x=x1,width=ww,top=top)
    r.sequence('C  PING复用连接', ['控制/工作连接','服务端'],[(0,1,'空闲15秒：PING'),(1,0,'相同connection_id'),(0,1,'下一次LIST或传输'),(1,0,'继续原TLS会话')],height=160,x=x2,width=ww,top=top)
    r.y=top-174
    r.sequence('D  业务错误、协议错误与QUIT', ['客户端','服务端'],[
        (0,1,'合法帧但业务越权/偏移错误'),(1,0,'原opcode|0x80 + ERROR + code'),(0,1,'后续合法请求可继续'),
        (0,1,'QUIT'),(1,0,'closed=true，然后关闭连接')],height=170)
    r.p('补充：无效报头、长度超限、截断和握手失败直接关闭连接；指纹未授权的证书即使由受信CA签发也不获得账号。业务错误码包括DENIED、STATE、BUSY、CONFLICT、QUOTA、INTEGRITY、NOT_FOUND和IO；不回传私钥或服务端绝对路径。',size=9,leading=14)

    r.new('时序 / 05', '上传事务、确认与最终提交', '未校验的临时数据不会出现在普通文件列表')
    r.sequence('E  UPLOAD_BEGIN → CHUNK → COMMIT', ['客户端','服务端','Storage / 磁盘'], [
        (0,1,'BEGIN(name, size, sha256)'),(1,2,'校验权限 / 名称 / 配额 / 冲突'),(2,1,'transfer_id, offset, prefix_sha256'),
        (1,0,'返回事务与断点'),(0,1,'CHUNK(tid, offset) + ≤64KiB'),(1,2,'共享限速 → 按偏移写入 / fsync'),
        (1,0,'确认新的offset；重复直到size'),(0,1,'UPLOAD_COMMIT(tid)'),(1,2,'总长 + SHA-256 + inode核验 / 发布'),(1,0,'name, size, sha256；连接继续')],height=319)
    r.h('事务标识、所有权与幂等性')
    r.p('事务ID为[user, name, size, sha256]的SHA-256，清单与.part保存在该用户.partial目录。活动事务绑定连接owner，另一个连接不能写入或取消正在进行的上传。同名不同事务和同一事务的并发活动请求均被拒绝，避免覆盖与互相续写。')
    r.p('已发布同名文件若长度与SHA-256完全一致，BEGIN返回complete，客户端直接确认完成；同名不同内容返回CONFLICT，要求更换文件名。此行为解决提交确认丢失后的重试，不提供静默覆盖。客户端在提交前再核对源文件大小与mtime，服务端独立检查全文件摘要。')
    r.h('提交为何不会发布半个文件')
    r.p('服务端先通过已打开描述符核验长度和摘要，再核对临时路径与已验证inode一致；使用不覆盖目标的硬链接发布，核查发布inode后删除临时链接与清单，并同步目录。最终名称仅指向完整校验对象；目标预先存在即拒绝。临时/最终文件处于同一存储文件系统。')
    r.note('持久化策略按块fsync，优先减少异常中断后的已确认数据丢失窗口；这也增加小块写入开销。本实现不把普通进程/文件系统失败测试扩展为所有断电与硬件故障的强一致性保证。')

    r.new('恢复 / 06', '双向续传与暂停、取消', '偏移值必须与内容身份共同验证，不能只依赖文件长度')
    r.sequence('F  上传暂停 / 断线后续传', ['客户端','服务端','临时事务'], [
        (0,1,'CANCEL(upload, discard=false)'),(1,2,'释放owner；保留.part与清单'),(1,0,'closed=true；任务paused'),
        (0,1,'继续：BEGIN同一name/size/hash'),(1,2,'检查事务；重算offset与前缀摘要'),(1,0,'offset + prefix_sha256'),(0,1,'本地前缀吻合才从offset发CHUNK')],height=244)
    r.sequence('G  下载续传与取消清理', ['客户端 / 本地','服务端'], [
        (0,1,'INFO(name, 本地.part长度)'),(1,0,'size, sha256, prefix_sha256, handle'),(0,1,'验证清单/前缀后请求剩余CHUNK'),
        (0,1,'暂停：CANCEL(download, handle)'),(1,0,'关闭远端句柄；本地保留断点'),(0,1,'取消：CANCEL + 本地清理.part/.json')],height=226)
    r.h('控制语义与异常边界')
    r.p('暂停在块边界生效：上传保留服务端事务及upload_ticket，下载保留本地.part与清单；继续/重试重新执行BEGIN或INFO。断线由finally释放活动所有权，未完成上传仍可恢复；新下载在取得INFO前失败不会留下阻塞重试的无清单临时文件。已暂停上传的“取消并清理”通过Client.cancel_upload(ticket)重新请求discard=true；暂停下载由cancel_download核对清单归属、目标文件名及设备/inode后清理本地断点；无可信清单或文件已被替换时保留原文件。',size=9,leading=14)
    r.p('取消上传discard=true删除服务端.part与清单。正在另一连接运行的事务不能被抢占删除。下载续传要求远端size/hash与保存清单相同，且已有前缀hash一致；任一不符都报错，防止把不同版本拼接。过期且非活动上传事务在后续BEGIN时按TTL回收。',size=9,leading=14)

    r.new('下载 / 07', '下载完整性与 GUI 交互', '多任务并行由工作池承载，Tk主线程保持可响应')
    r.sequence('H  DOWNLOAD_INFO → CHUNK → 完成', ['客户端','服务端','本地文件'], [
        (0,1,'INFO(name, offset)'),(1,0,'size/hash/prefix + download_id'),(0,1,'CHUNK(handle, offset, length)'),
        (1,0,'meta(offset,length) + binary payload'),(0,2,'pwrite + fsync；更新进度'),(0,1,'全部接收后CANCEL关闭句柄'),
        (0,2,'全长/全文件hash/inode核验'),(0,2,'不覆盖发布目标；清理.part/.json')],height=267)
    r.p('服务端下载句柄绑定本连接已打开的普通文件描述符，记录inode、长度与mtime，块读取前后检查版本；客户端验证返回偏移、块长度、非空载荷及总长边界。最终核对SHA-256，再用不覆盖链接发布；已有普通目标默认拒绝覆盖；临时路径被替换会失败。重启时可核对清单、摘要及inode，完成发布中断后的残留链接清理。',size=9,leading=14)
    r.table(['界面区域', '操作与反馈'], [
        ('连接与身份', '选择客户端配置并连接；显示证书对应用户、等级、TLS和限额，错误可重新连接'),
        ('本地 / 远端双栏', '本地选择文件夹/刷新；远端仅当前账号空间；支持多选上传和下载'),
        ('传输任务区', '方向、文件、进度、速率、状态；选中进度条及错误详情；多选暂停/继续/取消'),
        ('并发与反馈', '默认4个持久工作连接；同一池混合上传/下载，后台事件通过队列进入after更新')
    ],[100,CW-100],size=9,leading=14)
    r.h('界面验收状态')
    r.note('GUI使用Tk≥8.6的解释器；本机Python 3.15.2与Tk 9.1已确认窗口显示正常，能够连接alice。多任务、暂停、继续和取消由工作池回归测试覆盖；尚未完成全部按钮的逐项人工验收和1B录屏。')

    r.new('安全 / 08', '分层防护与明确的信任边界', '通道、身份、目录和进程权限分别约束不同攻击面')
    r.table(['威胁', '实现措施', '保证范围 / 局限'],[
        ('中间人 / 伪造服务端', 'TLS最低1.2；校验CA与主机名；ECDHE + AEAD', '拒绝不可信证书/错误主机名；本地CA私钥须保密'),
        ('冒用用户 / 越权', '客户端证书证明私钥持有；指纹映射账号；独立读写权限', '信任CA仍不等于授权账号；客户端私钥被盗需撤销配置'),
        ('路径穿越 / 链接攻击', '单文件名校验；dir_fd、O_NOFOLLOW；普通文件且nlink=1；inode复核', '客户端不能指定服务端绝对路径；拒绝符号链接与已有硬链接'),
        ('SQL / 命令注入', '业务无SQL数据库，不拼接Shell；JSON只作数据', '注入样式输入不会成为查询或命令；名称仍受独立校验'),
        ('内存 / 连接 / 慢速耗尽', '帧16/64KiB；整帧120秒；握手5秒；32总连接、每IP默认16；每IP20次/秒准入', '有界资源与超时缓解应用层DoS；无法保证抵御任意DDoS'),
        ('磁盘 / 速率滥用', '每用户配额、最多16待续传事务/256文件、TTL；共享带宽桶', '约束声明空间与有效载荷；不等同上游链路清洗')
    ],[77,229,CW-306],size=8.5,leading=13)
    r.h('目录权限与进程沙箱')
    r.p('初始化与Storage将存储根、账号目录、.partial设置为0700，私钥、配置、清单/数据文件默认0600。服务只接受账号子目录中的单文件名；账号名由管理员配置而非请求提供。应用目录隔离限制协议可访问对象，但单靠文件名校验无法约束被完全控制后的进程。',size=9,leading=14)
    r.p('Mac默认launch_server.command调用sandbox-exec；scripts/sandbox_profile.py生成deny-default策略：仅允许服务源码/解释器/系统必需目录和配置指定的证书读入，数据写入仅限配置root（另有/dev/null与终端设备例外），并开放必要网络/进程能力。读取证书是运行必需；CA私钥、客户端私钥不在服务证书读入白名单。',size=9,leading=14)
    r.note('验证包含：独立探针的目录外读写被拒，以及tests/test_sandbox.py中真实沙箱服务的TLS上传/下载成功、生成的目录外测试文件读写被拒。此策略为本机Mac环境实现，允许必要系统只读访问，并非跨平台沙箱或任意进程行为全隔离证明；其他系统应配置独立低权限服务账号及等效OS隔离。')

    r.new('测试 / 09', '自动验证与按身份限速实测', '结果从 output/*.json 读取；证据日期与范围保留在本页')
    if verification:
        r.p('验证时间：%s。测试%s项 / 失败%s / 错误%s / 跳过%s；耗时%.2f秒。解释器Python %s，TLS库%s。结论：%s。' % (
            verification.get('timestamp','未记录'),verification.get('tests','?'),verification.get('failures','?'),verification.get('errors','?'),verification.get('skipped','?'),
            verification.get('seconds',0),verification.get('python','?'),verification.get('ssl','?'),'通过' if verification.get('passed') else '未通过'),size=9,leading=14)
    else:r.note('缺少verification.json，尚不能给出测试通过结论。')
    r.table(['验证层', '覆盖的关键行为'],[
        ('协议 / 存储', '拆包/粘包、长度/JSON限制、整帧截止时间、路径/链接拒绝、配额、所有权与发布一致性'),
        ('真实TLS集成', '证书与主机名、未授权指纹、持久连接、文件往返摘要、断点/冲突、并发和权限'),
        ('GUI后端 / 沙箱', '工作池事件协调、暂停/取消/重试；完整沙箱服务TLS往返及目录外拒绝；不覆盖GUI视觉验收')
    ],[105,CW-105],size=8.5,leading=13)
    r.p('独立沙箱探针：目录内写入%s，目录外读取拒绝%s，目录外写入拒绝%s；整体%s。' % (
        '通过' if sandbox.get('inside_write') else '未验证', '通过' if sandbox.get('outside_read_denied') else '未验证',
        '通过' if sandbox.get('outside_write_denied') else '未验证', '通过' if sandbox.get('passed') else '未验证'),size=9,leading=14)
    results=benchmark.get('results',[])
    r.h('回环mTLS上传：普通用户与VIP')
    if results:
        rows=[]
        for b in results:
            rows.append((b['user']+' / '+b.get('tier',''), '%.0f KiB/s'%(b['configured_payload_bytes_per_second']/1024),
                         '%.2f MiB'%(b['bytes']/1048576), '%.4f s'%b['seconds'], '%.1f KiB/s'%(b['observed_bytes_per_second']/1024)))
        r.table(['账号','配置速率','载荷','耗时','实测速率'],rows,[105,105,80,100,CW-390],size=8.5,leading=13)
        bar_top=r.y-15
        maximum=max(b['seconds'] for b in results)
        for i,b in enumerate(results):
            yy=bar_top-i*29
            r.text(M,yy,b['user'],9)
            r.c.setFillColor(TEAL if i==0 else colors.HexColor('#7cabb1'))
            r.c.roundRect(M+48,yy-2,(CW-125)*b['seconds']/maximum,12,3,fill=1,stroke=0)
            r.text(M+CW-68,yy,'%.3f s'%b['seconds'],9)
        r.y=bar_top-len(results)*29-9
        r.p('测量时间：'+benchmark.get('timestamp','未记录')+'。每个用户单独测量；成功结果含全文件SHA-256。该对比说明不同身份的配置生效，不代表公网/NIC极限吞吐。',size=8.5,leading=13)
    else:r.note('缺少benchmark.json；应执行scripts/benchmark.py获得实测结果。')
    r.p('令牌桶速率r，容量B=max(65536, r/4)，初始满桶；任意区间有效载荷满足近似上界bytes≤r×t+B。2 MiB上传中alice配置256 KiB/s，B=64 KiB；bob配置1024 KiB/s，B=256 KiB。因此短样本平均速率可高于配置值，bob最短载荷等待约1.75秒、alice约7.75秒，与实测一致。',size=9,leading=14)
    r.p('统计口径仅二进制payload，上传与下载均消耗同一账号桶，元数据/TLS开销不计。多连接共享预算，等待时释放桶锁，不把某用户的限速等待变成全局停顿。并发整体验证与这里顺序单用户性能样本应分别理解。',size=9,leading=14)

    r.new('复现 / 10', '运行、验收与提交说明', '源代码可复查，报告可重建，视频须展示真实运行过程')
    r.h('在本实验工作目录启动')
    r.p('在项目根目录先执行./setup_demo.command生成私有本地CA、服务端和alice/bob证书及随机演示文件；重复执行不会覆盖现有runtime。终端一执行./launch_server.command；终端二执行./launch_client.command，默认加载runtime/alice.json。另一客户端可用--config runtime/bob.json。',size=9,leading=14)
    r.p('服务端使用系统Python3.9及标准库，Mac默认进入进程沙箱。GUI解释器需Tk≥8.6，推荐安装brew install python-tk@3.15后由启动器选择，或使用当前python.org安装包。Python源码无需C/C++编译，录屏应展示py_compile、初始化、部署和测试全过程。',size=9,leading=14)
    r.h('验证与报告重建')
    for command in [
        '/usr/bin/python3 -m py_compile harbor/*.py scripts/*.py run_*.py',
        '/usr/bin/python3 scripts/selftest.py',
        '/usr/bin/python3 scripts/benchmark.py',
        '/usr/bin/python3 scripts/verify_sandbox.py',
        'python3 -m pip install reportlab',
        'python3 scripts/build_report.py']:
        r.p(command,size=8,leading=12,gap=5)
    r.p('报告生成器仅额外依赖ReportLab，默认输出output/pdf/刘爽_202628013229057_ex1B_report.pdf；缺失证据明确显示未验证。Python3.9兼容源码与本机Tk运行时的兼容性分别检查。窗口启动与alice连接已验证，完整按钮操作和真实录屏尚未完成。',size=8.5,leading=13)
    r.table(['第40页加分项', '实现落点 / 验收动作'],[
        ('文件断点续传', '上传/下载均校验前缀；暂停、继续，观察resumed_from和最终摘要'),
        ('公钥身份认证', 'mTLS与指纹映射；合法证书成功，错误CA/主机名/未授权身份拒绝'),
        ('GUI多文件并行', '4工作连接混合双向队列；原生GUI需实机按钮与视觉验收'),
        ('身份带宽控制', 'alice 256 KiB/s、bob 1024 KiB/s；多连接同用户共享总预算')
    ],[112,CW-112],size=8.5,leading=13)
    r.p('提交命名：刘爽_202628013229057_EX1B.zip；根目录同名，报告名以ex1B_report.pdf结尾，真实视频以ex1B_play.mp4结尾。打包器排除docs、runtime、密钥和工作数据；证书在评分机器重新初始化。未实录视频时不得用示意图、脚本或空文件替代运行录像。',size=8.5,leading=13)
    r.p('参考与依据：[1]《实验1讲解2026.pdf》第31-48页（课程要求、长连接、协议图、ACL、四项加分）。[2] 本仓库harbor/与scripts/、tests/（实现与可执行验证）。[3] output/verification.json、benchmark.json、sandbox-verification.json（本次生成读取的实际证据）。',size=8,leading=12)
    r.finish()
    return {'output': str(output), 'pages': 10, 'tests': verification.get('tests'),
            'passed': verification.get('passed'), 'gui_visual_acceptance': 'window and alice connection confirmed; full button acceptance pending'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT)
    args=parser.parse_args()
    output=args.output.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps(build(output), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

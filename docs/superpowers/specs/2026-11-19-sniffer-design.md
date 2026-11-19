# 1A：嗅探器设计与实现

依据：根目录《实验 1 讲解 2026.pdf》全 66 页，重点第 2–3、5、9、14–15、21、64–65 页。用户要求本地完成 1A，主要运行于当前 macOS，争取较高完成度。

## 约束与验收

- 必须真实抓包（NPS），有 GUI，不以样例回放冒充实时抓包。
- 通过系统 libpcap 枚举网卡、抓包和 BPF 过滤，用户空间自主解析（NPA）。
- HTTP、TCP、UDP、IPv4、IPv6、ICMP 可过滤，显示过滤支持 and/or/not 与括号。
- 加分：双向 IP+端口 TCP 流、序列号重组、时序展示；进程产生的 TCP 流关联。
- 报文列表、协议树、十六进制三窗格；暂停/停止；离线 PCAP 导入导出；统计和丢包指标。
- 提交时间 2026-11-24 23:55，ZIP，源码目录+MP4+PDF/DOCX，报告含 Git 链接，保留完整 Git 历史；README 不是提交要求。
- 1B 不实现。英文名 Secure File Transfer Software Design and Implementation。

## 实现选择（开发者决定）

Python 3.9+ 标准库 + ctypes 直接绑定 libpcap；本地 HTTP GUI 绑定 127.0.0.1，随机访问令牌并校验 Origin/Host。静态 HTML/CSS/JS 不用 CDN。macOS 优先；Linux 与 Windows Npcap 尽力兼容，不宣称实机验证。

模块：pcap.py 负责 ABI/资源生命周期、capture.py 负责工作线程及有界存储、protocols.py 负责无状态解码、filters.py 负责逻辑表达式、flows.py 负责双向流/重组、processes.py 负责 lsof 快照关联、server.py 负责本地 API、web/ 负责 GUI。抓包和解析与 HTTP 请求分离，以批量增量刷新减少阻塞。

解码：Ethernet/VLAN、NULL/LOOP、RAW、Linux SLL/SLL2；ARP、IPv4（选项、分片边界）、IPv6（扩展头）、TCP、UDP、ICMP/v6；基于载荷特征而非仅端口识别 HTTP/1、DNS、TLS ClientHello/SNI。TLS 不做解密，不把 HTTP/2、QUIC 完整解析列为已完成。

重组：按方向、TCP 序号排序，处理 SYN 序号、重传、重叠、乱序、回绕，报告缺口/冲突/截断，不拼接跨缺口数据。首包前缺失未知。连接复用/端口重用通过新 SYN 划分。内存硬上限，清理旧包时同步移除其流数据。

进程：macOS lsof -F 字段模式按完整四元组优先关联，监听端口回退标注置信度。快照有竞态和权限限制；未知显式展示，不伪造归属。

验证：独立构造报文的单元测试、真实 libpcap 离线/BPF 测试、HTTP API 集成、GUI 浏览器操作、真实回环抓包（若 /dev/bpf 权限允许）；性能只报告本机实测。

交付：可运行源码、自动化测试、可重复生成的无敏感样例、中文用户/实验报告、演示脚本、按姓名学号参数化的提交打包脚本。尚无用户身份与 GitHub URL，不编造；尚无人工演示视频，不能宣称完成提交。

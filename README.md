# 实验 1A：嗅探器设计与实现

## 运行与复现

以下命令按需分别执行；启动程序的终端需保持运行。

```sh
./launch.command
```

```sh
./verify_live.command
```

```sh
/usr/bin/python3 -m unittest discover -v
```

```sh
/usr/bin/python3 -m compileall -q run.py sniffer scripts
```

```sh
/usr/bin/python3 scripts/benchmark.py --packets 10000
```

演示步骤：lo0 + BPF `tcp port 8080` → 启动本地 HTTP 服务 → curl 请求 → HTTP 字段与原始字节 → TCP 流时序 → 保持连接并刷新进程 → 导出/清空/导入。

离线样例单独演示乱序、重传、缺口、IPv6、DNS 和 TLS SNI，与实时抓包分别展示。操作前确认接口与捕获过滤表达式，停止后可导出 PCAP 复核。

# 实验 1B：安全文件传输软件设计与实现

Harbor 使用自定义应用层协议与双向认证 TLS 长连接，实现用户隔离、SHA-256 校验、双向断点续传、多文件并行传输和按用户共享带宽限速。

## 环境

- Python 3.9 或更新版本，核心程序使用标准库。
- 初始化证书需要 OpenSSL 命令行工具。
- 图形客户端需要 Tkinter，且 Tk ≥ 8.6。Mac 自带的旧 Tk 8.5 不受支持；启动器会选择可用的现代 Tk 解释器。

## 运行

首次运行，生成本机证书、账号配置和演示文件：

```sh
./setup_demo.command
```

终端一启动服务端并保持运行：

```sh
./launch_server.command
```

终端二启动客户端，再点击“连接”：

```sh
./launch_client.command
```

默认连接 `localhost:9444`，身份为 alice。服务端未启动时会出现连接被拒绝。

另一用户可在独立客户端中连接：

```sh
./launch_client.command --config runtime/bob.json
```

alice 默认限速 256 KiB/s、配额 64 MiB；bob 默认限速 1 MiB/s、配额 128 MiB。两用户文件互相隔离。限速按同一账号的上传、下载及所有连接共享计算，允许有限初始突发。

## 操作

选择本地文件上传，完成后刷新远端列表；选择远端文件下载到新的本地目录。任务支持暂停、继续或重试、取消并清理，默认四个工作连接并行传输。已有同名不同内容的文件不会被覆盖。

暂停保留断点，取消只清理具有匹配归属记录的下载临时文件。若已有不属于当前下载的 `.part` 或清单文件，程序会保留它们并报错，应更换目标路径。证书、文件内容或续传前缀不一致时不会关闭校验来强行继续。

## 验证与命令行

以下命令按需分别执行：

```sh
./launch_client.command --check-runtime
/usr/bin/python3 scripts/selftest.py
/usr/bin/python3 scripts/benchmark.py
/usr/bin/python3 scripts/verify_sandbox.py
/usr/bin/python3 client_cli.py --config runtime/alice.json list
/usr/bin/python3 client_cli.py --config runtime/alice.json ping --count 3
```

支持自定义服务端配置：

```sh
./launch_server.command --config /配置文件路径/server.json --port 9444
```

Mac 上默认使用进程沙箱。`runtime/` 中的私钥、配置和实际文件仅供本机使用，不提交到 Git；初始化不会覆盖已有数据。测试记录位于 `evidence/`，报告位于 `output/pdf/`。

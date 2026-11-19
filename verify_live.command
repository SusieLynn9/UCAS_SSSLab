#!/bin/zsh
set -e
cd "$(dirname "$0")"
print '仅抓取本脚本创建的回环 HTTP 服务端口，不捕获其他网络流量。'
/usr/bin/sudo /usr/bin/python3 scripts/verify_live.py
print '真实抓包验证结束。请保留上方输出用于实验报告。'

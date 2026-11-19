#!/bin/zsh
set -e
cd "$(dirname "$0")"
print 'Prism · 1A 嗅探器'
print '实时抓包需要 BPF 权限；密码由系统 sudo 验证，程序不读取或保存密码。'
/usr/bin/sudo -v
exec /usr/bin/python3 run.py "$@"

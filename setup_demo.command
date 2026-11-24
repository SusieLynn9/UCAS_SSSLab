#!/bin/zsh
set -e
cd -- "${0:A:h}"
if [[ -f runtime/server.json ]]; then
  print '已有本机配置，保留现有证书和文件。'
elif [[ -e runtime ]]; then
  print 'runtime 已存在但配置不完整。请先备份检查，或使用 init_demo.py --output 指定新目录。'
  exit 1
else
  /usr/bin/python3 -m scripts.init_demo --output runtime
fi
print '初始化完成。终端一运行 ./launch_server.command，终端二运行 ./launch_client.command。'

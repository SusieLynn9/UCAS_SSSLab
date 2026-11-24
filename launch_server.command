#!/bin/zsh
set -e
cd -- "${0:A:h}"
if [[ -x /usr/bin/sandbox-exec ]]; then
  exec ./launch_server_sandboxed.command "$@"
fi
print '提示：此系统未启用 Mac 进程沙箱，请使用独立低权限服务账户部署。'
exec /usr/bin/python3 run_server.py "$@"

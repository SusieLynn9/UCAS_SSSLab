#!/bin/zsh
set -e
cd -- "${0:A:h}"
if [[ ! -x /usr/bin/sandbox-exec ]]; then
  print '此环境没有 sandbox-exec。请按报告的低权限账户部署说明运行，并如实记录未进行进程沙箱验证。'
  exit 1
fi
/usr/bin/python3 -B scripts/sandbox_profile.py --config runtime/server.json --output output/server.sb
python_binary=$(/usr/bin/python3 -c 'import sys; print(sys.executable)')
exec /usr/bin/sandbox-exec -f output/server.sb "$python_binary" -B run_server.py --config runtime/server.json "$@"

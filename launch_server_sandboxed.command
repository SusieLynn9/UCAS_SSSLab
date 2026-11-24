#!/bin/zsh
set -e
cd -- "${0:A:h}"
if [[ ! -x /usr/bin/sandbox-exec ]]; then
  print '此环境没有 sandbox-exec。请按报告的低权限账户部署说明运行，并如实记录未进行进程沙箱验证。'
  exit 1
fi
server_config=runtime/server.json
args=("$@")
for (( i=1; i<=${#args}; i++ )); do
  if [[ "${args[i]}" == --config ]]; then
    if (( i == ${#args} )); then
      print -u2 '--config 需要配置文件路径。'
      exit 2
    fi
    (( i += 1 ))
    server_config="${args[i]}"
  elif [[ "${args[i]}" == --config=* ]]; then
    server_config="${args[i]#--config=}"
  fi
done
/usr/bin/python3 -B scripts/sandbox_profile.py --config "$server_config" --output output/server.sb
python_binary=$(/usr/bin/python3 -c 'import sys; print(sys.executable)')
exec /usr/bin/sandbox-exec -f output/server.sb "$python_binary" -B run_server.py --config runtime/server.json "$@"

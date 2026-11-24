#!/bin/zsh
# Prefer a supported Tk runtime; Apple's Tk 8.5 can display an empty window.
cd -- "${0:A:h}" || exit 1
python_bin=''
for candidate in .venv/bin/python /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import tkinter,sys;sys.exit(0 if tkinter.TkVersion>=8.6 else 1)' >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done
if [[ -z "$python_bin" ]]; then
  print '没有找到 Tk 8.6 或更新版本。Mac 自带 Tk 8.5 不受支持，可能出现灰色空白窗口。'
  print '现有 Homebrew Python 3.15 可安装：brew install python-tk@3.15'
  print '也可使用 python.org 自带现代 Tk 的 Python 安装程序。'
  exit 1
fi
"$python_bin" run_client.py "$@"
result=$?
if (( result != 0 )); then
  print '\n客户端未能启动，请查看上方错误信息。'
fi
exit $result

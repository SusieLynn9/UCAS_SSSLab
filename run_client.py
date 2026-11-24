#!/usr/bin/env python3
"""Launch the Harbor native client."""
import argparse
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description='Harbor 安全文件传输客户端')
    default = Path(__file__).resolve().parent / 'runtime' / 'alice.json'
    parser.add_argument('--config', type=Path, default=default if default.is_file() else None,
                        help='客户端 JSON 配置文件（含 CA、客户端证书和私钥路径）')
    parser.add_argument('--workers', type=int, default=4, choices=range(1, 9), metavar='1..8',
                        help='持久传输连接数，默认 4')
    parser.add_argument('--check-runtime', action='store_true', help='检查 Python/Tk 兼容性，不打开窗口')
    args = parser.parse_args()
    try:
        import tkinter
        if tkinter.TkVersion < 8.6:
            raise RuntimeError('Tk 8.5 不受支持，可能出现灰色空白窗口。请使用现代 Tk（Homebrew: brew install python-tk@3.15），再用 launch_client.command 启动。')
        if args.check_runtime:
            print('Python: %s | Tk: %s | Tcl: %s' % (sys.executable, tkinter.TkVersion, tkinter.TclVersion))
            return 0
        from harbor.gui import main as run_gui
        run_gui(config_path=args.config, workers=args.workers)
    except ImportError as exc:
        print('客户端无法启动：%s。请使用带 Tkinter 的 Python 3.9 或更新版本。' % exc, file=sys.stderr)
        return 1
    except Exception as exc:
        # macOS Finder launches may otherwise hide startup errors completely.
        print('客户端启动失败：%s' % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -eq 0 ] && [ ! -t 0 ] && [ ! -p /dev/stdin ] && [ -z "${KCONC_HAS_TERMINAL:-}" ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
    export KCONC_HAS_TERMINAL=1
    for term in xdg-terminal-exec x-terminal-emulator gnome-terminal konsole xfce4-terminal xterm; do
        command -v "$term" >/dev/null 2>&1 || continue
        case "$term" in
            xdg-terminal-exec) set -- "$root/start.sh" ;;
            gnome-terminal) set -- -- "$root/start.sh" ;;
            xfce4-terminal) set -- -x "$root/start.sh" ;;
            *) set -- -e "$root/start.sh" ;;
        esac
        if "$term" "$@"; then exit 0; fi
    done
    echo "无法启动图形终端，请在此目录打开终端并运行 ./start.sh。" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    offline=0
    install=0
    for option in "$@"; do
        case "$option" in --offline) offline=1 ;; --install-deps) install=1 ;; esac
    done
    if [ "$offline" -eq 1 ] || ! command -v apt-get >/dev/null 2>&1; then
        echo '菜单需要 Python 3。请在受支持的 Debian 或 Ubuntu 主机上准备 python3。' >&2
        exit 2
    fi
    if [ "$install" -eq 0 ] && [ -t 0 ]; then
        printf '菜单需要 Python 3，允许通过 apt 安装后继续？[Y/n] '
        read -r answer
        case "$answer" in
            ""|[Yy]|[Yy][Ee][Ss]) install=1 ;;
        esac
    fi
    if [ "$install" -eq 0 ]; then
        echo '缺少 Python 3。可在终端允许安装，或使用 --install-deps。' >&2
        exit 2
    fi
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update
        apt-get install -y python3
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y python3
    else
        echo '安装 Python 3 需要管理员权限。' >&2
        exit 2
    fi
    command -v python3 >/dev/null 2>&1 || { echo '安装后仍未找到 python3。' >&2; exit 2; }
fi
exec python3 -B "$root/scripts/teacher/start.py" "$@"

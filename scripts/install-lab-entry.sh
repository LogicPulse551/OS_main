#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="${LAB_DIR:-$HOME/os-concurrency-lab}"
umask 077
mkdir -p "$LAB_DIR/bin"
install -m 755 "$REPO_DIR/实验环境/openeuler-x86_64/lab.py" "$LAB_DIR/bin/lab"
printf 'Installed lab entry: %s/bin/lab\n' "$LAB_DIR"

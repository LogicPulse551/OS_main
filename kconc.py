#!/usr/bin/env python3
"""Load this checkout's command package so scripts and adapters share a version."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from kconc.cli import main

if __name__ == '__main__':
    raise SystemExit(main())

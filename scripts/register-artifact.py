#!/usr/bin/env python3
"""Register a supported build receipt, or explicitly record an absent variant."""
import argparse
import json
from pathlib import Path
import sys
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
from kconc.artifacts import from_receipt, missing


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receipt', type=Path)
    p.add_argument('--parent', type=Path)
    p.add_argument('--missing', choices=['repaired','optimized'])
    p.add_argument('--purpose', choices=['detection','performance'])
    p.add_argument('--family')
    p.add_argument('--reason')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    if out.is_relative_to(REPO) or out.exists():
        p.error('identity output must be a new file outside the repository')
    if bool(a.receipt) == bool(a.missing):
        p.error('choose exactly one of --receipt or --missing')
    if a.receipt and any(x is not None for x in [a.purpose,a.family,a.reason]):
        p.error('generated purpose/family/variant come from the build receipt')
    value = from_receipt(a.receipt,a.parent) if a.receipt else missing(a.missing,a.purpose,a.family,a.reason,a.parent)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x',encoding='utf-8') as f:
        json.dump(value,f,indent=2)
    print(json.dumps(dict(path=str(out),identity_id=value['identity_id'],status=value['status'])))


if __name__ == '__main__':
    main()

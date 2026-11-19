#!/usr/bin/env python3
"""Fetch or verify the immutable source revisions used by the MAccConc lab."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
LOCK = REPO / 'configs/maccconc.lock.json'


def git(directory, *args, check=True):
    result = subprocess.run(['git', '-C', str(directory), *args],
                            capture_output=True, text=True,
                            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
    if check and result.returncode:
        raise RuntimeError(f'git {args[0]} failed: {result.stderr.strip()}')
    return result


def load_lock():
    data = json.loads(LOCK.read_text(encoding='utf-8'))
    if data['schema_version'] != 1:
        raise ValueError('Unsupported source lock format')
    for spec in data['sources'].values():
        if not re.fullmatch(r'[0-9a-f]{40}', spec['commit']):
            raise ValueError('A full immutable commit SHA is required')
        if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?', spec['url']):
            raise ValueError('Unexpected upstream repository URL')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', spec['directory']):
            raise ValueError('Invalid source directory')
    return data


def inspect_checkout(path, spec, allow_unborn=False):
    if not (path / '.git').exists():
        raise RuntimeError(f'Not a managed Git checkout: {path}')
    top = Path(git(path, 'rev-parse', '--show-toplevel').stdout.strip()).resolve()
    if top != path.resolve():
        raise RuntimeError(f'Unexpected Git root: {top}')
    if git(path, 'config', '--get', 'remote.origin.url').stdout.strip() != spec['url']:
        raise RuntimeError(f'Origin differs from the lock: {path}')
    if git(path, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise RuntimeError(f'Refusing a dirty source checkout: {path}')
    head = git(path, 'rev-parse', '--verify', 'HEAD', check=False)
    if head.returncode:
        if allow_unborn and not any(p.name != '.git' for p in path.iterdir()):
            return False
        raise RuntimeError(f'Missing source revision: {path}')
    if head.stdout.strip() != spec['commit']:
        raise RuntimeError(f'HEAD differs from the lock; existing files are preserved: {path}')
    return True


def verify(path, spec):
    inspect_checkout(path, spec)
    for filename, expected in spec.get('git_blobs', {}).items():
        if git(path, 'rev-parse', f'HEAD:{filename}').stdout.strip() != expected:
            raise RuntimeError(f'Locked blob differs: {filename}')
    for sub in spec.get('submodules', []):
        entry = git(path, 'ls-tree', 'HEAD', '--', sub['path']).stdout
        if not entry.startswith('160000 commit ' + sub['commit'] + '\t'):
            raise RuntimeError(f'Submodule gitlink differs: {sub["path"]}')
        inspect_checkout(path / sub['path'], sub)
    return {'directory': str(path), 'commit': spec['commit'],
            'clean': True, 'submodules_verified': len(spec.get('submodules', []))}


def fetch(path, spec):
    if not path.exists():
        path.mkdir(parents=True)
        git(path, 'init', '--quiet')
        git(path, 'remote', 'add', 'origin', spec['url'])
    present = inspect_checkout(path, spec, allow_unborn=True)
    if not present:
        git(path, 'fetch', '--depth=1', 'origin', spec['commit'])
        git(path, 'checkout', '--detach', spec['commit'])
    for sub in spec.get('submodules', []):
        subpath = path / sub['path']
        if (subpath / '.git').exists():
            inspect_checkout(subpath, sub)
        elif subpath.exists() and any(subpath.iterdir()):
            raise RuntimeError(f'Refusing nonempty submodule destination: {subpath}')
        git(path, 'submodule', 'update', '--init', '--depth=1', '--', sub['path'])
    return verify(path, spec)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'fetch', 'verify'])
    parser.add_argument('--component', choices=['maccconc', 'linux', 'llvm', 'all'], default='maccconc')
    lab = Path(os.environ.get('LAB_DIR', str(Path.home() / 'os-concurrency-lab')))
    parser.add_argument('--source-root', type=Path, default=lab / 'sources/k01')
    args = parser.parse_args()
    lock = load_lock()
    root = args.source_root.expanduser().resolve()
    if root.is_relative_to(REPO) or REPO.is_relative_to(root):
        raise ValueError('Source cache must be outside the delivery repository and its ancestors')
    selected = list(lock['sources']) if args.component == 'all' else [args.component]
    result = {}
    for name in selected:
        spec = lock['sources'][name]
        destination = (root / spec['directory']).resolve()
        if not destination.is_relative_to(root):
            raise ValueError('Source destination escapes source root')
        print(f'{args.command}: {name} {spec["commit"]}', file=sys.stderr, flush=True)
        if args.command == 'plan':
            result[name] = {'directory': str(destination), **spec}
        else:
            result[name] = (fetch if args.command == 'fetch' else verify)(destination, spec)
    print(json.dumps({'action': args.command, 'components': result}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)

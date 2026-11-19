#!/usr/bin/env python3
"""Create an independent K02 overlay from a stopped baseline; never modify its disks."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def command(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr.strip()}')
    return result.stdout


def require_regular(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'Expected a regular, non-symlink file: {path}')


def require_stopped(source):
    qmp_path = source / 'run/qmp.sock'
    if qmp_path.exists():
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(1)
            try:
                client.connect(str(qmp_path))
            except (ConnectionRefusedError, FileNotFoundError):
                pass
            else:
                raise RuntimeError('Baseline QMP is alive; stop the baseline before copying.')
    pid_file = source / 'run/qemu.pid'
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            process = Path(f'/proc/{pid}/cmdline')
            if process.exists() and b'qemu' in process.read_bytes():
                raise RuntimeError('Baseline PID still identifies QEMU; refusing offline copy.')
        except ValueError:
            raise RuntimeError('Invalid baseline PID file; inspect it before copying.')
    disk = source / 'images/experiment.qcow2'
    disk_text = str(disk).encode()
    qmp_text = str(qmp_path).encode()
    for process in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            args = process.read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if args and b'qemu' in args[0] and any(disk_text in arg or qmp_text in arg for arg in args):
            raise RuntimeError('An active QEMU command references the baseline.')


def prepare(source, target):
    if target == source or source.is_relative_to(target):
        raise RuntimeError('Target must not be the source or one of its ancestors.')
    if target.is_relative_to(REPO) or REPO.is_relative_to(target):
        raise RuntimeError('VM files must be outside the delivery repository and its ancestors.')
    if target.exists():
        raise RuntimeError('Target already exists; no files will be overwritten.')
    disk = source / 'images/experiment.qcow2'
    seed = source / 'seed/seed.img'
    key = source / 'keys/id_ed25519'
    stop_record = source / 'evidence/last-stop.json'
    for file in (disk, seed, key, stop_record):
        require_regular(file)
    control = source / 'run/control.lock'
    if not control.parent.is_dir():
        raise RuntimeError('Missing baseline lifecycle directory.')
    with control.open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A baseline lifecycle operation is active.')
        require_stopped(source)
        stopped = json.loads(stop_record.read_text())
        stat_before = disk.stat()
        if not (stopped.get('graceful_stop_observed') is True
                and stopped.get('qmp_shutdown_confirmed') is True
                and stopped.get('process_exit_observed') is True
                and stopped.get('monitor_connected_before_requests') is True
                and stopped.get('qmp_shutdown_event', {}).get('event') == 'SHUTDOWN'
                and stopped.get('qmp_shutdown_event', {}).get('data', {}).get('guest') is True
                and stopped.get('qmp_shutdown_event', {}).get('data', {}).get('reason') == 'guest-shutdown'
                and stopped.get('disk') == str(disk)
                and stopped.get('disk_size') == stat_before.st_size
                and stopped.get('disk_mtime_ns') == stat_before.st_mtime_ns):
            raise RuntimeError('No matching QMP-confirmed guest-shutdown record; use the current lab.py stop first.')
        launch_record = source / 'evidence/last-launch.json'
        if launch_record.exists():
            launched = json.loads(launch_record.read_text())
            stop_time = datetime.datetime.fromisoformat(stopped.get('time_utc', ''))
            launch_time = datetime.datetime.fromisoformat(launched['time_utc'])
            if stop_time < launch_time:
                raise RuntimeError('The stop record predates the last launch; stop the baseline again.')
        chain = json.loads(command('qemu-img', 'info', '--backing-chain', '--output=json', disk))
        if len(chain) < 2 or any(entry.get('format') != 'qcow2' for entry in chain):
            raise RuntimeError('Expected the baseline qcow2 overlay and its qcow2 backing chain.')
        backing = chain[0].get('full-backing-filename')
        stored_backing = chain[0].get('backing-filename', '')
        if not backing or not Path(backing).is_absolute() or not Path(stored_backing).is_absolute():
            raise RuntimeError('Baseline needs an absolute backing-file path before copying.')
        for entry in chain[1:]:
            parent = Path(entry['filename']).resolve()
            require_regular(parent)
            if parent.stat().st_mode & 0o222:
                raise RuntimeError(f'Backing disk is not read-only: {parent}')
        command('qemu-img', 'check', disk)
        source_hash = digest(disk)
        target.mkdir(parents=True, mode=0o700)
        for name in ('images', 'keys', 'seed', 'run', 'logs', 'evidence', 'bin'):
            (target / name).mkdir(mode=0o700)
        snapshot = target / 'images/baseline-frozen.qcow2'
        command('cp', '--reflink=auto', '--sparse=always', '--', disk, snapshot)
        copied_hash = digest(snapshot)
        if copied_hash != source_hash or digest(disk) != source_hash:
            raise RuntimeError('Baseline changed during copying; target left for inspection, not activated.')
        require_stopped(source)
        if disk.stat().st_mtime_ns != stat_before.st_mtime_ns:
            raise RuntimeError('Baseline metadata changed during copying; refusing activation.')
        snapshot.chmod(0o444)
        command('qemu-img', 'check', snapshot)
        image = target / 'images/experiment.qcow2'
        command('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', snapshot, image)
        shutil.copy2(seed, target / 'seed/seed.img')
        for name in ('id_ed25519', 'id_ed25519.pub', 'known_hosts'):
            file = source / 'keys' / name
            if file.exists():
                require_regular(file)
                shutil.copy2(file, target / 'keys' / name)
                (target / 'keys' / name).chmod(0o600)
        shutil.copy2(REPO / '实验环境/openeuler-x86_64/lab.py', target / 'bin/lab')
        (target / 'bin/lab').chmod(0o755)
        result = {
            'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_lab': str(source), 'target_lab': str(target),
            'source_stop_record': stopped, 'source_overlay_sha256': source_hash,
            'frozen_overlay_sha256': copied_hash, 'original_backing_chain': chain,
            'frozen_snapshot': str(snapshot), 'writable_overlay': str(image),
            'baseline_preserved': True,
            'note': 'Shares original read-only backing disks; do not move/delete them. No guest was started.'}
        (target / 'evidence/baseline-fork.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'target_lab': str(target), 'baseline_preserved': True,
                          'evidence': str(target / 'evidence/baseline-fork.json')}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-lab', type=Path, default=Path.home() / 'os-concurrency-lab')
    parser.add_argument('--target-lab', type=Path, default=Path.home() / 'os-concurrency-k02')
    args = parser.parse_args()
    os.umask(0o077)
    prepare(args.source_lab.expanduser().resolve(), args.target_lab.expanduser().resolve())


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)

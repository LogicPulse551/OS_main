#!/usr/bin/env python3
"""Local QEMU lifecycle. Run inside WSL Debian as the regular lab owner."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

LAB = Path(os.environ.get('LAB_DIR', str(Path.home() / 'os-concurrency-lab'))).resolve()
RUN = LAB / 'run'
PORT = int(os.environ.get('LAB_SSH_PORT', '2222'))

def optional_resources():
    """Validate opt-in experimental resources without changing stock defaults."""
    try:
        memory = int(os.environ.get('LAB_MEMORY_MIB', '4096'))
        cid_text = os.environ.get('LAB_VSOCK_CID')
        cid = int(cid_text) if cid_text is not None else None
    except ValueError:
        raise SystemExit('LAB_MEMORY_MIB and LAB_VSOCK_CID must be decimal integers.')
    if not 512 <= memory <= 1048576:
        raise SystemExit('LAB_MEMORY_MIB must be between 512 and 1048576 MiB.')
    if cid is not None:
        if not 3 <= cid < 0xffffffff:
            raise SystemExit('LAB_VSOCK_CID must be a guest CID between 3 and 4294967294.')
        if not os.access('/dev/vhost-vsock', os.R_OK | os.W_OK):
            raise SystemExit('VSOCK requested but /dev/vhost-vsock is not readable/writable.')
    return memory, cid

def qmp(command, arguments=None):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(str(RUN / 'qmp.sock'))
        f = s.makefile('rwb')
        json.loads(f.readline())
        def request(cmd, args=None):
            msg = {'execute': cmd}
            if args is not None:
                msg['arguments'] = args
            f.write(json.dumps(msg).encode() + b'\n'); f.flush()
            while True:
                item = json.loads(f.readline())
                if 'error' in item:
                    raise RuntimeError(item['error'])
                if 'return' in item:
                    return item['return']
        request('qmp_capabilities')
        return request(command, arguments)

class ShutdownMonitor:
    """Keep the same QMP connection open before and throughout poweroff."""
    def __init__(self):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.buffer = b''
        self.closed = False
        self.greeting = False
        self.events = []
        self.responses = {}
        self.next_id = 0

    def connect(self):
        self.socket.connect(str(RUN / 'qmp.sock'))
        deadline = time.monotonic() + 5
        while not self.greeting and not self.closed and time.monotonic() < deadline:
            self.poll(max(0, deadline - time.monotonic()))
        if not self.greeting:
            raise RuntimeError('No QMP greeting before shutdown request')
        self.command('qmp_capabilities')

    def poll(self, timeout=0):
        # Do not use a timed-out socket.makefile(): subsequent reads can fail.
        if self.closed or not select.select([self.socket], [], [], timeout)[0]:
            return False
        data = self.socket.recv(65536)
        if not data:
            self.closed = True
            return False
        self.buffer += data
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            if not line.strip():
                continue
            message = json.loads(line)
            if 'QMP' in message:
                self.greeting = True
            elif 'event' in message:
                self.events.append(message)
            elif 'id' in message:
                self.responses[message['id']] = message
        return True

    def command(self, name):
        self.next_id += 1
        request_id = self.next_id
        self.socket.sendall(json.dumps({'execute': name, 'id': request_id}).encode() + b'\n')
        deadline = time.monotonic() + 5
        while request_id not in self.responses and not self.closed and time.monotonic() < deadline:
            self.poll(max(0, deadline - time.monotonic()))
        reply = self.responses.pop(request_id, None)
        if reply is None or 'return' not in reply:
            raise RuntimeError(f'QMP {name} was not acknowledged: {reply}')
        return reply['return']

    def close(self):
        self.socket.close()

def guest_shutdown_event(events):
    return next((event for event in events
                 if event.get('event') == 'SHUTDOWN'
                 and event.get('data', {}).get('guest') is True
                 and event.get('data', {}).get('reason') == 'guest-shutdown'), None)

def running():
    try:
        return qmp('query-status')
    except (OSError, ValueError, RuntimeError):
        return None

def process_alive():
    try:
        pid = int((RUN/'qemu.pid').read_text().strip())
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        return any(str(RUN/'qmp.sock').encode() in arg for arg in cmdline)
    except (OSError, ValueError):
        return False

def ssh_args():
    return ['ssh', '-i', str(LAB/'keys/id_ed25519'), '-p', str(PORT),
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile='+str(LAB/'keys/known_hosts'), 'lab@127.0.0.1']

def start():
    if running():
        print('Already running.'); return
    if process_alive():
        raise SystemExit('QEMU is alive but QMP is unavailable; refusing to replace its control files.')
    disk = LAB / 'images/experiment.qcow2'
    if not disk.exists():
        raise SystemExit('Run prepare.sh first.')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('KVM permission missing; reopen Debian after joining the kvm group.')
    memory, vsock_cid = optional_resources()
    RUN.mkdir(parents=True, exist_ok=True)
    (LAB/'logs').mkdir(exist_ok=True)
    (LAB/'evidence').mkdir(exist_ok=True)
    for name in ('qmp.sock', 'serial.sock', 'qemu.pid'):
        (RUN/name).unlink(missing_ok=True)
    args = ['qemu-system-x86_64', '-name', 'oe-kernel-lab',
            '-accel', 'kvm', '-cpu', 'host', '-smp', '4', '-m', str(memory),
            '-drive', f'file={disk},format=qcow2,if=virtio',
            '-drive', f'file={LAB}/seed/seed.img,format=raw,if=virtio,readonly=on',
            '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{PORT}-:22',
            '-device', 'virtio-net-pci,netdev=n0',
            '-device', 'virtio-rng-pci', '-display', 'none',
            '-chardev', f'socket,id=ser0,path={RUN}/serial.sock,server=on,wait=off,logfile={LAB}/logs/serial.log',
            '-serial', 'chardev:ser0',
            '-qmp', f'unix:{RUN}/qmp.sock,server=on,wait=off',
            '-pidfile', str(RUN/'qemu.pid'), '-daemonize']
    if vsock_cid is not None:
        args += ['-device', f'vhost-vsock-pci,guest-cid={vsock_cid}']
    # Optional direct boot is reserved for a separately built experimental kernel.
    kernel = os.environ.get('LAB_KERNEL')
    kernel_artifact = None
    if kernel:
        kernel_path = Path(kernel).resolve(strict=True)
        with kernel_path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        kernel_artifact = {'path': str(kernel_path), 'sha256_before_launch': digest,
                           'bytes': kernel_path.stat().st_size}
        args += ['-kernel', str(kernel_path), '-append',
                 os.environ.get('LAB_APPEND', 'root=/dev/vda2 rw console=ttyS0')]
        if os.environ.get('LAB_INITRD'):
            args += ['-initrd', str(Path(os.environ['LAB_INITRD']).resolve())]
    subprocess.run(args, check=True)
    if kernel_artifact:
        with kernel_path.open('rb') as stream:
            kernel_artifact['sha256_after_launch'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    (LAB/'evidence/last-launch.json').write_text(json.dumps({
        'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'command': args, 'kernel_artifact': kernel_artifact}, indent=2)+'\n')
    print(json.dumps({'vm': qmp('query-status'), 'kvm': qmp('query-kvm'),
                      'ssh': f'127.0.0.1:{PORT}'}, indent=2))

def stop():
    if not process_alive() and not running():
        print('Already stopped.'); return
    record = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'graceful_stop_observed': False, 'qmp_shutdown_confirmed': False,
              'process_exit_observed': False, 'monitor_connected_before_requests': False,
              'method': 'persistent QMP guest-shutdown confirmation; SSH poweroff with ACPI fallback',
              'requests': [], 'errors': []}
    monitor = None
    try:
        monitor = ShutdownMonitor()
        monitor.connect()
        record['monitor_connected_before_requests'] = True
        deadline = time.monotonic() + 60
        command = ssh_args() + ['sudo', '-n', 'systemctl', 'poweroff']
        try:
            response = subprocess.run(command, capture_output=True, text=True, timeout=15)
            record['requests'].append({'command': command, 'exit_code': response.returncode,
                                       'stdout': response.stdout, 'stderr': response.stderr})
        except subprocess.TimeoutExpired:
            record['requests'].append({'command': command, 'exit_code': None, 'timeout_seconds': 15})
        while monitor.poll(0):
            pass
        if process_alive() and guest_shutdown_event(monitor.events) is None:
            try:
                response = monitor.command('system_powerdown')
                record['requests'].append({'qmp': 'system_powerdown', 'acknowledged': True,
                                           'response': response})
            except (OSError, ValueError, RuntimeError) as error:
                record['requests'].append({'qmp': 'system_powerdown', 'acknowledged': False,
                                           'error': str(error)})
        while time.monotonic() < deadline:
            if not process_alive():
                # Drain messages queued before QEMU exited, including SHUTDOWN.
                while monitor.poll(0):
                    pass
                record['process_exit_observed'] = True
                break
            if monitor.closed:
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            else:
                monitor.poll(min(1, max(0, deadline - time.monotonic())))
    except (OSError, ValueError, RuntimeError) as error:
        record['errors'].append(str(error))
    finally:
        record['qmp_events'] = monitor.events if monitor else []
        record['qmp_shutdown_event'] = guest_shutdown_event(record['qmp_events'])
        record['qmp_shutdown_confirmed'] = bool(record['monitor_connected_before_requests']
            and record['process_exit_observed'] and record['qmp_shutdown_event'] is not None)
        record['graceful_stop_observed'] = record['qmp_shutdown_confirmed']
        if monitor:
            monitor.close()
        disk = LAB / 'images/experiment.qcow2'
        record['disk'] = str(disk)
        try:
            stat = disk.stat()
            record.update(disk_size=stat.st_size, disk_mtime_ns=stat.st_mtime_ns)
        except OSError as error:
            record['errors'].append(str(error))
            record['graceful_stop_observed'] = False
        finished = datetime.datetime.now(datetime.timezone.utc)
        record['time_utc'] = finished.isoformat()
        evidence = LAB / 'evidence'
        evidence.mkdir(exist_ok=True)
        payload = json.dumps(record, indent=2) + '\n'
        (evidence / ('stop-' + finished.strftime('%Y%m%dT%H%M%S.%fZ') + '.json')).write_text(payload)
        (evidence / 'last-stop.json').write_text(payload)
    if record['graceful_stop_observed']:
        print('Stopped cleanly; QMP guest-shutdown and process exit confirmed.'); return
    if record['process_exit_observed']:
        raise SystemExit('QEMU exited without confirmed guest-shutdown; snapshot creation remains blocked. See last-stop.json.')
    raise SystemExit('Shutdown was not confirmed; no process was force-killed. See last-stop.json.')

def status():
    state = running()
    result = {'lab_dir': str(LAB),
              'state': state or ('alive-qmp-unavailable' if process_alive() else 'stopped'),
              'ssh_port': PORT}
    if state:
        result.update(kvm=qmp('query-kvm'), cpus=len(qmp('query-cpus-fast')))
    print(json.dumps(result, indent=2))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command', choices=['start','stop','status','ssh'])
    parser.add_argument('args', nargs=argparse.REMAINDER)
    ns=parser.parse_args()
    os.umask(0o077)
    if ns.command == 'ssh':
        os.execvp('ssh', ssh_args()+ns.args)
    if ns.command == 'status':
        status(); return
    RUN.mkdir(parents=True, exist_ok=True)
    with (RUN/'control.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Another lifecycle operation is active.')
        {'start': start, 'stop': stop}[ns.command]()

if __name__ == '__main__':
    main()

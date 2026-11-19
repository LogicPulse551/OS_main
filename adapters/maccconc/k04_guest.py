#!/usr/bin/env python3
"""Root guest supervisor for one K04 run; process cleanup is not kernel reset."""
from __future__ import annotations

import argparse
import ctypes
import datetime
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path('/home/lab/k04')
# None follows ROOT at validation time so adapters retain their own build root.
# An adapter may explicitly add build roots without changing run/plan roots.
BUILD_ROOTS = None
FAULTS = {'none', 'setup', 'hang', 'cleanup', 'property'}
PHASES = {'setup', 'initial_state', 'operations', 'property', 'teardown'}
MAX_REQUEST = 65536
MAX_PHASE_LOG = 8 * 1024 * 1024


class GuestError(ValueError):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuestError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise GuestError('Non-finite JSON value')
    return value


def _constant(text):
    raise GuestError('Non-finite JSON value: ' + text)


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant)


def _path(value):
    if not isinstance(value, str) or not value or '\0' in value:
        raise GuestError('Expected a nonempty path string')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or str(path) != value:
        raise GuestError('Paths must be absolute and normalized')
    return path


def _no_symlinks(path):
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise GuestError('Symlink is not allowed: ' + str(part))


def _regular(path, *, private=False):
    _no_symlinks(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise GuestError('Expected a regular file: ' + str(path))
    if private and (info.st_uid != 0 or info.st_mode & 0o022):
        raise GuestError('Request/plan must be root-owned and not writable by group or others')
    return info


def _read_regular(path, limit, *, private=False):
    _regular(path, private=private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise GuestError('Expected a bounded regular file: ' + str(path))
        if private and (info.st_uid != 0 or info.st_mode & 0o022):
            raise GuestError('Request ownership changed')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise GuestError('File exceeded its size limit')
    return data


def load_request(request_path):
    """Validate the entire fixed request before starting or signalling anything."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise GuestError('Run this supervisor as root inside the Linux experimental guest')
    request_path = _path(str(request_path))
    directory = request_path.parent
    if request_path.name != 'request.json' or directory.parent != ROOT or not re.fullmatch(r'run-[0-9a-f]{32}', directory.name):
        raise GuestError('Request must be /home/lab/k04/run-<32 lowercase hex>/request.json')
    _no_symlinks(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise GuestError('Run directory must be root-owned with private permissions')
    value = parse_json(_read_regular(request_path, MAX_REQUEST, private=True).decode('utf-8'))
    fields = {'run_id', 'executable', 'scenario_library', 'plan_path', 'timeout_seconds', 'fault'}
    if not isinstance(value, dict) or set(value) != fields:
        raise GuestError('Request must contain exactly: ' + ', '.join(sorted(fields)))
    if value['run_id'] != directory.name[4:]:
        raise GuestError('run_id differs from directory identity')
    if type(value['timeout_seconds']) is not int or not 1 <= value['timeout_seconds'] <= 300:
        raise GuestError('timeout_seconds must be an integer between 1 and 300')
    if not isinstance(value['fault'], str) or value['fault'] not in FAULTS:
        raise GuestError('Unknown native-wrapper fault')
    build_roots = {ROOT} if BUILD_ROOTS is None else BUILD_ROOTS
    for field in ('executable', 'scenario_library'):
        path = _path(value[field])
        if path.parent.name != 'bin' or path.parent.parent.parent not in build_roots or not re.fullmatch(r'build-[A-Za-z0-9._-]+', path.parent.parent.name):
            raise GuestError(field + ' must be in an allowed build-*/bin directory')
        _regular(path)
        if field == 'executable' and not os.access(path, os.X_OK):
            raise GuestError('Executable permission is missing')
    if value['plan_path'] is not None:
        plan = _path(value['plan_path'])
        if plan.parent != directory:
            raise GuestError('Plan must be a direct file in this run directory')
        _regular(plan, private=True)
    return request_path, value


def save(path, value):
    """Durable record replacement, with a unique private temporary file."""
    if path.is_symlink():
        raise GuestError('Refuse to replace a symlink record')
    temporary = path.parent / ('.' + path.name + '-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def process_info(pid):
    """Read Linux stat without splitting a parenthesized comm on spaces."""
    text = Path('/proc', str(pid), 'stat').read_text()
    fields = text.rsplit(') ', 1)[1].split()
    return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
            'pgid': int(fields[2]), 'session_id': int(fields[3]), 'starttime': int(fields[19])}


def group_members(pgid):
    members = []
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            item = process_info(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        if item['pgid'] == pgid:
            members.append(item)
    return sorted(members, key=lambda item: item['pid'])


def remaining_members(leader_pid):
    """Include adopted escapees; never pretend a changed process group is clean.

    This dedicated supervisor starts exactly one direct child. After subreaper
    adoption, any other direct child belongs to that run, even if it used setsid.
    Such an escapee is reported but is not signalled as part of the original group.
    """
    members = {item['pid']: item for item in group_members(leader_pid)}
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            item = process_info(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        if item['pid'] != leader_pid and item['ppid'] == os.getpid():
            item['adopted_by_supervisor'] = True
            members[item['pid']] = item
    return sorted(members.values(), key=lambda item: item['pid'])


def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    if result != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')
    return True


def reap_adopted(leader_pid):
    """Do not steal Popen's direct-child wait status."""
    reaped = []
    for entry in Path('/proc').glob('[0-9]*'):
        pid = int(entry.name)
        if pid == leader_pid:
            continue
        try:
            info = process_info(pid)
            if info['ppid'] != os.getpid():
                continue
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                reaped.append({'pid': waited, 'wait_status': status})
        except (FileNotFoundError, ProcessLookupError, ChildProcessError):
            pass
    return reaped


def terminate_group(process, identity, *, grace=2.0):
    """Signal only the session/process group created by this supervisor."""
    record = {'attempted': True, 'signals': [], 'errors': [], 'reaped': []}
    pgid = identity['pgid']
    for sig in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        record['reaped'].extend(reap_adopted(process.pid))
        members = group_members(pgid)
        if not members:
            break
        if any(item['session_id'] != process.pid for item in members):
            record['errors'].append('Process group session identity differs; refusing signal')
            break
        leaders = [item for item in members if item['pid'] == process.pid]
        if leaders and leaders[0]['starttime'] != identity['starttime']:
            record['errors'].append('Leader starttime changed; refusing reused PID')
            break
        try:
            os.killpg(pgid, sig)
            record['signals'].append(int(sig))
        except ProcessLookupError:
            pass
        except OSError as error:
            record['errors'].append(str(error))
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()
            record['reaped'].extend(reap_adopted(process.pid))
            if not group_members(pgid):
                break
            time.sleep(.025)
    process.poll()
    record['reaped'].extend(reap_adopted(process.pid))
    record['remaining_members'] = remaining_members(process.pid)
    record['remaining_pids'] = [item['pid'] for item in record['remaining_members']]
    record['confirmed'] = not record['errors'] and not record['remaining_pids'] and process.returncode is not None
    return record


def parse_phases(directory, replay):
    path = directory / 'trace' / ('testcase.stdout.txt' if replay else 'baseline/testcase.stdout.txt')
    phases, errors = [], []
    try:
        lines = _read_regular(path, MAX_PHASE_LOG).decode('utf-8', errors='strict').splitlines()
    except (OSError, ValueError) as error:
        return phases, ['Phase log unavailable: ' + str(error)]
    seen = set()
    for number, line in enumerate(lines, 1):
        if not line.startswith('KCONC_PHASE '):
            continue
        if len(phases) >= 32:
            errors.append('Too many phase records')
            break
        try:
            value = parse_json(line[len('KCONC_PHASE '):])
            if not isinstance(value, dict) or value.get('phase') not in PHASES or type(value.get('passed')) is not bool:
                raise GuestError('Unknown phase or non-boolean passed')
            if value['phase'] in seen:
                raise GuestError('Duplicate phase: ' + value['phase'])
            seen.add(value['phase'])
            phases.append(value)
        except (ValueError, TypeError) as error:
            errors.append(f'Line {number}: {error}')
    return phases, errors


def _cancelled(directory, run_id):
    path = directory / 'cancel.json'
    if not path.exists() and not path.is_symlink():
        return False
    value = parse_json(_read_regular(path, MAX_REQUEST, private=True).decode())
    if not isinstance(value, dict) or value.get('run_id') != run_id or value.get('cancel') is not True:
        raise GuestError('Cancel record does not match this run')
    return True


def command_for_request(request, directory):
    command = [request['executable'], request['scenario_library']]
    if request['plan_path'] is not None:
        return command + ['--k03-replay', request['plan_path'], str(directory / 'trace')]
    return command + ['--k03-record', str(directory / 'trace')]


def supervise(request_path):
    """Run once; the host must separately decide whether kernel state is reusable."""
    import fcntl
    request_path, request = load_request(request_path)
    directory = request_path.parent
    lock_fd = os.open(directory / 'supervisor.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GuestError('A supervisor already owns this run') from error
        if any((directory / name).exists() or (directory / name).is_symlink()
               for name in ('guest-state.json', 'guest-result.json', 'trace', 'executor.stdout.txt', 'executor.stderr.txt')):
            raise GuestError('This run has already started; use a new run directory')
        replay = request['plan_path'] is not None
        command = command_for_request(request, directory)
        result = {'schema_version': 1, 'kind': 'kconc.guest', 'run_id': request['run_id'],
                  'outcome': 'execution_failed', 'exit_code': None, 'started_utc': now(), 'finished_utc': None,
                  'command': command, 'fault': request['fault'], 'process': None,
                  'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'remaining_pids': [], 'local_cleanup': {'attempted': False, 'confirmed': True, 'errors': []},
                  'cancel_requested': False, 'timed_out': False, 'phases': [], 'phase_errors': [], 'error': None,
                  'scope': 'One supervised executor; process cleanup is not kernel state reset. Record mode only parses baseline phases.'}
        process, identity = None, None
        try:
            result['subreaper_enabled'] = subreaper()
            save(directory / 'guest-state.json', dict(result, state='prepared'))
            if _cancelled(directory, request['run_id']):
                result.update(outcome='cancelled', cancel_requested=True)
            else:
                env = os.environ.copy()
                env['KCONC_FAULT'] = request['fault']
                with (directory / 'executor.stdout.txt').open('xb') as stdout, (directory / 'executor.stderr.txt').open('xb') as stderr:
                    deadline = time.monotonic() + request['timeout_seconds']
                    process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                               stdout=stdout, stderr=stderr, start_new_session=True)
                    identity = process_info(process.pid)
                    if identity['pgid'] != process.pid or identity['session_id'] != process.pid:
                        raise GuestError('Executor did not enter its own process group and session')
                    result['process'] = dict(identity, boot_id=result['boot_id'])
                    save(directory / 'guest-state.json', dict(result, state='running'))
                    while process.poll() is None:
                        if _cancelled(directory, request['run_id']):
                            result.update(outcome='cancelled', cancel_requested=True)
                            break
                        if time.monotonic() >= deadline:
                            result.update(outcome='timeout', timed_out=True)
                            break
                        time.sleep(.05)
                    if result['cancel_requested'] or result['timed_out']:
                        result['local_cleanup'] = terminate_group(process, identity)
                    else:
                        reap_adopted(process.pid)
                        remaining = remaining_members(process.pid)
                        if remaining:
                            result['error'] = {'type': 'ResidualProcesses', 'message': 'Executor exited while descendants remained'}
                            result['local_cleanup'] = terminate_group(process, identity)
                        elif process.returncode == 0:
                            result['outcome'] = 'completed'
                    result['exit_code'] = process.poll()
        except BaseException as error:
            result['error'] = {'type': type(error).__name__, 'message': str(error)}
            if isinstance(error, KeyboardInterrupt):
                result.update(outcome='cancelled', cancel_requested=True)
            else:
                result['outcome'] = 'execution_failed'
            if process is not None:
                if identity is not None:
                    try:
                        result['local_cleanup'] = terminate_group(process, identity)
                    except Exception as cleanup_error:
                        result['local_cleanup'] = {'attempted': True, 'confirmed': False, 'errors': [str(cleanup_error)]}
                else:
                    # No verified identity means do not signal a guessed process group.
                    result['local_cleanup'] = {'attempted': False, 'confirmed': False,
                                               'errors': ['Executor identity was not captured; guest recovery required']}
                result['exit_code'] = process.poll()
        finally:
            if process is not None:
                try:
                    reap_adopted(process.pid)
                    result['remaining_members'] = remaining_members(process.pid)
                    result['remaining_pids'] = [item['pid'] for item in result['remaining_members']]
                    if result['remaining_pids'] or process.poll() is None:
                        result['local_cleanup']['confirmed'] = False
                except Exception as error:
                    result['remaining_pids'] = None
                    result['local_cleanup']['confirmed'] = False
                    result['local_cleanup']['errors'].append(str(error))
            result['phases'], result['phase_errors'] = parse_phases(directory, replay)
            result['finished_utc'] = now()
            save(directory / 'guest-result.json', result)
            save(directory / 'guest-state.json', dict(result, state='finished'))
        return result


def cancel(request_path):
    """Request cancellation without trusting a caller-supplied PID."""
    path, request = load_request(request_path)
    directory = path.parent
    if (directory / 'guest-result.json').exists():
        return {'run_id': request['run_id'], 'cancel_requested': False, 'already_finished': True}
    if not _cancelled(directory, request['run_id']):
        save(directory / 'cancel.json', {'run_id': request['run_id'], 'cancel': True, 'requested_utc': now()})
    return {'run_id': request['run_id'], 'cancel_requested': True, 'already_finished': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('run', 'cancel'))
    parser.add_argument('--request', required=True, type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        value = supervise(args.request) if args.command == 'run' else cancel(args.request)
        code = {'completed': 0, 'timeout': 124, 'cancelled': 130, 'execution_failed': 1}.get(value.get('outcome'), 0)
    except (OSError, ValueError) as error:
        value = {'schema_version': 1, 'kind': 'kconc.guest-error', 'error': {'type': type(error).__name__, 'message': str(error)}}
        code = 1
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""K03 fixed-sample control evidence. Run in Debian; all outputs outside the repo."""
import argparse
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import uuid

REPO = Path(__file__).resolve().parents[1]
TEAM = ['adapters/maccconc/k03-evidence.h', 'patches/maccconc/0002-k03-evidence.patch',
        'tests/maccconc/child-exit.c', 'scripts/build-maccconc-k03-guest.sh']
COMMIT = 'c17ba2d68167d1a892dbdec326bd6cfec32ec9f1'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


class Session:
    def __init__(self, args):
        self.args = args
        self.out = args.output.resolve()
        if self.out.is_relative_to(REPO) or REPO.is_relative_to(self.out):
            raise ValueError('Evidence must be outside the delivery repository')
        self.out.mkdir(parents=True, exist_ok=False)
        self.commands = []
        self.labdir = Path(os.environ['LAB_DIR']).resolve()
        if self.labdir == Path.home() / 'os-concurrency-lab':
            raise ValueError('Use the independent experimental VM, not the original baseline')
        self.launch = json.loads((self.labdir / 'evidence/last-launch.json').read_text())
        self.runtime = load_module('k03_runtime', REPO / 'scripts/verify-maccconc-runtime.py')
        network = self.runtime.command_option(self.launch['command'], '-netdev')
        match = re.search(r'hostfwd=tcp:127\.0\.0\.1:(\d+)-:22(?:,|$)', network)
        if not match or os.environ.get('LAB_SSH_PORT', match[1]) != match[1]:
            raise ValueError('SSH port differs from the experimental VM launch')
        os.environ['LAB_SSH_PORT'] = match[1]
        self.lab = load_module('k03_lab', REPO / '实验环境/openeuler-x86_64/lab.py')
        if not self.lab.qmp('query-status').get('running'):
            raise ValueError('Experimental VM must be running')

    def run(self, argv, *, data=None, timeout=120, check=True, binary=False):
        number = len(self.commands)
        item = {'command': list(map(str, argv)), 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        self.commands.append(item)
        try:
            p = subprocess.run(item['command'], input=data, capture_output=True, timeout=timeout)
            item['exit_code'] = p.returncode
            (self.out / f'command-{number:03d}.stderr.txt').write_bytes(p.stderr)
            if not binary:
                (self.out / f'command-{number:03d}.stdout.txt').write_bytes(p.stdout)
            else:
                item['stdout_sha256'] = hashlib.sha256(p.stdout).hexdigest()
                item['stdout_bytes'] = len(p.stdout)
            if check and p.returncode:
                raise RuntimeError(f'Command {number} failed ({p.returncode}): {p.stderr[-2000:].decode(errors="replace")}')
            return p
        except subprocess.TimeoutExpired as error:
            item['exit_code'] = None
            item['timeout'] = timeout
            (self.out / f'command-{number:03d}.stdout.txt').write_bytes(error.stdout or b'')
            (self.out / f'command-{number:03d}.stderr.txt').write_bytes(error.stderr or b'')
            raise
        finally:
            save(self.out / 'commands.json', self.commands)

    def ssh(self, argv, **kwargs):
        return self.run(self.lab.ssh_args() + [shlex.join(list(map(str, argv)))], **kwargs)

    def guest_python(self, code, **kwargs):
        return self.ssh(['sudo', '-n', 'python3', '-'], data=code.encode(), **kwargs)

    def collect(self, remote, destination):
        p = self.ssh(['sudo', '-n', 'tar', '-C', str(remote), '-czf', '-', '.'], binary=True)
        destination.mkdir()
        with tarfile.open(fileobj=io.BytesIO(p.stdout), mode='r:gz') as archive:
            archive.extractall(destination, filter='data')

    def upload(self, files, remote):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
        self.ssh(['mkdir', '-p', '/home/lab/k03'])
        self.ssh(['mkdir', remote])
        self.ssh(['tar', '-xzf', '-', '-C', remote], data=stream.getvalue())

    def identity(self):
        args = self.args
        identity = self.runtime.kernel_identity(self.labdir, args.build_lab, args.kernel_build, self.launch)
        if not identity['passed']:
            raise ValueError('Kernel launch/build identity failed')
        build_record = json.loads(Path(identity['build_result']).read_text())
        vmlinux = (args.kernel_build / 'vmlinux').resolve()
        vmlinux_hash = sha(vmlinux)
        if not any(Path(x['path']).resolve() == vmlinux and x['sha256'] == vmlinux_hash
                   and x['bytes'] == vmlinux.stat().st_size for x in build_record['artifacts']):
            raise ValueError('vmlinux differs from the matching K02 kernel build artifact')
        build = str(args.guest_build)
        code = f'''import pathlib,hashlib,json,platform,gzip
r=pathlib.Path({build!r})
result=json.loads((r/'result.json').read_text())
inputs=json.loads((r/'inputs.json').read_text())
hashes={{x['name']:hashlib.sha256((r/'bin'/x['name']).read_bytes()).hexdigest() for x in result['binaries']}}
print(json.dumps({{'result':result,'inputs':inputs,'hashes':hashes,'release':platform.release(),
'arch':platform.machine(),'config_sha256':hashlib.sha256(gzip.decompress(pathlib.Path('/proc/config.gz').read_bytes())).hexdigest()}}))
'''
        guest = json.loads(self.guest_python(code).stdout)
        expected_release = (args.kernel_build / 'include/config/kernel.release').read_text().strip()
        expected_team = {Path(p).name: sha(REPO / p) for p in TEAM[:3]}
        team_actual = {Path(x['input_path']).name: x['sha256'] for x in guest['inputs']['team_inputs']}
        checks = {
            'guest_build_passed': guest['result']['passed'] is True,
            'upstream_matches': guest['result']['upstream_commit'] == COMMIT,
            'team_inputs_match': team_actual == expected_team,
            'build_script_matches': guest['inputs']['build_script_sha256'] == sha(REPO / TEAM[3]),
            'binaries_match': len(guest['result']['binaries']) == 3 and all(guest['hashes'][x['name']] == x['sha256'] for x in guest['result']['binaries']),
            'release_matches': guest['release'] == expected_release,
            'config_matches': guest['config_sha256'] == identity['config_sha256_now'],
            'guest_x86_64': guest['arch'] == 'x86_64',
        }
        result = {'checks': checks, 'passed': all(checks.values()), 'kernel': identity, 'guest': guest,
                  'binding': {'kernel_image': identity['image_sha256_now'], 'kernel_config': identity['config_sha256_now'],
                              'vmlinux': vmlinux_hash, 'binaries': guest['hashes'], 'team': expected_team,
                              'maccconc_commit': COMMIT, 'linux_commit': identity['source_commit']}}
        save(self.out / 'identity.json', result)
        if not result['passed']:
            raise ValueError('Runtime identity checks failed; see identity.json')
        return result['binding']

    def execute(self, mode, sample='demo-dup-vs-close.so', plan=None):
        remote = '/home/lab/k03/run-' + uuid.uuid4().hex
        exe = str(self.args.guest_build / 'bin/kcov-autorace-k03')
        argv = ['sudo', '-n', 'timeout', '-k', '5', '60', exe, str(self.args.guest_build / 'bin' / sample)]
        if plan:
            upload = '/home/lab/k03/plan-' + uuid.uuid4().hex
            self.upload({'plan.txt': Path(plan).read_bytes()}, upload)
            argv += ['--k03-replay', upload + '/plan.txt', remote]
        else:
            argv += ['--k03-record', remote]
        metadata = {'remote': remote, 'exit_code': None, 'remaining_pids': None,
                    'sample': sample, 'mode': mode, 'started': True}
        save(self.out / 'execution.json', metadata)
        try:
            result = self.ssh(argv, timeout=80, check=False)
            metadata['exit_code'] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            metadata['execution_error'] = str(error)
        # Do not continue if the timeout wrapper left a child with this exact executable.
        code = f'''import pathlib,json
matches=[]
for p in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  if str((p/'exe').resolve()) == {exe!r}: matches.append(int(p.name))
 except OSError: pass
print(json.dumps(matches))
'''
        try:
            metadata['remaining_pids'] = json.loads(self.guest_python(code).stdout)
        except Exception as error:
            metadata['process_check_error'] = str(error)
        try:
            exists = self.ssh(['sudo', '-n', 'test', '-d', remote], check=False).returncode == 0
            if exists:
                self.collect(remote, self.out / 'trace')
            else:
                metadata['collect_error'] = 'Remote output directory absent or unreachable'
        except Exception as error:
            metadata['collect_error'] = str(error)
        finally:
            save(self.out / 'execution.json', metadata)
        if metadata['remaining_pids'] != []:
            raise RuntimeError('Executor child remains alive: stop the VM before any further attempt')
        if any(key.endswith('_error') for key in metadata):
            raise RuntimeError('Execution or collection incomplete; see execution.json')
        return metadata

    def source_map(self, directories):
        ips = set()
        for directory in directories:
            for path in directory.glob('*.events.jsonl'):
                for line in path.read_text().splitlines():
                    event = json.loads(line)
                    if event['kind'] == 'MEMORY':
                        ips.add(event['ip'])
        if not ips or self.args.source_mapper is None:
            raise ValueError('Nonempty memory trace and --source-mapper are required')
        p = self.run([str(self.args.source_mapper), str(self.args.kernel_build / 'vmlinux')],
                     data=('\n'.join(sorted(ips)) + '\n').encode(), check=False)
        (self.out / 'source-map.jsonl').write_bytes(p.stdout)
        rows = [json.loads(line) for line in p.stdout.decode().splitlines()]
        mapping = {x['raw_ip']: x for x in rows}
        save(self.out / 'source-map-status.json', {'exit_code': p.returncode, 'input_ips': len(ips),
            'mapped': len(mapping), 'not_found': [x for x in rows if not x.get('found')],
            'helper_sha256': sha(self.args.source_mapper), 'source_sha256': sha(REPO / 'adapters/maccconc/source-map.cpp')})
        if p.returncode or len(rows) != len(ips) or set(mapping) != ips or any(
                not x.get('found') or int(x['lookup_ip'], 16) != int(x['raw_ip'], 16) - 1 for x in rows):
            raise ValueError('Incomplete or invalid source mapping; see source-map-status.json')
        return mapping


def build(session):
    args = session.args
    if session.run(['git', '-C', str(args.source), 'rev-parse', 'HEAD']).stdout.decode().strip() != COMMIT:
        raise ValueError('Source commit mismatch')
    if session.run(['git', '-C', str(args.source), 'status', '--porcelain', '--untracked-files=no']).stdout.strip():
        raise ValueError('Source cache has tracked modifications')
    upstream = session.run(['git', '-C', str(args.source), 'archive', COMMIT], binary=True).stdout
    remote = '/home/lab/k03/inputs-' + uuid.uuid4().hex
    session.upload({'upstream.tar': upstream, **{Path(p).name: (REPO / p).read_bytes() for p in TEAM}}, remote)
    session.ssh(['mkdir', remote + '/source'])
    session.ssh(['tar', '-xf', remote + '/upstream.tar', '-C', remote + '/source'])
    command = ['bash', remote + '/build-maccconc-k03-guest.sh', remote + '/source',
               remote + '/k03-evidence.h', remote + '/0002-k03-evidence.patch', remote + '/child-exit.c', str(args.guest_build)]
    result = session.ssh(command, timeout=180, check=False)
    session.collect(args.guest_build, session.out / 'build')
    return {'passed': result.returncode == 0 and json.loads((session.out / 'build/result.json').read_text()).get('passed') is True,
            'guest_build': str(args.guest_build), 'exit_code': result.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'record', 'bind', 'replay', 'child-exit', 'view'])
    parser.add_argument('--output', type=Path, required=True, help='new external evidence directory')
    parser.add_argument('--guest-build', type=Path, default=Path('/home/lab/k03/build-01'))
    parser.add_argument('--build-lab', type=Path, default=Path.home() / 'os-concurrency-lab')
    parser.add_argument('--kernel-build', type=Path, default=Path.home() / 'os-concurrency-lab/build/linux-2fc2e45b0cd7')
    parser.add_argument('--source', type=Path, default=Path.home() / 'os-concurrency-lab/sources/k01/maccconc')
    parser.add_argument('--source-mapper', type=Path)
    parser.add_argument('--record', type=Path, help='record evidence directory')
    parser.add_argument('--binding', type=Path, help='saved binding directory')
    parser.add_argument('--trace', type=Path, help='raw trace directory for GUI view only')
    args = parser.parse_args()
    session = None
    result = {'passed': False, 'action': args.action}
    try:
        if not args.guest_build.is_absolute() or '..' in args.guest_build.parts or not args.guest_build.is_relative_to('/home/lab/k03'):
            raise ValueError('Guest build must be a normalized path below /home/lab/k03')
        session = Session(args)
        analysis = load_module('k03_analysis', REPO / 'adapters/maccconc/k03_analysis.py') if args.action in ('bind', 'replay') else None
        if args.action == 'build':
            result.update(build(session))
        elif args.action in ('record', 'child-exit'):
            session.identity()
            execution = session.execute(args.action, 'child-exit.so' if args.action == 'child-exit' else 'demo-dup-vs-close.so')
            if args.action == 'record':
                summary = json.loads((session.out / 'trace/summary.json').read_text())
                result.update(passed=execution['exit_code'] == 0, summary=summary)
            else:
                run = json.loads((session.out / 'trace/baseline/run.json').read_text())
                result.update(passed=execution['exit_code'] != 0 and run['child_ok'] is False and run['child_status'] == 7 << 8 and not run['control_valid'], run=run)
        elif args.action == 'bind':
            current = session.identity()
            old = json.loads((args.record / 'identity.json').read_text())['binding']
            if old != current:
                raise ValueError('Recorded build differs from the current runtime')
            classifications = analysis.classify_candidates(args.record / 'trace')
            save(session.out / 'candidates.json', classifications)
            # Candidate policy is fixed before replay: first valid dup(fd)==fd success.
            candidates = [Path(item['dir']) for item in classifications
                          if item['control_valid'] and not item['errors']
                          and item.get('dup_outcome', {}).get('success')
                          and item['dup_outcome']['returned_original_fd']]
            if not candidates:
                raise ValueError('No valid fd-reuse candidate; all search attempts retained')
            selected = candidates[0]
            shutil.copytree(selected, session.out / 'reference')
            shutil.copyfile(selected / 'plan.txt', session.out / 'plan.txt')
            analysis.read_plan(session.out / 'plan.txt')
            session.source_map([session.out / 'reference'])
            binding = {'identity': current, 'candidate': selected.name,
                       'plan_sha256': sha(session.out / 'plan.txt'),
                       'source_mapper_sha256': sha(args.source_mapper),
                       'source_mapper_source_sha256': sha(REPO / 'adapters/maccconc/source-map.cpp'),
                       'analyzer_sha256': sha(REPO / 'adapters/maccconc/k03_analysis.py'),
                       'reference_sha256': {p.name: sha(p) for p in (session.out / 'reference').iterdir() if p.is_file()},
                       'selection': 'first control_valid candidate with dup(fd)==fd and Success; no replay results used',
                       'replay_attempts': 3, 'required_matches': 3,
                       'scope': 'K03 fixed upstream sample/key path; not K10 20-attempt stability, full VM determinism, or kernel bug detection'}
            save(session.out / 'binding.json', binding)
            result.update(passed=True, candidate=selected.name, binding=binding)
        elif args.action == 'replay':
            binding = json.loads((args.binding / 'binding.json').read_text())
            if sha(args.binding / 'plan.txt') != binding['plan_sha256']:
                raise ValueError('Saved plan hash mismatch: refused before guest execution')
            for name, wanted in binding['reference_sha256'].items():
                if Path(name).name != name or sha(args.binding / 'reference' / name) != wanted:
                    raise ValueError('Saved reference hash mismatch: refused before guest execution')
            if args.source_mapper is None or sha(args.source_mapper) != binding['source_mapper_sha256'] or \
                    sha(REPO / 'adapters/maccconc/source-map.cpp') != binding['source_mapper_source_sha256'] or \
                    sha(REPO / 'adapters/maccconc/k03_analysis.py') != binding['analyzer_sha256']:
                raise ValueError('Analysis implementation mismatch: refused before guest execution')
            if session.identity() != binding['identity']:
                raise ValueError('Runtime identity mismatch: refused before guest execution')
            execution = session.execute('replay', plan=args.binding / 'plan.txt')
            mapping = session.source_map([args.binding / 'reference', session.out / 'trace'])
            comparison = analysis.compare_runs(args.binding / 'reference', session.out / 'trace', args.binding / 'plan.txt', mapping)
            save(session.out / 'comparison.json', comparison)
            result.update(passed=execution['exit_code'] == 0 and comparison['passed'], comparison=comparison)
        elif args.action == 'view':
            # Original GUI wire format, deliberately labelled archived view, never execution replay.
            frame = struct.pack('<I', 2)
            for thread in ('A', 'B'):
                words = [int(x, 16) for x in (args.trace / f'{thread}.words').read_text().splitlines()]
                frame += struct.pack('<Q', len(words)) + struct.pack('<' + 'Q' * len(words), *words)
            code = 'import socket,sys; s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(20); s.connect((2,1262702422)); s.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR); s.close()'
            session.ssh(['python3', '-c', code], data=frame, timeout=30)
            result.update(passed=True, mode='archived-trace-view-only', frame_bytes=len(frame), frame_sha256=hashlib.sha256(frame).hexdigest(), trace=str(args.trace), ui_verified=False)
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    if session:
        save(session.out / 'result.json', result)
    # Full event projections remain in result.json/comparison.json, not the terminal.
    display = {key: value for key, value in result.items() if key not in ('comparison', 'binding', 'run')}
    if 'comparison' in result:
        comparison = result['comparison']
        display.update(failed_checks=[key for key, value in comparison['checks'].items() if not value],
                       errors=comparison['errors'], counts=comparison['counts'])
    print(json.dumps(display, ensure_ascii=False, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

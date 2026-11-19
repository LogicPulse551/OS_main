"""K04 fixed-scenario lifecycle and fail-closed recovery for a dedicated VM.

Control and trace checks reuse the accepted K03 adapter. Resource scope is the
scenario's declared descriptors; a fresh guest is required after uncertainty.
"""
from contextlib import contextmanager, redirect_stdout
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from types import SimpleNamespace
import uuid

REPO = Path(__file__).resolve().parents[2]
STATE = 'run/k04-state.json'
PROFILE = 'k04-runtime.json'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fail(code, message):
    from .cli import OperationError
    raise OperationError(code, message)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def persist(path, value):
    """Persist the dirty marker before allowing guest mutation."""
    path = Path(path)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_stopped(prepare, labdir, timeout=10):
    """QEMU may unlink its PID/QMP files just before /proc disappears.

    Keep the original offline-disk gate: retries perform only the same read-only
    checks, and no disk action is allowed until all of them pass.
    """
    transient = {'Baseline QMP is alive; stop the baseline before copying.',
        'Baseline PID still identifies QEMU; refusing offline copy.',
        'An active QEMU command references the baseline.'}
    deadline = time.monotonic() + timeout
    while True:
        try:
            prepare.require_stopped(labdir)
            return
        except RuntimeError as error:
            if str(error) not in transient or time.monotonic() >= deadline:
                raise
            time.sleep(.1)


def guard_legacy(runtime, operation):
    for state_file, profile_file in [(STATE, PROFILE), ('run/k05-state.json', 'k05-runtime.json'), ('run/k06-state.json', 'k06-runtime.json'), ('run/k07-state.json', 'k07-runtime.json'), ('run/k08-state.json', 'k08-runtime.json'), ('run/k09-state.json', 'k09-runtime.json'), ('run/k10-state.json', 'k10-runtime.json'), ('run/k11-state.json', 'k11-runtime.json'), ('run/k12-state.json', 'k12-runtime.json'), ('run/k13-state.json', 'k13-runtime.json')]:
        path = Path(runtime['lab_dir']) / state_file
        registered = (Path(runtime['lab_dir']) / profile_file).exists()
        if operation != 'env.status' and (path.exists() or registered) and (not path.is_file() or read(path).get('state') != 'ready'):
            fail('recovery_required', 'Registered runtime is not ready; legacy operations cannot bypass recovery')


@contextmanager
def lab_environment(runtime, launch=None):
    previous = {key: value for key, value in os.environ.items() if key.startswith('LAB_')}
    for key in previous:
        del os.environ[key]
    os.environ.update(LAB_DIR=runtime['lab_dir'], LAB_SSH_PORT=str(runtime['ssh_port']))
    if launch:
        os.environ.update(launch)
    try:
        yield
    finally:
        for key in list(os.environ):
            if key.startswith('LAB_'):
                del os.environ[key]
        os.environ.update(previous)


class Runtime:
    lab_prefix = 'os-concurrency-k04'
    state_file = STATE
    profile_file = PROFILE

    def __init__(self, task, out):
        self.task, self.out = task, out
        self.runtime = task['runtime']
        self.labdir = Path(self.runtime['lab_dir'])
        if not self.labdir.name.startswith(self.lab_prefix):
            fail('dedicated_runtime_required', 'K04 requires a dedicated os-concurrency-k04* VM; baseline VMs are protected')
        self.check_directories()
        self.lab = load('k04_lab', REPO / '实验环境/openeuler-x86_64/lab.py')
        self.k03 = load('k04_k03', REPO / 'scripts/maccconc-k03.py')
        self.commands = []
        self.statepath = self.labdir / self.state_file
        self.profilepath = self.labdir / self.profile_file

    def check_directories(self):
        if self.labdir.is_symlink() or self.labdir.resolve() != self.labdir:
            fail('invalid_runtime_path', 'Dedicated VM root must not be an alias')
        for name in ('images', 'run', 'evidence', 'keys', 'seed'):
            path = self.labdir / name
            if path.is_symlink() or not path.is_dir() or path.resolve() != path:
                fail('invalid_runtime_path', 'Dedicated runtime directories must not alias other paths: ' + name)

    def call(self, argv, *, data=None, timeout=30, check=True):
        number = len(self.commands)
        item = {'command': list(map(str, argv)), 'started_utc': now(), 'exit_code': None}
        self.commands.append(item)
        try:
            p = subprocess.run(item['command'], input=data, capture_output=True, timeout=timeout)
            item['exit_code'] = p.returncode
            (self.out / f'k04-{number:03d}.stdout').write_bytes(p.stdout)
            (self.out / f'k04-{number:03d}.stderr').write_bytes(p.stderr)
            if check and p.returncode:
                fail('guest_command_failed', f'Command {number} exited {p.returncode}; inspect retained logs')
            return p
        except subprocess.TimeoutExpired as error:
            item['timed_out'] = True
            (self.out / f'k04-{number:03d}.stdout').write_bytes(error.stdout or b'')
            (self.out / f'k04-{number:03d}.stderr').write_bytes(error.stderr or b'')
            raise
        finally:
            item['finished_utc'] = now()
            persist(self.out / 'k04-commands.json', self.commands)

    def ssh(self, argv, **kwargs):
        return self.call(self.lab.ssh_args() + [shlex.join(list(map(str, argv)))], **kwargs)

    def guest(self, code, **kwargs):
        return json.loads(self.ssh(['sudo', '-n', 'python3', '-'], data=code.encode(), **kwargs).stdout)

    def boot_id(self):
        return self.guest("import pathlib,json; print(json.dumps(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()))")

    def identity(self):
        args = SimpleNamespace(output=self.out / ('identity-' + uuid.uuid4().hex[:8]),
            guest_build=Path(self.runtime['scenario_guest_build']), build_lab=Path(self.runtime['build_lab']),
            kernel_build=Path(self.runtime['kernel_build']))
        session = self.k03.Session(args)
        original = session.identity()
        build = self.runtime['lifecycle_guest_build']
        value = self.guest(f"""import pathlib,json,hashlib
p=pathlib.Path({build!r}); r=json.loads((p/'result.json').read_text())
print(json.dumps({{'record':r,'hashes':{{name:hashlib.sha256((p/'bin'/name).read_bytes()).hexdigest() for name in ['kcov-autorace-k03','dup-close-v1.so']}}}}))
""")
        record, hashes = value['record'], value['hashes']
        checks = {
            'native_build': record.get('passed') is True and record.get('scenario') == 'dup-close-v1',
            'scenario_source': record.get('inputs', {}).get('scenario_sha256') == digest(REPO / 'scenarios/dup-close-v1.c'),
            'build_script': record.get('inputs', {}).get('build_script_sha256') == digest(REPO / 'scripts/build-k04-scenario.sh'),
            'binaries': {x['name']: x['sha256'] for x in record.get('binaries', [])} == hashes,
            'unchanged_executor': hashes['kcov-autorace-k03'] == original['binaries']['kcov-autorace-k03'],
            'upstream_source': record.get('inputs', {}).get('upstream_source_git_blob') == 'd2c6e1c79d0ff81a716dbb603c5c36a81ad6589e',
        }
        identity = {'kernel_and_k03': original, 'scenario_binaries': hashes, 'scenario_inputs': record['inputs']}
        persist(self.out / 'scenario-identity.json', {'passed': all(checks.values()), 'checks': checks, 'identity': identity})
        if not all(checks.values()):
            fail('identity_mismatch', 'K04 scenario/build identity did not pass')
        return identity

    def profile(self):
        if not self.profilepath.is_file():
            fail('runtime_not_initialized', 'Use runtime.initialize on the prepared dedicated K04 VM first')
        profile = read(self.profilepath)
        if profile.get('schema_version') != 1 or profile.get('lab_dir') != str(self.labdir):
            fail('invalid_runtime_profile', 'K04 profile identity mismatch')
        if any(profile['runtime'].get(k) != v for k, v in self.runtime.items()):
            fail('runtime_profile_mismatch', 'Task runtime differs from the registered recovery profile')
        return profile

    def mark(self, state, **fields):
        record = {'schema_version': 1, 'state': state, 'updated_utc': now(), **fields}
        persist(self.statepath, record)
        persist(self.out / 'runtime-state.json', record)
        return record

    def initialize(self):
        if self.profilepath.exists():
            fail('already_initialized', 'Runtime registration cannot overwrite an existing recovery profile')
        self.mark('dirty', reason='Runtime registration in progress; no recovery profile committed yet')
        fork = read(self.labdir / 'evidence/baseline-fork.json')
        checkpoint = self.labdir / 'images/baseline-frozen.qcow2'
        if fork.get('target_lab') != str(self.labdir) or fork.get('frozen_snapshot') != str(checkpoint):
            fail('invalid_checkpoint', 'Dedicated VM does not have a matching prepared baseline')
        chain = json.loads(self.call(['qemu-img', 'info', '--backing-chain', '--output=json', checkpoint]).stdout)
        disks = []
        for entry in chain:
            path = Path(entry['filename'])
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o222:
                fail('invalid_checkpoint', 'Recovery backing files must be ordinary read-only files')
            disks.append({'path': str(path), 'sha256': digest(path)})
        if disks[0]['path'] != str(checkpoint) or disks[0]['sha256'] != fork['frozen_overlay_sha256']:
            fail('invalid_checkpoint', 'Prepared checkpoint hash does not match')
        launch = read(self.labdir / 'evidence/last-launch.json')['command']
        option = lambda c, k: c[c.index(k)+1]
        devices = [launch[i+1] for i, x in enumerate(launch[:-1]) if x == '-device']
        cids = [int(x.split('guest-cid=')[1]) for x in devices if x.startswith('vhost-vsock-pci,guest-cid=')]
        if len(cids) != 1 or cids[0] < 3:
            fail('invalid_runtime_profile', 'A dedicated VSOCK CID is required')
        launch_env = {'LAB_KERNEL': option(launch, '-kernel'), 'LAB_APPEND': option(launch, '-append'),
                      'LAB_VSOCK_CID': str(cids[0]), 'LAB_MEMORY_MIB': option(launch, '-m')}
        identity = self.identity()
        profile = {'schema_version': 1, 'lab_dir': str(self.labdir), 'runtime': self.runtime,
                   'checkpoint': str(checkpoint), 'disks': disks, 'identity': identity, 'launch_env': launch_env}
        persist(self.profilepath, profile)
        state = self.mark('ready', boot_id=self.boot_id(), last_action='initialized')
        return {'profile_sha256': digest(self.profilepath), 'state': state, 'identity': identity}

    def check_profile_identity(self, profile):
        if self.identity() != profile['identity']:
            fail('identity_mismatch', 'Current scenario or kernel differs from the recovery profile')

    def run_scenario(self):
        from .scenario_protocol import classify
        profile = self.profile()
        state = read(self.statepath)
        if state.get('state') != 'ready':
            fail('recovery_required', 'Previous run is incomplete or unclean; recover before another round')
        if self.boot_id() != state.get('boot_id'):
            self.mark('dirty', reason='Unexpected guest boot identity')
            fail('recovery_required', 'Guest rebooted outside the lifecycle; explicit recovery is required')
        self.check_profile_identity(profile)
        analysis_module = load('k04_analysis', REPO / 'adapters/maccconc/k03_analysis.py')
        plan = self.out / 'input-plan.txt'
        with plan.open('xb') as stream:
            stream.write(Path(self.task['inputs']['plan']).read_bytes())
        analysis_module.read_plan(plan)
        run_id = uuid.uuid4().hex
        remote = '/home/lab/k04/run-' + run_id
        active = {'run_id': run_id, 'remote': remote, 'request': remote + '/request.json',
                  'boot_id': state['boot_id'], 'output': str(self.out), 'scenario': self.task['scenario'],
                  'plan_sha256': digest(plan), 'guest_supervisor_sha256': digest(REPO / 'adapters/maccconc/k04_guest.py')}
        self.mark('dirty', active=active, boot_id=state['boot_id'], reason='Round started; cleanup not yet established')
        request = {'run_id': run_id, 'executable': self.runtime['lifecycle_guest_build'] + '/bin/kcov-autorace-k03',
                   'scenario_library': self.runtime['lifecycle_guest_build'] + '/bin/dup-close-v1.so',
                   'plan_path': remote + '/plan.txt', 'timeout_seconds': self.task['scenario']['timeout_seconds'],
                   'fault': self.task['scenario']['fault']}
        persist(self.out / 'guest-request.json', request)
        files = {'request.json': json.dumps(request), 'plan.txt': plan.read_text(),
                 'supervisor.py': (REPO / 'adapters/maccconc/k04_guest.py').read_text()}
        code = f"""import pathlib,json,os,subprocess
p=pathlib.Path({remote!r}); p.mkdir(mode=0o700)
for name,data in {files!r}.items():
 f=p/name; f.write_text(data); f.chmod(0o600)
with (p/'supervisor.stdout').open('xb') as out,(p/'supervisor.stderr').open('xb') as err:
 child=subprocess.Popen(['python3',str(p/'supervisor.py'),'run','--request',str(p/'request.json')],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
print(json.dumps({{'supervisor_pid':child.pid}}))
"""
        cancelled = False
        collected = False
        guest = None
        try:
            active.update(self.guest(code))
            self.mark('dirty', active=active, boot_id=state['boot_id'], reason='Guest supervisor active')
            deadline = time.monotonic() + request['timeout_seconds'] + 25
            while time.monotonic() < deadline:
                guest = self.poll_guest(remote)
                if guest is not None:
                    break
                time.sleep(.25)
            if guest is None:
                fail('guest_supervisor_timeout', 'No supervisor result; runtime remains quarantined')
        except KeyboardInterrupt:
            cancelled = True
            # A second interrupt can abort this attempt; the persisted marker still blocks new work.
            self.cancel_guest(active)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                guest = self.poll_guest(remote)
                if guest is not None:
                    break
                time.sleep(.25)
        finally:
            # Collection is evidence only, never permission to clear the marker.
            try:
                self.collect(remote)
                collected = True
            except Exception as error:
                persist(self.out / 'collection-error.json', {'error': str(error)})
        if guest is None:
            fail('recovery_required', 'No complete supervisor result; runtime remains quarantined')
        persist(self.out / 'guest-observed.json', guest)
        expected_command = [request['executable'], request['scenario_library'], '--k03-replay', request['plan_path'], remote + '/trace']
        if (guest.get('run_id') != run_id or guest.get('boot_id') != state['boot_id']
                or guest.get('fault') != request['fault'] or guest.get('command') != expected_command):
            fail('guest_result_mismatch', 'Supervisor result does not bind to this request, command and guest boot')
        if not collected or read(self.out / 'guest/guest-result.json') != guest:
            fail('collection_incomplete', 'Complete collected evidence must match the observed supervisor result')
        trace = self.out / 'guest/trace'
        run = read(trace / 'run.json') if (trace / 'run.json').is_file() else None
        analyzed = {'errors': [], 'trace_valid': False, 'control_valid': False}
        try:
            if run is not None and run.get('overflow') is False:
                events = {t: analysis_module.read_events(trace, t) for t in ('A', 'B')}
                raw = {t: analysis_module._raw_consistency(trace, t, events[t], run) for t in ('A', 'B')}
                checks = analysis_module._control_checks(run, events, analysis_module.read_plan(trace / 'plan.txt'))
                checks['submitted_plan_bytes_identical'] = (trace / 'plan.txt').read_bytes() == plan.read_bytes()
                analyzed.update(trace_valid=all(v['valid'] for v in raw.values()), control_valid=all(checks.values()), checks=checks, raw=raw)
        except Exception as error:
            analyzed['errors'].append(str(error))
        classification = classify(guest, run, analyzed)
        result = {'schema_version': 1, 'kind': 'kconc.scenario', 'scenario': 'dup-close-v1', 'run_id': run_id,
                  'passed': classification['passed'] and not cancelled, 'classification': classification, 'guest': guest,
                  'host_cancel_requested': cancelled,
                  'analysis': analyzed, 'active': active, 'scope': 'One fixed dup/close lifecycle; not regmap checking or K10 stability'}
        persist(self.out / 'scenario-result.json', result)
        self.last_result = result
        if not classification['recovery_required']:
            self.mark('ready', boot_id=state['boot_id'], last_run_id=run_id, result=str(self.out / 'scenario-result.json'))
        else:
            self.mark('dirty', active=active, boot_id=state['boot_id'], reason='Lifecycle cleanup not confirmed', classification=classification)
        if cancelled:
            raise KeyboardInterrupt
        return result

    def poll_guest(self, remote):
        return self.guest(f"import pathlib,json; p=pathlib.Path({remote + '/guest-result.json'!r}); print(p.read_text() if p.exists() else 'null')")

    def cancel_guest(self, active):
        if not re.fullmatch(r'[0-9a-f]{32}', active.get('run_id', '')) or active['remote'] != '/home/lab/k04/run-' + active['run_id'] or active.get('request') != active['remote'] + '/request.json':
            fail('invalid_active_run', 'Cannot cancel an unbound run')
        if active.get('boot_id') != self.boot_id():
            fail('recovery_required', 'Guest changed; stale cancellation target refused')
        return self.ssh(['sudo', '-n', 'python3', active['remote'] + '/supervisor.py', 'cancel', '--request', active['request']])

    def collect(self, remote):
        # Reuse the K03 safe tar extraction without creating or changing a session.
        session = object.__new__(self.k03.Session)
        session.out, session.commands, session.lab = self.out, [], self.lab
        session.collect(remote, self.out / 'guest')

    def recover(self):
        profile = self.profile()
        prior = read(self.statepath) if self.statepath.exists() else {'state': 'unknown', 'reason': 'Registration interrupted before state persistence'}
        self.mark('recovering', previous=prior, reason='Explicit checkpoint recovery in progress')
        recovery = {'previous': prior, 'steps': [], 'passed': False}
        try:
            expected_checkpoint = str(self.labdir / 'images/baseline-frozen.qcow2')
            if profile['checkpoint'] != expected_checkpoint or not profile['disks'] or profile['disks'][0]['path'] != expected_checkpoint:
                fail('invalid_checkpoint', 'Recovery checkpoint must be the registered dedicated frozen image')
            for item in profile['disks']:
                path = Path(item['path'])
                if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o222 or digest(path) != item['sha256']:
                    fail('checkpoint_mismatch', 'Recovery backing identity failed; current disk was not replaced')
            recovery['steps'].append('checkpoint_hashes_verified')
            output = io.StringIO()
            try:
                with redirect_stdout(output):
                    self.lab.stop()
            except (Exception, SystemExit) as error:
                recovery['graceful_stop_error'] = str(error)
            (self.out / 'recovery-stop.txt').write_text(output.getvalue())
            if self.lab.process_alive():
                self.lab.qmp('quit')
                deadline = time.monotonic() + 10
                while self.lab.process_alive() and time.monotonic() < deadline:
                    time.sleep(.1)
            prepare = load('k04_prepare', REPO / 'scripts/prepare-maccconc-vm.py')
            wait_stopped(prepare, self.labdir)
            recovery['steps'].append('old_qemu_exit_confirmed')
            self.check_directories()
            images = self.labdir / 'images'
            disk = images / 'experiment.qcow2'
            if disk.is_symlink() or disk.resolve().parent != images.resolve():
                fail('invalid_overlay', 'Writable disk is outside the dedicated images directory')
            archive = images / ('retired-' + uuid.uuid4().hex + '.qcow2')
            if disk.exists():
                disk.rename(archive)
                recovery['retained_old_overlay'] = str(archive)
            self.call(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', profile['checkpoint'], disk])
            recovery['steps'].append('fresh_overlay_created')
            with lab_environment(self.runtime, profile['launch_env']), redirect_stdout(output):
                self.lab.start()
            (self.out / 'recovery-start.txt').write_text(output.getvalue())
            deadline = time.monotonic() + 60
            boot = None
            while time.monotonic() < deadline:
                try:
                    boot = self.boot_id()
                    break
                except Exception:
                    time.sleep(1)
            if not boot or boot == prior.get('boot_id', prior.get('active', {}).get('boot_id')):
                fail('recovery_boot_failed', 'A new reachable guest boot was not established')
            self.check_profile_identity(profile)
            recovery.update(passed=True, boot_id=boot)
            recovery['steps'].append('new_boot_and_build_identity_verified')
            persist(self.out / 'recovery.json', recovery)
            self.mark('ready', boot_id=boot, last_action='checkpoint_recovery', recovery=str(self.out / 'recovery.json'))
            return recovery
        except BaseException:
            recovery['passed'] = False
            self.mark('dirty', previous=prior, reason='Recovery incomplete', boot_id=prior.get('boot_id'))
            raise
        finally:
            if not recovery['passed']:
                persist(self.out / 'recovery.json', recovery)


def dispatch(task, out, envelope):
    from .cli import runtime_lock
    op = task['operation']
    with lab_environment(task['runtime']):
        runtime = Runtime(task, out)
        try:
            if op == 'runtime.status':
                runtime.profile()
                data = {'state': read(runtime.statepath), 'vm': runtime.lab.running(), 'execution_readiness_verified': False}
            elif op == 'scenario.cancel':
                runtime.profile()
                state = read(runtime.statepath)
                active = state.get('active', {})
                if state.get('state') != 'dirty' or active.get('run_id') != task['scenario']['run_id']:
                    fail('no_matching_active_run', 'Cancellation must name the current active run ID')
                reply = runtime.cancel_guest(active)
                data = json.loads(reply.stdout)
                if data.get('run_id') != active['run_id'] or type(data.get('cancel_requested')) is not bool:
                    fail('invalid_cancel_reply', 'Cancellation acknowledgement does not match the active run')
                data['cleanup_verified'] = False
            else:
                with runtime_lock(task['runtime']):
                    # Coordinate disk operations with the original lab lifecycle as well.
                    import fcntl
                    with (runtime.labdir / 'run/control.lock').open('a') as lock:
                        try:
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            fail('runtime_busy', 'VM lifecycle control lock is already held')
                        if op == 'runtime.initialize':
                            data = runtime.initialize()
                        elif op == 'runtime.recover':
                            data = runtime.recover()
                        elif op == 'scenario.run':
                            data = runtime.run_scenario()
                        else:
                            fail('unsupported_operation', 'Unknown lifecycle operation')
            envelope['data'] = data
            if op != 'scenario.run':
                persist(out / 'runtime-result.json', {'schema_version': 1, 'kind': 'kconc.runtime',
                    'passed': True, 'operation': op, 'scope': envelope['result_scope'], 'data': data})
            if op == 'scenario.run' and not data['passed']:
                fail('scenario_incomplete', 'Scenario did not pass; inspect independent classification axes')
        except BaseException:
            if hasattr(runtime, 'last_result'):
                envelope['data'] = runtime.last_result
            elif runtime.statepath.exists():
                envelope['data']['runtime_state'] = read(runtime.statepath)
            raise

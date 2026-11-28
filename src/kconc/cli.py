"""Run kernel experiment tasks with their inputs, commands and results saved together."""
import argparse
from contextlib import contextmanager
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import uuid

from .manifest import CATALOG, LIFECYCLE_OPERATIONS, ManifestError, load_manifest, normalize_manifest
from .results import ResultError, read_result

REPO = Path(__file__).resolve().parents[2]
TIMEOUTS = {'env.status': 25, 'env.check': 300, 'build.identity': 180,
            'k03.record': 240, 'k03.bind': 600, 'k03.replay': 240, 'k03.view': 60}


class OperationError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def new_output(path):
    resolved = path.expanduser().resolve()
    if resolved.is_relative_to(REPO) or REPO.is_relative_to(resolved):
        raise OperationError('invalid_output', 'Output must be outside the delivery repository and its ancestors')
    if path.is_symlink() or resolved.exists():
        raise OperationError('output_exists', 'Output must be a new directory; existing files are never replaced')
    resolved.mkdir(parents=True, mode=0o700, exist_ok=False)
    return resolved


def implementation():
    def git(*args):
        try:
            p = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True, timeout=10)
            return p.stdout.strip() if p.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    paths = [REPO / 'kconc.py', *sorted((REPO / 'src/kconc').glob('*.py')),
             REPO / 'scripts/maccconc-k03.py', REPO / 'scripts/verify-maccconc-runtime.py',
             REPO / '实验环境/openeuler-x86_64/lab.py', REPO / 'configs/maccconc.lock.json']
    lifecycle_paths = ['src/kconc/lifecycle.py', 'src/kconc/scenario_protocol.py',
                       'adapters/maccconc/k04_guest.py', 'scripts/build-k04-scenario.sh',
                       'scenarios/dup-close-v1.c']
    lifecycle_paths += ['adapters/maccconc/k05_guest.py', 'adapters/maccconc/k05_analysis.py',
        'adapters/maccconc/k05-executor.patch', 'scenarios/regmap-v1.c', 'scenarios/regmap-client.c',
        'kernel/k05/kconc-regmap.c', 'kernel/k05/kconc-regmap.h', 'kernel/k05/Kconfig.fragment',
        'kernel/k05/Makefile.fragment', 'configs/kernel/k05-regmap.fragment',
        'scripts/build-k05-kernel.py', 'scripts/build-k05-guest.sh']
    lifecycle_paths += ['adapters/maccconc/k06_guest.py', 'adapters/maccconc/k06_analysis.py',
        'scenarios/regmap-k06.c', 'scenarios/regmap-k06-client.c', 'scenarios/regmap-k06-cases.h',
        'kernel/k06/kconc-regmap.c', 'kernel/k06/kconc-regmap.h', 'kernel/k06/Kconfig.fragment',
        'kernel/k06/Makefile.fragment', 'configs/kernel/k06-regmap.fragment',
        'scripts/build-k06-kernel.py', 'scripts/build-k06-guest.sh']
    lifecycle_paths += ['adapters/maccconc/k07_guest.py', 'adapters/maccconc/k07_analysis.py',
        'scenarios/regmap-k07.c', 'scenarios/regmap-k07-client.c', 'scenarios/regmap-k07-cases.h',
        'kernel/k07/kconc-regmap.c', 'kernel/k07/kconc-regmap.h', 'kernel/k07/Kconfig.fragment',
        'kernel/k07/Makefile.fragment', 'configs/kernel/k07-regmap.fragment',
        'scripts/build-k07-kernel.py', 'scripts/build-k07-guest.sh']
    lifecycle_paths += ['adapters/maccconc/k08_guest.py', 'adapters/maccconc/k08_analysis.py',
        'adapters/maccconc/k08-executor.patch', 'scripts/build-k08-guest.sh', 'configs/scenarios/k08-inputs.json']
    lifecycle_paths += ['adapters/maccconc/k09_guest.py', 'adapters/maccconc/k09_analysis.py',
        'adapters/maccconc/k09-executor.patch', 'scripts/build-k09-guest.sh']
    missing_lifecycle = [name for name in lifecycle_paths if not (REPO / name).is_file()]
    paths = sorted(set(paths + [REPO / name for name in lifecycle_paths if name not in missing_lifecycle]))
    status = git('status', '--porcelain')
    return {'commit': git('rev-parse', 'HEAD'), 'worktree_dirty': None if status is None else bool(status),
            'files': {p.relative_to(REPO).as_posix(): digest(p) for p in paths},
            'missing_lifecycle_files': missing_lifecycle}


@contextmanager
def runtime_lock(runtime):
    if sys.platform != 'linux':
        raise OperationError('unsupported_platform', 'Live operations must run in WSL Debian; offline commands remain available')
    import fcntl
    lab = Path(runtime['lab_dir'])
    if not (lab / 'run').is_dir():
        raise OperationError('missing_runtime', 'Runtime run directory is absent; use the existing environment setup first')
    # Coordinates this entry point only; users must not run legacy executors concurrently.
    with (lab / 'run/kconc.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OperationError('runtime_busy', 'Another unified CLI operation owns this runtime') from error
        yield


def require_vsock_port():
    try:
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as probe:
            probe.bind((socket.VMADDR_CID_ANY, 1262702422))
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            raise OperationError('vsock_busy', 'VSOCK port 1262702422 is in use; close its GUI/server before env.check') from error
        raise OperationError('vsock_unavailable', str(error)) from error
    # A later race is still handled by the original verifier, never treated as a pass.


def backend_command(task, out):
    op, runtime, inputs = task['operation'], task['runtime'], task['inputs']
    python = sys.executable
    if op == 'env.status':
        return [python, str(REPO / '实验环境/openeuler-x86_64/lab.py'), 'status'], out / 'backend.stdout.json'
    if op == 'env.check':
        return [python, str(REPO / 'scripts/verify-maccconc-runtime.py'), '--guest-build', runtime['probe_guest_build'],
                '--build-lab', runtime['build_lab'], '--kernel-build', runtime['kernel_build']], out / 'backend.stdout.json'
    if op == 'build.identity':
        return [python, str(REPO / 'src/kconc/backend.py'), '--task', str(out / 'task.json'),
                '--output', str(out / 'backend')], out / 'backend/identity.json'
    command = [python, str(REPO / 'scripts/maccconc-k03.py'), op.split('.')[1], '--output', str(out / 'backend')]
    for field, option in [('scenario_guest_build', '--guest-build'), ('build_lab', '--build-lab'), ('kernel_build', '--kernel-build')]:
        if field in runtime:
            command += [option, runtime[field]]
    for field, value in inputs.items():
        command += ['--' + field.replace('_', '-'), value]
    return command, out / 'backend/result.json'


def stop_process(process, backend):
    """Best effort local process cleanup; never claims guest rollback."""
    failures = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if process.poll() is not None:
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass  # Child can exit between poll and signal; still reap it.
        except OSError as error:
            failures.append(str(error))
        try:
            process.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            continue
        except OSError as error:
            failures.append(str(error))
    backend['exit_code'] = process.poll()
    backend['local_cleanup'] = {'process_exited': backend['exit_code'] is not None, 'errors': failures}


def execute_process(command, env, out, timeout, envelope):
    backend = {'command': command, 'cwd': str(REPO), 'timeout_seconds': timeout,
               'started_utc': now(), 'exit_code': None,
               'stdout': str(out / 'backend.stdout.json'), 'stderr': str(out / 'backend.stderr.txt')}
    envelope['backend'] = backend
    save(out / 'result.json', envelope)
    process = None
    with (out / 'backend.stdout.json').open('wb') as stdout, (out / 'backend.stderr.txt').open('wb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=REPO, env=env, stdout=stdout, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            backend['pid'] = process.pid
            save(out / 'result.json', envelope)
            backend['exit_code'] = process.wait(timeout=timeout)
        except (KeyboardInterrupt, subprocess.TimeoutExpired) as error:
            backend['interrupted'] = isinstance(error, KeyboardInterrupt)
            backend['timed_out'] = isinstance(error, subprocess.TimeoutExpired)
            envelope['data']['recovery_required'] = True
            # This only stops the local process group, not a guest state rollback.
            if process is not None:
                stop_process(process, backend)
            if isinstance(error, KeyboardInterrupt):
                raise
            raise OperationError('backend_timeout', 'Backend timed out; inspect guest cleanup before further execution') from error
        except Exception:
            if process is not None:
                envelope['data']['recovery_required'] = True
                stop_process(process, backend)
            raise
        finally:
            backend['finished_utc'] = now()
            stdout.flush()
            stderr.flush()
            for field in ('stdout', 'stderr'):
                backend[field + '_sha256'] = digest(Path(backend[field]))
    return backend['exit_code']


def json_object(path):
    # Runtime status/identity are private adapters; public historical formats use results.py.
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise OperationError('missing_backend_result', 'Expected a bounded backend result file: ' + str(path))
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise OperationError('invalid_backend_result', 'Backend result is not an object')
    return value


def run_live(task, out, envelope):
    if task['operation'] == 'native.regmap-two-prelock':
        from .native_regmap_two_prelock import run
        run(task, out, envelope)
        return
    if task['operation'] in {'artifact.check', 'artifact.loaded'}:
        from .artifacts import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import REDUCTION_OPERATIONS
    if task['operation'] in REDUCTION_OPERATIONS:
        from .reduction import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import FEEDBACK_OPERATIONS
    if task['operation'] in FEEDBACK_OPERATIONS:
        from .feedback import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import REGRESSION_OPERATIONS
    if task['operation'] in REGRESSION_OPERATIONS:
        from .regression import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import REPLAY_OPERATIONS
    if task['operation'] in REPLAY_OPERATIONS:
        from .replay import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import SEARCH_OPERATIONS
    if task['operation'] in SEARCH_OPERATIONS:
        from .search import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import SAMPLE_OPERATIONS
    if task['operation'] == 'candidate.export':
        from .sampling import export_samples
        envelope['data'] = export_samples(task, out)
        return
    if task['operation'] in SAMPLE_OPERATIONS:
        from .sampling import dispatch
        dispatch(task, out, envelope)
        return
    from .manifest import REGMAP_OPERATIONS, RMW_OPERATIONS, MUTEX_OPERATIONS
    if task['operation'] in MUTEX_OPERATIONS:
        from .mutex import dispatch
        dispatch(task, out, envelope)
        return
    if task['operation'] in RMW_OPERATIONS:
        from .rmw import dispatch
        dispatch(task, out, envelope)
        return
    if task['operation'] in REGMAP_OPERATIONS:
        from .regmap import dispatch
        dispatch(task, out, envelope)
        return
    if task['operation'] in LIFECYCLE_OPERATIONS:
        from .lifecycle import dispatch
        dispatch(task, out, envelope)
        return
    with runtime_lock(task['runtime']):
        from .lifecycle import guard_legacy
        guard_legacy(task['runtime'], task['operation'])
        if task['operation'] == 'env.check':
            require_vsock_port()
        command, result_path = backend_command(task, out)
        env = {key: value for key, value in os.environ.items() if not key.startswith('LAB_')}
        env.update(LAB_DIR=task['runtime']['lab_dir'], LAB_SSH_PORT=str(task['runtime']['ssh_port']),
                   PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1')
        code = execute_process(command, env, out, TIMEOUTS[task['operation']], envelope)
        envelope['backend']['result'] = str(result_path)
        if task['operation'] in ('env.status', 'build.identity'):
            if code != 0:
                raise OperationError('backend_failed', f'Backend exited {code}; inspect retained stdout/stderr')
            value = json_object(result_path)
            envelope['backend']['result_sha256'] = digest(result_path)
            if task['operation'] == 'env.status':
                state = value.get('state')
                if not (state in ('stopped', 'alive-qmp-unavailable') if isinstance(state, str)
                        else isinstance(state, dict) and type(state.get('running')) is bool):
                    raise OperationError('invalid_backend_result', 'Unrecognized VM status')
                envelope['data'] = {'observation': value, 'vm_running': isinstance(state, dict) and state['running'],
                                    'execution_readiness_verified': False}
            else:
                checks = value.get('checks')
                if value.get('passed') is not True or not isinstance(checks, dict) or not checks or \
                        any(v is not True for v in checks.values()) or not isinstance(value.get('binding'), dict):
                    raise OperationError('invalid_backend_result', 'K03 identity did not pass all original checks')
                envelope['data'] = {'checks': checks, 'binding': value['binding'], 'scenario_executed': False}
        else:
            try:
                summary = read_result(result_path, backend_exit_code=code)
            except ResultError:
                if code and not result_path.exists():
                    raise OperationError('backend_failed', f'Backend exited {code} without a result; retained logs explain the failure')
                raise
            envelope['data'] = {'evidence_origin': 'backend_executed_in_this_invocation', 'backend_report': summary}
            envelope['backend']['result_sha256'] = summary['source']['sha256']
            expected_kind = ('maccconc.k02.runtime' if task['operation'] == 'env.check'
                             else 'maccconc.' + task['operation'])
            if summary['kind'] != expected_kind or (task['operation'] == 'env.check'
                    and summary['summary'].get('mode') != 'full'):
                raise OperationError('backend_scope_mismatch', 'Backend result does not match the requested operation and scope')
            if code != 0 or summary['reported_passed'] is not True:
                raise OperationError('backend_failed', f'Backend did not pass (process exit {code})')


def run_task(*, manifest=None, inline=None, output=None):
    envelope = {'schema_version': 1, 'kind': 'kconc.run', 'run_id': str(uuid.uuid4()), 'operation': None,
                'status': 'running', 'exit_code': None, 'started_utc': now(), 'finished_utc': None,
                'result_scope': 'Task has not completed', 'request': {}, 'data': {}, 'error': None,
                'backend': None, 'output_directory': None}
    out = None
    try:
        if output is not None:
            out = new_output(output)
            envelope['output_directory'] = str(out)
        if manifest is not None:
            envelope['request'] = {'path': str(manifest.expanduser().resolve())}
            task = load_manifest(manifest)
            envelope['request']['sha256'] = digest(manifest.expanduser().resolve())
        else:
            task = normalize_manifest(inline, Path.cwd())
            envelope['request'] = {'inline': True}
        envelope.update(operation=task['operation'], result_scope=CATALOG[task['operation']]['scope'],
                        implementation=implementation())
        if out:
            save(out / 'task.json', task)
            save(out / 'result.json', envelope)
        if not CATALOG[task['operation']]['supported']:
            envelope.update(status='unsupported', exit_code=3,
                            error={'code': 'unsupported_operation', 'message': 'This operation is not implemented; no backend was executed'})
        elif task['operation'] == 'result.read':
            envelope['data'] = read_result(Path(task['inputs']['result']))
            envelope.update(status='read', exit_code=0)
        elif task['operation'] == 'report.trace':
            from .trace_report import write_report
            if out is None:
                raise OperationError('invalid_output', 'Reports require a new output directory')
            envelope['data'] = write_report(out, **{name: Path(path) for name, path in task['inputs'].items()})
            envelope.update(status='read', exit_code=0)
        elif task['operation'] == 'demo.review':
            from .competition_demo import render_bundle
            if out is None:
                raise OperationError('invalid_output', 'A demo requires a new output directory')
            envelope['data'] = render_bundle(Path(task['inputs']['bundle']), out)
            envelope.update(status='read', exit_code=0)
        elif task['operation'] == 'optimize.bma400':
            if out is None:
                raise OperationError('invalid_output', 'Source generation requires a new output directory')
            command = [sys.executable, '-B', str(REPO/'scripts/optimization/bma400.py'), '--output', str(out/'source')]
            for key, path in task['inputs'].items():
                command.extend(['--' + key.replace('_', '-'), path])
            with (out/'generator.stdout').open('xb') as stdout, (out/'generator.stderr').open('xb') as stderr:
                code = subprocess.run(command, stdout=stdout, stderr=stderr).returncode
            envelope['backend'] = {'command': command, 'exit_code': code}
            receipt = out/'source/result.json'
            if receipt.is_file():
                outcome = json.loads(receipt.read_bytes())
                envelope['data'] = {'decision': outcome.get('decision'), 'source_result': 'source/result.json',
                                    'result_sha256': digest(receipt), 'reason': outcome.get('reason')}
            if code == 3 and envelope['data'].get('decision') == 'original_fallback':
                envelope.update(status='failed', exit_code=3, error={'code': 'source_fallback', 'message': envelope['data']['reason']})
            elif code or envelope['data'].get('decision') != 'scoped_source_verified':
                raise OperationError('generator_failed', 'Inspect the retained source generation result and stderr')
            else:
                envelope.update(status='passed', exit_code=0)
        else:
            if out is None:
                raise OperationError('invalid_output', 'Live operations require --output NEW_EXTERNAL_DIRECTORY')
            run_live(task, out, envelope)
            envelope.update(status='passed', exit_code=0)
    except ManifestError as error:
        envelope.update(status='invalid', exit_code=2, error={'code': error.code, 'message': error.message})
    except ResultError as error:
        envelope.update(status='failed', exit_code=1, error={'code': error.code, 'message': error.message})
    except OperationError as error:
        invalid = error.code in ('invalid_output', 'output_exists')
        envelope.update(status='invalid' if invalid else 'failed', exit_code=2 if invalid else 1,
                        error={'code': error.code, 'message': error.message})
    except KeyboardInterrupt:
        envelope.update(status='interrupted', exit_code=130, error={'code': 'interrupted', 'message': 'Interrupted; backend cleanup is not implied'})
    except Exception as error:
        envelope.update(status='failed', exit_code=1, error={'code': 'operation_error', 'message': str(error), 'type': type(error).__name__})
    envelope['finished_utc'] = now()
    if out:
        try:
            save(out / 'result.json', envelope)
        except OSError as error:
            envelope['data']['before_persistence_failure'] = {
                'status': envelope['status'], 'exit_code': envelope['exit_code'], 'error': envelope['error']}
            envelope.update(status='failed', exit_code=1, result_persisted=False,
                            error={'code': 'result_write_failed', 'message': str(error)})
    return envelope


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise OperationError('invalid_arguments', message)


def main(argv=None):
    parser = Parser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    iio = sub.add_parser('iio', help='Identify and compare normal IIO reads from saved captures')
    iio.add_argument('action', choices=('discover', 'verify', 'negative'))
    iio.add_argument('arguments', nargs=argparse.REMAINDER)
    ram = sub.add_parser('ram-regmap', help='Search, inspect and replay a private RAM regmap case')
    ram.add_argument('action', choices=('actors', 'inspect', 'exercise', 'replay'))
    ram.add_argument('arguments', nargs=argparse.REMAINDER)
    sub.add_parser('commands', help='List implemented operations and explicit unsupported capabilities')
    validate = sub.add_parser('validate', help='Validate a runtime task manifest offline')
    validate.add_argument('manifest', type=Path)
    run = sub.add_parser('run', help='Run one task and preserve its full result outside the repository')
    run.add_argument('manifest', type=Path)
    run.add_argument('--output', required=True, type=Path)
    show = sub.add_parser('result', help='Read a historical result without executing a backend')
    show.add_argument('path', type=Path)
    show.add_argument('--output', type=Path)
    report = sub.add_parser('report', help='Browse an archived regmap trace alongside its source code')
    report.add_argument('--bundle', type=Path, required=True, help='archived bundle directory or bundle.json')
    report.add_argument('--attempt', type=Path, help='optional historical replay attempt directory or comparison.json')
    report.add_argument('--source-root', type=Path, required=True, help='matching kernel source tree or extracted source snapshot')
    report.add_argument('--build-record', type=Path, required=True, help='build receipt binding source hashes to this kernel')
    report.add_argument('--output', type=Path, required=True, help='new directory outside the repository')
    demo = sub.add_parser('demo', help='Open a saved competition run as a portable offline report')
    demo.add_argument('bundle', type=Path)
    demo.add_argument('--output', type=Path, required=True)
    opt = sub.add_parser('optimize', help='Find and certify regmap bulk reads in a Linux source tree')
    opt.add_argument('--kernel', required=True, type=Path)
    opt.add_argument('--config', required=True, type=Path, help='resolved x86_64 Kbuild .config')
    opt.add_argument('--scope', default='drivers', help='driver directory or file relative to the kernel')
    opt.add_argument('--policy', choices=('private-api', 'valid-api', 'valid-n', 'init-n', 'registered'),
                     help='select private objects, six-byte IIO reads, variable reads checked per call or '
                          'at map initialization, or registered SPI instances')
    opt.add_argument('--build-dir', type=Path, default=os.getenv('KCONC_KBUILD_DIR'),
                     help='configured kernel object directory containing Kbuild compilation records')
    opt.add_argument('--clang', type=Path, help='Clang binary used for Kbuild (default: clang on PATH)')
    opt.add_argument('--compcert', type=Path, default=os.getenv('KCONC_COMPCERT'))
    opt.add_argument('--coq-bin', type=Path, default=os.getenv('KCONC_COQ_BIN'))
    opt.add_argument('--materialize', action='store_true', help='also create a ready-to-build Linux source copy')
    opt.add_argument('--output', required=True, type=Path, help='new directory outside both source trees')
    try:
        args = parser.parse_args(argv)
        if args.command == 'ram-regmap':
            if args.action == 'actors':
                from .actor_run import main as actor_main
                return actor_main(args.arguments)
            if args.action == 'inspect':
                from .regmap_three_check import main as inspect
                return inspect(args.arguments)
            scripts = {'exercise': 'regmap-three-run.py', 'replay': 'regmap-central/replay.py'}
            return subprocess.run([sys.executable, '-B', str(REPO / 'scripts' / scripts[args.action]),
                                   *args.arguments]).returncode
        if args.command == 'iio':
            from .iio_path import main as iio_main
            return iio_main([args.action, *args.arguments])
        if args.command == 'commands':
            value = {'schema_version': 1, 'kind': 'kconc.catalog', 'operations': CATALOG,
                     'source_commands': {'optimize': 'Discover and certify supported regmap bulk reads',
                                         'ram-regmap': 'Search operation orders, inspect three-worker traces and replay registered cases',
                                         'iio': 'Discover and verify per-axis read paths in matching kernel captures'},
                     'scope': 'Runtime adapters, not a copy of the external development task status'}
            code = 0
        elif args.command == 'optimize':
            if args.policy == 'registered' or (args.policy is None and args.build_dir is None):
                from .sixbyte import optimize
            elif args.policy in ('valid-api', 'valid-n', 'init-n'):
                from .valid_opt import optimize
            else:
                from .api_opt import optimize
            try:
                value = optimize(args)
            except (OSError, ValueError) as error:
                raise OperationError('invalid_optimization_input', str(error)) from error
            code = 0
        elif args.command == 'validate':
            task = load_manifest(args.manifest)
            value = {'schema_version': 1, 'kind': 'kconc.validation', 'status': 'validated', 'task': task,
                     'operation_supported': CATALOG[task['operation']]['supported'], 'backend_executed': False}
            code = 0
        elif args.command == 'report':
            inputs = {key: str(path) for key, path in vars(args).items() if key in
                      ('bundle', 'source_root', 'build_record', 'attempt') and path is not None}
            value = run_task(inline={'schema_version': 1, 'operation': 'report.trace', 'inputs': inputs}, output=args.output)
            code = value['exit_code']
        elif args.command == 'demo':
            value = run_task(inline={'schema_version': 1, 'operation': 'demo.review', 'inputs': {'bundle': str(args.bundle)}},
                             output=args.output)
            code = value['exit_code']
        else:
            value = run_task(manifest=args.manifest, output=args.output) if args.command == 'run' else run_task(
                inline={'schema_version': 1, 'operation': 'result.read', 'inputs': {'result': str(args.path)}}, output=args.output)
            code = value['exit_code']
    except (OperationError, ManifestError) as error:
        value = {'schema_version': 1, 'kind': 'kconc.cli-error', 'status': 'invalid', 'exit_code': 2,
                 'error': {'code': error.code, 'message': error.message}}
        code = 2
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return code

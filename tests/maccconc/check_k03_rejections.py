#!/usr/bin/env python3
"""K03 rejection checks in Debian. Uses the running experimental VM; never boots it.

These are infrastructure negative tests, not kernel bug scenarios. All temporary
bindings and evidence are placed in a new external output directory. Guest inputs
use a fresh /home/lab/k03/rejections-* directory and are retained for inspection.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import uuid

REPO = Path(__file__).resolve().parents[2]
HOST = REPO / 'scripts/maccconc-k03.py'
EXE_NAME = 'kcov-autorace-k03'


def tree_hashes(root):
    """Do not follow symlinks when copying a binding into test-owned storage."""
    entries = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Binding must not contain symlinks: ' + str(path))
        if path.is_file():
            entries[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not path.is_dir():
            raise ValueError('Unexpected binding file type: ' + str(path))
    return entries


def guest_state(session, output, executable):
    code = f'''import pathlib,json
matches=[]
for p in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  if str((p/'exe').resolve()) == {str(executable)!r}: matches.append(int(p.name))
 except OSError: pass
print(json.dumps({{'output_exists':pathlib.Path({str(output)!r}).exists(),'remaining_pids':matches}}))
'''
    return json.loads(session.guest_python(code).stdout)


def guest_snapshot(session, directory):
    # Exclude atime: reading a file to hash it can legitimately update atime.
    code = f'''import pathlib,json,hashlib,stat
root=pathlib.Path({str(directory)!r}); rows=[]
for p in [root]+sorted(root.rglob('*')):
 s=p.lstat()
 row={{'path':p.relative_to(root).as_posix(),'mode':stat.S_IMODE(s.st_mode),
       'inode':s.st_ino,'mtime_ns':s.st_mtime_ns,'type':'directory' if p.is_dir() else 'file'}}
 if p.is_file(): row.update(size=s.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 rows.append(row)
print(json.dumps(rows))
'''
    return json.loads(session.guest_python(code).stdout)


def host_rejection(session, args, name, source_binding, mutation, expected_message):
    case = session.out / name
    case.mkdir()
    copied = case / 'binding'
    shutil.copytree(source_binding, copied)
    mutation(copied)
    attempt = case / 'attempt'
    command = [sys.executable, str(HOST), 'replay', '--binding', str(copied),
               '--output', str(attempt), '--guest-build', str(args.guest_build),
               '--build-lab', str(args.build_lab), '--kernel-build', str(args.kernel_build),
               '--source-mapper', str(args.source_mapper)]
    command_index = len(session.commands)
    completed = session.run(command, timeout=180, check=False)
    result_path = attempt / 'result.json'
    actual = json.loads(result_path.read_text()) if result_path.exists() else {}
    checks = {
        'exit_is_1': completed.returncode == 1,
        'result_failed': actual.get('passed') is False,
        'expected_rejection': actual.get('error', {}).get('message') == expected_message,
        'no_execution_json': not (attempt / 'execution.json').exists(),
        'no_trace_directory': not (attempt / 'trace').exists(),
    }
    if name == 'wrong-binary-binding':
        identity_path = attempt / 'identity.json'
        checks['current_runtime_identity_passed'] = identity_path.exists() and json.loads(identity_path.read_text()).get('passed') is True
    row = {'name': name, 'passed': all(checks.values()), 'checks': checks,
           'command_index': command_index, 'attempt': str(attempt),
           'expected': {'exit_code': 1, 'error_message': expected_message,
                        'execution_json': 'absent', 'trace_directory': 'absent'},
           'actual': actual}
    session_host.save(case / 'check.json', row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--guest-build', type=Path, required=True)
    parser.add_argument('--source-mapper', type=Path, required=True)
    parser.add_argument('--build-lab', type=Path, default=Path.home() / 'os-concurrency-lab')
    parser.add_argument('--kernel-build', type=Path, default=Path.home() / 'os-concurrency-lab/build/linux-2fc2e45b0cd7')
    args = parser.parse_args()
    args.binding = args.binding.resolve(strict=True)
    args.output = args.output.resolve()
    args.source_mapper = args.source_mapper.resolve(strict=True)
    if args.output.exists() or args.output.is_relative_to(args.binding) or args.binding.is_relative_to(args.output):
        parser.error('--output must be new and separate from --binding')
    if args.output.is_relative_to(REPO) or REPO.is_relative_to(args.output):
        parser.error('--output must be outside the delivery repository')
    if not args.guest_build.is_absolute() or '..' in args.guest_build.parts or not args.guest_build.is_relative_to('/home/lab/k03'):
        parser.error('--guest-build must be normalized below /home/lab/k03')

    # Import is inert. Session creation below is the first QMP/SSH-capable step.
    global session_host
    spec = importlib.util.spec_from_file_location('k03_host_rejections', HOST)
    session_host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(session_host)
    session = None
    result = {'passed': False, 'scope': 'K03 input/binding/output rejection; not kernel bug detection',
              'cases': [], 'source_binding': str(args.binding),
              'driver_sha256': session_host.sha(Path(__file__)),
              'host_script_sha256': session_host.sha(HOST),
              'expected_case_count': 5}
    before = None
    try:
        before = tree_hashes(args.binding)
        binding = json.loads((args.binding / 'binding.json').read_text())
        plan = (args.binding / 'plan.txt').read_bytes()
        if hashlib.sha256(plan).hexdigest() != binding['plan_sha256']:
            raise ValueError('The supplied original binding already has a modified plan')
        for name, wanted in binding['reference_sha256'].items():
            if Path(name).name != name or session_host.sha(args.binding / 'reference' / name) != wanted:
                raise ValueError('The supplied original reference differs from its binding')
        if session_host.sha(args.source_mapper) != binding['source_mapper_sha256'] or \
                session_host.sha(REPO / 'adapters/maccconc/source-map.cpp') != binding['source_mapper_source_sha256'] or \
                session_host.sha(REPO / 'adapters/maccconc/k03_analysis.py') != binding['analyzer_sha256']:
            raise ValueError('Use the source mapper and analysis implementation of the final binding')
        session = session_host.Session(args)
        session_host.save(session.out / 'original-binding.before.json', before)
        if session.identity() != binding['identity']:
            raise ValueError('The original binding must match the current runtime before negative tests')
        executable = args.guest_build / 'bin' / EXE_NAME
        remote = '/home/lab/k03/rejections-' + uuid.uuid4().hex
        if guest_state(session, remote, executable)['remaining_pids']:
            raise RuntimeError('Another executor is active; run these checks without concurrent scenarios')
        result['guest_test_directory'] = remote
        # Exactly one byte changes; the saved plan hash/reference stay untouched.
        malformed = bytes([plan[0] ^ 1]) + plan[1:]
        lines = plan.splitlines()
        if len(lines) < 6:
            raise ValueError('Expected a generated plan with at least two stack elements')
        truncated = b'\n'.join(lines[:-1]) + b'\n'

        row = host_rejection(session, args, 'changed-plan', args.binding,
                             lambda path: (path / 'plan.txt').write_bytes(malformed),
                             'Saved plan hash mismatch: refused before guest execution')
        result['cases'].append(row)
        if not row['passed']:
            raise RuntimeError('Changed-plan rejection failed; stop before further negative cases')

        def change_binary(path):
            saved = json.loads((path / 'binding.json').read_text())
            original = saved['identity']['binaries'][EXE_NAME]
            saved['identity']['binaries'][EXE_NAME] = ('0' if original[0] != '0' else '1') + original[1:]
            session_host.save(path / 'binding.json', saved)

        row = host_rejection(session, args, 'wrong-binary-binding', args.binding, change_binary,
                             'Runtime identity mismatch: refused before guest execution')
        result['cases'].append(row)
        if not row['passed']:
            raise RuntimeError('Binary-binding rejection failed; stop before further negative cases')

        session.upload({'malformed.txt': malformed, 'truncated.txt': truncated}, remote)
        for name, expected in [('malformed', 'invalid K03 plan header'), ('truncated', 'invalid K03 stack element')]:
            output = remote + '/' + name + '-output'
            command_index = len(session.commands)
            completed = session.ssh(['sudo', '-n', 'timeout', '-k', '5', '15', str(executable),
                                     str(args.guest_build / 'bin/demo-dup-vs-close.so'), '--k03-replay',
                                     remote + '/' + name + '.txt', output], timeout=30, check=False)
            state = guest_state(session, output, executable)
            checks = {'exit_is_1': completed.returncode == 1,
                      'expected_rejection': expected in completed.stderr.decode(errors='replace'),
                      'output_absent': not state['output_exists'], 'no_executor_remains': state['remaining_pids'] == []}
            row = {'name': 'guest-' + name + '-plan', 'passed': all(checks.values()), 'checks': checks,
                   'command_index': command_index, 'state': state,
                   'expected': {'exit_code': 1, 'stderr_contains': expected, 'output_directory': 'absent'}}
            result['cases'].append(row)
            session_host.save(session.out / (name + '-plan.check.json'), row)
            if not row['passed']:
                raise RuntimeError('Guest plan rejection failed; stop before further negative cases')

        existing = remote + '/existing-output'
        session.guest_python(f'''from pathlib import Path
p=Path({existing!r}); p.mkdir(mode=0o700); (p/'sentinel.txt').write_bytes(b'K03 existing output must remain unchanged\\n')
(p/'nested').mkdir(mode=0o700); (p/'nested/data.bin').write_bytes(bytes(range(64)))
''')
        existing_before = guest_snapshot(session, existing)
        session_host.save(session.out / 'existing-output.before.json', existing_before)
        command_index = len(session.commands)
        completed = session.ssh(['sudo', '-n', 'timeout', '-k', '5', '15', str(executable),
                                 str(args.guest_build / 'bin/demo-dup-vs-close.so'),
                                 '--k03-record', existing], timeout=30, check=False)
        existing_after = guest_snapshot(session, existing)
        session_host.save(session.out / 'existing-output.after.json', existing_after)
        state = guest_state(session, existing, executable)
        checks = {'exit_is_1': completed.returncode == 1,
                  'expected_rejection': 'output directory already exists' in completed.stderr.decode(errors='replace'),
                  'directory_unchanged': existing_before == existing_after,
                  'output_still_exists': state['output_exists'], 'no_executor_remains': state['remaining_pids'] == []}
        row = {'name': 'guest-existing-output', 'passed': all(checks.values()), 'checks': checks,
               'command_index': command_index, 'state': state,
               'expected': {'exit_code': 1, 'stderr_contains': 'output directory already exists',
                            'directory_entries_content_mode_inode_mtime': 'unchanged'}}
        result['cases'].append(row)
        session_host.save(session.out / 'existing-output.check.json', row)
        result['passed'] = len(result['cases']) == 5 and all(row['passed'] for row in result['cases'])
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if before is not None:
            try:
                after = tree_hashes(args.binding)
                result['original_binding_unchanged'] = before == after
                if session:
                    session_host.save(session.out / 'original-binding.after.json', after)
                if before != after:
                    result['passed'] = False
            except Exception as error:
                result['passed'] = False
                result['original_binding_check_error'] = str(error)
        if session:
            session_host.save(session.out / 'result.json', result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

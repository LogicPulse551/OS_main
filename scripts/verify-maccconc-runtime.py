#!/usr/bin/env python3
"""Verify the isolated K02 guest and VSOCK transport; do not run K03 scenarios."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
LOCK = json.loads((REPO / 'configs/maccconc.lock.json').read_text())

GUEST_COLLECTOR = r'''
import gzip, hashlib, json, os, pathlib, platform, subprocess
root = pathlib.Path(BUILD)
def run(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {'command': args, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'command': args, 'exit_code': None, 'error': str(error)}
result = {'kernel': platform.release(), 'arch': platform.machine(), 'cpus': os.cpu_count(),
          'euid': os.geteuid(), 'os_release': pathlib.Path('/etc/os-release').read_text()}
try:
    result['config_text'] = gzip.decompress(pathlib.Path('/proc/config.gz').read_bytes()).decode()
except (OSError, EOFError, UnicodeError) as error:
    result['config_error'] = str(error)
try:
    result['regmap_symbols'] = {}
    for line in pathlib.Path('/proc/kallsyms').read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] in ('regmap_read', 'regmap_write'):
            result['regmap_symbols'][fields[2]] = {'address': fields[0], 'type': fields[1],
                                                   'module': fields[3] if len(fields) > 3 else None}
except OSError as error:
    result['regmap_symbols_error'] = str(error)
result['abi'] = run([str(root/'bin/kcov-probe'), '--abi-only'])
result['kcov'] = run([str(root/'bin/kcov-probe')])
result['ldd'] = {name: run(['ldd', str(root/'bin'/name)]) for name in
                 ('kcov-autorace', 'kcov-terminal', 'kcov-vsock-client')}
# These locked entry points reject argc == 1 before any kernel or socket work.
result['executor_usage'] = {name: run([str(root/'bin'/name)], timeout=10) for name in
                            ('kcov-autorace', 'kcov-terminal', 'kcov-vsock-client')}
try:
    result['guest_build'] = json.loads((root/'result.json').read_text())
    result['binary_sha256'] = {entry['name']: hashlib.sha256((root/'bin'/entry['name']).read_bytes()).hexdigest()
                               for entry in result['guest_build']['binaries']}
except (OSError, ValueError, KeyError) as error:
    result['guest_build_error'] = str(error)
print(json.dumps(result))
'''


def parse_config(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)', line.strip())
        disabled = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line.strip())
        if match:
            result[match[1]] = match[2]
        elif disabled:
            result[disabled[1]] = 'n'
    return result


def ssh(lab, argv, timeout=45, input_text=None):
    command = lab.ssh_args() + [shlex.join([str(arg) for arg in argv])]
    try:
        p = subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=timeout)
        return {'command': command, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'command': command, 'exit_code': None, 'error': str(error)}


def parsed_success(command):
    if command.get('exit_code') != 0:
        return None
    try:
        return json.loads(command['stdout'])
    except (ValueError, KeyError):
        return None


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def command_option(command, option):
    positions = [i for i, value in enumerate(command) if value == option]
    if len(positions) != 1 or positions[0] + 1 == len(command):
        raise ValueError(f'Expected exactly one {option} value in QEMU command')
    return command[positions[0] + 1]


def guest_vsock_cid(command):
    """Read the single VSOCK device emitted by this project's QEMU launcher."""
    devices = []
    for position, value in enumerate(command):
        if value != '-device':
            continue
        if position + 1 == len(command) or command[position + 1].startswith('-'):
            raise ValueError('QEMU -device has no device specification')
        fields = command[position + 1].split(',')
        if fields[0] == 'vhost-vsock-pci':
            devices.append(fields[1:])
    if len(devices) != 1:
        raise ValueError('Expected exactly one vhost-vsock-pci device in QEMU command')
    fields = [field for field in devices[0] if field.split('=', 1)[0] == 'guest-cid']
    if len(fields) != 1 or re.fullmatch(r'guest-cid=[0-9]+', fields[0]) is None:
        raise ValueError('Expected exactly one decimal guest-cid in VSOCK device')
    cid = int(fields[0].split('=', 1)[1])
    if not 3 <= cid <= 0xfffffffe:
        raise ValueError('VSOCK guest-cid must be between 3 and 4294967294')
    return cid


def live_launch_identity(lab_dir, launch):
    """Bind the recorded launch and its transport CID to the current process."""
    command = launch.get('command') if isinstance(launch, dict) else None
    if type(command) is not list or not command or any(type(arg) is not str or not arg for arg in command):
        raise ValueError('last-launch.command must be a nonempty list of argument strings')
    if Path(command[0]).name != 'qemu-system-x86_64':
        raise ValueError('Recorded launch is not the supported QEMU x86_64 executable')
    pidfile = lab_dir / 'run/qemu.pid'
    if Path(command_option(command, '-pidfile')).resolve() != pidfile.resolve():
        raise ValueError('Recorded QEMU PID file does not match the experimental lab')
    pid_text = pidfile.read_text().strip()
    if re.fullmatch(r'[1-9][0-9]*', pid_text) is None:
        raise ValueError('QEMU PID file must contain a positive decimal PID')
    pid = int(pid_text)
    raw = Path(f'/proc/{pid}/cmdline').read_bytes()
    if not raw or not raw.endswith(b'\0'):
        raise ValueError('Live QEMU command line is missing or malformed')
    running_command = [arg.decode() for arg in raw[:-1].split(b'\0')]
    if running_command != command:
        raise ValueError('Live QEMU command line differs from last-launch.command')
    cid = guest_vsock_cid(running_command)
    return {'passed': True, 'qemu_pid': pid, 'command': running_command,
            'guest_vsock_cid': cid, 'launch_command_matches': True,
            'boundary': 'Current PID command line equals the recorded launch; CID is taken from that live command.'}


def kernel_identity(lab_dir, source_lab, kernel_build, launch):
    expected_image = (kernel_build / 'arch/x86/boot/bzImage').resolve()
    actual_hash = file_sha256(expected_image)
    candidates = []
    records = list((source_lab / 'evidence/k02').glob('kernel-*/build-result.json'))
    records += list((source_lab / 'evidence/k05').glob('kernel-*/build-result.json'))
    records += list((source_lab / 'evidence/k06').glob('kernel-*/build-result.json'))
    records += list((source_lab / 'evidence/k07').glob('kernel-*/build-result.json'))
    records += list((source_lab / 'evidence/k10').glob('kernel-*/build-result.json'))
    records += list((source_lab / 'evidence/k11').glob('kernel-*/build-result.json'))
    for path in sorted(records):
        record = json.loads(path.read_text())
        image = next((entry for entry in record.get('artifacts', [])
                      if Path(entry['path']).resolve() == expected_image), None)
        if image is not None:
            candidates.append((path, record, image))
    if not candidates:
        raise ValueError('No kernel build-result.json identifies the supplied bzImage')
    record_path, record, image = candidates[-1]
    steps = json.loads(Path(record['steps']).read_text())
    config_path = (kernel_build / '.config').resolve()
    config_hash = file_sha256(config_path)
    config = next((entry for entry in record.get('artifacts', [])
                   if Path(entry['path']).resolve() == config_path), {})
    launch_artifact = launch.get('kernel_artifact') or {}
    launch_image = Path(command_option(launch['command'], '-kernel')).resolve()
    pid = int((lab_dir / 'run/qemu.pid').read_text().strip())
    running_command = [item.decode() for item in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if item]
    running_image = Path(command_option(running_command, '-kernel')).resolve()
    checks = {
        'build_source_matches': record.get('stage') == 'kernel' and
                                record.get('source_commit') == LOCK['sources']['linux']['commit'],
        'build_steps_passed': bool(steps) and all(step.get('exit_code') == 0 for step in steps),
        'image_paths_match': launch_image == expected_image and running_image == expected_image and
                             Path(launch_artifact.get('path', '')).resolve() == expected_image,
        'image_hashes_match': actual_hash == image['sha256'] ==
                              launch_artifact.get('sha256_before_launch') ==
                              launch_artifact.get('sha256_after_launch'),
        'image_sizes_match': expected_image.stat().st_size == image.get('bytes') == launch_artifact.get('bytes'),
        'config_matches_build': config_hash == config.get('sha256') and
                                config_path.stat().st_size == config.get('bytes'),
    }
    if record.get('task') in ('K05', 'K06', 'K07'):
        stage = record['task'].lower()
        expected_inputs = {f'kernel/{stage}/kconc-regmap.c', f'kernel/{stage}/kconc-regmap.h',
            f'kernel/{stage}/Kconfig.fragment', f'kernel/{stage}/Makefile.fragment',
            f'configs/kernel/{stage}-regmap.fragment', f'scripts/build-{stage}-kernel.py'}
        inputs = record.get('team_inputs', [])
        checks[stage+'_team_inputs_match'] = (len(inputs) == len(expected_inputs) and
            {x.get('path') for x in inputs} == expected_inputs and
            all(file_sha256(REPO/x['path']) == x.get('sha256') for x in inputs))
    if record.get('task') == 'K10':
        stage = {'rmw':'k06', 'mutex':'k07'}.get(record.get('family'))
        expected_inputs = {f'kernel/{stage}/kconc-regmap.c', f'kernel/{stage}/kconc-regmap.h',
            f'kernel/{stage}/Kconfig.fragment', f'kernel/{stage}/Makefile.fragment',
            f'configs/kernel/{stage}-regmap.fragment', f'scripts/build-{stage}-kernel.py',
            'patches/maccconc/0003-k10-control.patch', 'scripts/build-k10-kernel.py'}
        inputs = record.get('team_inputs', [])
        checks['k10_control_build_passed'] = (record.get('kind') == 'kconc.control-kernel.build'
            and record.get('passed') is True and stage is not None
            and record.get('original_family') == stage)
        checks['k10_team_inputs_match'] = (len(inputs) == 8 and
            {x.get('path') for x in inputs} == expected_inputs and
            all(file_sha256(REPO/x['path']) == x.get('sha256') for x in inputs))
        checks['k10_control_inputs_match'] = (
            record.get('control_patch_sha256') == file_sha256(REPO/'patches/maccconc/0003-k10-control.patch')
            and record.get('build_script_sha256') == file_sha256(REPO/'scripts/build-k10-kernel.py'))
        checks['k10_build_checks_passed'] = bool(record.get('checks')) and all(x is True for x in record['checks'].values())
        baseline = record.get('accepted_baseline', [])
        checks['k10_baseline_preserved'] = (record.get('accepted_baseline_unchanged') is True
            and bool(baseline) and all(file_sha256(Path(x['path'])) == x['sha256'] for x in baseline))
    if record.get('task') == 'K11':
        checks.update(k11_build_identity(record_path, record, source_lab, kernel_build))
    return {'passed': all(checks.values()), 'checks': checks,
            'expected_image': str(expected_image), 'image_sha256_now': actual_hash,
            'config_sha256_now': config_hash, 'build_config': config, 'launch_artifact': launch_artifact,
            'launch_image': str(launch_image), 'running_qemu_image_argument': str(running_image),
            'qemu_pid': pid, 'build_result': str(record_path), 'build_image': image,
            'source_commit': record.get('source_commit'),
            'boundary': 'Hashes before/after launch, current QEMU arguments and on-disk artifact hash; no running-memory hash.'}


def k11_build_identity(record_path, record, source_lab, kernel_build):
    """Validate the repaired build chain; KUnit runtime results are separate."""
    if record.get('recorder_policy_id') is not None:
        return k11_irqtail_build_identity(record_path, record, source_lab, kernel_build)
    checks = {}
    family = record.get('family')
    stage = {'rmw': 'k06', 'mutex': 'k07'}.get(family)
    repair = f'patches/maccconc/0004-k11-{family}-repair.patch'
    expected_inputs = {f'kernel/{stage}/kconc-regmap.c', f'kernel/{stage}/kconc-regmap.h',
        f'kernel/{stage}/Kconfig.fragment', f'kernel/{stage}/Makefile.fragment',
        f'configs/kernel/{stage}-regmap.fragment', f'scripts/build-{stage}-kernel.py',
        'patches/maccconc/0003-k10-control.patch', 'scripts/build-k10-kernel.py',
        repair, 'scripts/build-k11-kernel.py'}
    inputs = record.get('team_inputs', [])
    checks['k11_repaired_build_passed'] = (record.get('kind') == 'kconc.repaired-kernel.build'
        and record.get('passed') is True and stage is not None
        and record.get('profile_id') == 'kconc.k11.regmap-repair-v1'
        and record.get('original_family') == stage
        and record.get('variant') == ('shared-update-guard' if family == 'rmw' else 'shared-gate'))
    checks['k11_team_inputs_match'] = (len(inputs) == 10
        and {entry.get('path') for entry in inputs} == expected_inputs
        and all(file_sha256(REPO/entry['path']) == entry.get('sha256') for entry in inputs))
    checks['k11_build_checks_passed'] = (bool(record.get('checks'))
        and all(value is True for value in record['checks'].values()))
    if not checks['k11_repaired_build_passed'] or not checks['k11_team_inputs_match']:
        return checks
    spec = importlib.util.spec_from_file_location('k11_runtime_build_verifier', REPO/'scripts/build-k11-kernel.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    source_lab = Path(source_lab).resolve()
    kernel_build = Path(kernel_build).resolve()
    source = Path(record['source']).resolve()
    checks['k11_new_tree_paths_match'] = (re.fullmatch(r'linux-'+stage+r'-k11-[A-Za-z0-9][A-Za-z0-9._-]*', kernel_build.name) is not None
        and kernel_build.parent == source_lab/'build'
        and source == source_lab/'sources'/kernel_build.name
        and Path(record['kernel_build']).resolve() == kernel_build
        and (kernel_build/'source').resolve() == source)
    checks['k11_repair_inputs_match'] = (record.get('repair_patch') == {'path': repair, 'sha256': file_sha256(REPO/repair)}
        and record.get('control_patch_sha256') == file_sha256(REPO/'patches/maccconc/0003-k10-control.patch')
        and record.get('build_script_sha256') == file_sha256(REPO/'scripts/build-k11-kernel.py'))
    parent_entry = record.get('accepted_parent_build_record', {})
    parent_path = Path(parent_entry.get('path', ''))
    checks['k11_parent_record_matches'] = parent_entry == builder.artifact(parent_path)
    parent, parent_source, parent_build, preserved = builder.verify_parent(
        parent_path, source_lab, family, LOCK['sources']['linux']['commit'])
    checks['k11_accepted_baselines_preserved'] = (record.get('accepted_baseline_unchanged') is True
        and record.get('accepted_parent') == preserved and builder.unchanged(preserved))
    expected_delta = {'CONFIG_KCONC_REGMAP_KUNIT_TEST': {'before': None, 'after': 'y'}}
    checks['k11_exact_config_delta'] = (record.get('config_delta') == expected_delta
        and builder.config_delta(parent_build/'.config', kernel_build/'.config') == expected_delta)
    config = builder.config_values(kernel_build/'.config')
    checks['k11_kunit_config_and_suite'] = (all(config.get(name) == 'y' for name in
        ('CONFIG_KCONC_REGMAP_KUNIT_TEST', 'CONFIG_KUNIT', 'CONFIG_KUNIT_DEBUGFS',
         'CONFIG_KUNIT_DEFAULT_ENABLED', 'CONFIG_KUNIT_AUTORUN_ENABLED'))
        and record.get('kunit_suite') == 'kconc-k11-'+family
        and record.get('kunit_expected_cases') == (6 if family == 'rmw' else 4)
        and record.get('kunit_runtime_status') == 'not_run_by_builder')
    expected_sources = builder.snapshot(source, builder.REGMAP_INPUTS+[builder.KUNIT_HEADER])
    checks['k11_repaired_sources_match'] = (record.get('regmap_sources') == expected_sources
        and record.get('repaired_driver') == builder.artifact(source/'drivers/base/regmap/kconc-regmap.c')
        and record.get('kunit_header') == builder.artifact(source/builder.KUNIT_HEADER))
    checks['k11_upstream_abi_and_control_unchanged'] = (all(
        file_sha256(source/'drivers/base/regmap'/name) == file_sha256(parent_source/'drivers/base/regmap'/name)
        for name in ('kconc-regmap.h', 'regmap.c', 'regmap-ram.c', 'Makefile'))
        and record.get('patched_kcov_sha256') == parent['patched_kcov_sha256']
        and file_sha256(source/'kernel/kcov.c') == parent['patched_kcov_sha256'])
    checks['k11_all_artifacts_match'] = (record.get('artifacts') == builder.snapshot(kernel_build, builder.ARTIFACTS)
        and record.get('regmap_objects') == builder.snapshot(kernel_build, builder.REGMAP_OBJECTS))
    # This is read-only: confirm that the concrete repaired sources contain the
    # exact declared patch, including the shared-body KUnit header and Kconfig.
    patch_check = subprocess.run(['git', '-C', str(source), 'apply', '--reverse', '--check', str(REPO/repair)],
        capture_output=True, text=True, timeout=30)
    checks['k11_declared_repair_present'] = patch_check.returncode == 0
    return checks


def k11_irqtail_build_identity(record_path, record, source_lab, kernel_build):
    """Validate the fresh recorder guard plus both preserved build parents."""
    checks = {}
    family = record.get('family')
    stage = {'rmw': 'k06', 'mutex': 'k07'}.get(family)
    repair = f'patches/maccconc/0004-k11-{family}-repair.patch'
    expected_inputs = {f'kernel/{stage}/kconc-regmap.c', f'kernel/{stage}/kconc-regmap.h',
        f'kernel/{stage}/Kconfig.fragment', f'kernel/{stage}/Makefile.fragment',
        f'configs/kernel/{stage}-regmap.fragment', f'scripts/build-{stage}-kernel.py',
        'patches/maccconc/0003-k10-control.patch', 'scripts/build-k10-kernel.py',
        repair, 'scripts/build-k11-kernel.py', 'patches/maccconc/0005-k11-irq-tail.patch',
        'scripts/build-k11-irqtail-kernel.py'}
    inputs = record.get('team_inputs', [])
    checks['k11_repaired_build_passed'] = (record.get('kind') == 'kconc.repaired-kernel.build'
        and record.get('passed') is True and stage is not None
        and record.get('profile_id') == 'kconc.k11.regmap-repair-v1'
        and record.get('recorder_policy_id') == 'kconc.k11.x86-irq-entry-guard-v1'
        and record.get('original_family') == stage
        and record.get('variant') == ('shared-update-guard' if family == 'rmw' else 'shared-gate'))
    checks['k11_team_inputs_match'] = (len(inputs) == 12
        and {entry.get('path') for entry in inputs} == expected_inputs
        and all(file_sha256(REPO/entry['path']) == entry.get('sha256') for entry in inputs))
    checks['k11_build_checks_passed'] = (bool(record.get('checks'))
        and all(value is True for value in record['checks'].values()))
    if not checks['k11_repaired_build_passed'] or not checks['k11_team_inputs_match']:
        return checks
    spec = importlib.util.spec_from_file_location('k11_runtime_build_verifier', REPO/'scripts/build-k11-irqtail-kernel.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    source_lab = Path(source_lab).resolve()
    kernel_build = Path(kernel_build).resolve()
    source = Path(record['source']).resolve()
    checks['k11_new_tree_paths_match'] = (re.fullmatch(r'linux-'+stage+r'-k11-[A-Za-z0-9][A-Za-z0-9._-]*', kernel_build.name) is not None
        and kernel_build.parent == source_lab/'build'
        and source == source_lab/'sources'/kernel_build.name
        and Path(record['kernel_build']).resolve() == kernel_build
        and (kernel_build/'source').resolve() == source)
    checks['k11_repair_inputs_match'] = (record.get('repair_patch') == {'path': repair, 'sha256': file_sha256(REPO/repair)}
        and record.get('control_patch_sha256') == file_sha256(REPO/'patches/maccconc/0003-k10-control.patch')
        and record.get('build_script_sha256') == file_sha256(REPO/'scripts/build-k11-irqtail-kernel.py')
        and record.get('build_script_path') == builder.BUILD_SCRIPT
        and record.get('recorder_patch') == {'path': builder.RECORDER_PATCH,
            'sha256': file_sha256(REPO/builder.RECORDER_PATCH)})
    parent_entry = record.get('accepted_parent_build_record', {})
    parent_path = Path(parent_entry.get('path', ''))
    checks['k11_parent_record_matches'] = parent_entry == builder.artifact(parent_path)
    parent, parent_source, parent_build, preserved = builder.verify_parent(
        parent_path, source_lab, family, LOCK['sources']['linux']['commit'])
    checks['k11_accepted_baselines_preserved'] = (record.get('accepted_baseline_unchanged') is True
        and record.get('accepted_parent') == preserved and builder.unchanged(preserved))
    repaired_entry = record.get('repaired_parent_build_record', {})
    repaired_path = Path(repaired_entry.get('path', ''))
    checks['k11_fixed_parent_record_matches'] = repaired_entry == builder.artifact(repaired_path)
    fixed, fixed_source, fixed_build, fixed_rows = builder.verify_repaired_parent(
        repaired_path, source_lab, family, parent, parent_path)
    checks['k11_fixed_parent_preserved'] = (record.get('repaired_parent_unchanged') is True
        and record.get('repaired_parent') == fixed_rows and builder.unchanged(fixed_rows))
    checks['k11_fixed_parent_config_unchanged'] = not builder.config_delta(
        fixed_build/'.config', kernel_build/'.config')
    expected_delta = {'CONFIG_KCONC_REGMAP_KUNIT_TEST': {'before': None, 'after': 'y'}}
    checks['k11_exact_config_delta'] = (record.get('config_delta') == expected_delta
        and builder.config_delta(parent_build/'.config', kernel_build/'.config') == expected_delta)
    config = builder.config_values(kernel_build/'.config')
    checks['k11_kunit_config_and_suite'] = (all(config.get(name) == 'y' for name in
        ('CONFIG_KCONC_REGMAP_KUNIT_TEST', 'CONFIG_KUNIT', 'CONFIG_KUNIT_DEBUGFS',
         'CONFIG_KUNIT_DEFAULT_ENABLED', 'CONFIG_KUNIT_AUTORUN_ENABLED'))
        and record.get('kunit_suite') == 'kconc-k11-'+family
        and record.get('kunit_expected_cases') == (6 if family == 'rmw' else 4)
        and record.get('kunit_runtime_status') == 'not_run_by_builder')
    expected_sources = builder.snapshot(source, builder.REGMAP_INPUTS+[builder.KUNIT_HEADER])
    checks['k11_repaired_sources_match'] = (record.get('regmap_sources') == expected_sources
        and record.get('repaired_driver') == builder.artifact(source/'drivers/base/regmap/kconc-regmap.c')
        and record.get('kunit_header') == builder.artifact(source/builder.KUNIT_HEADER))
    checks['k11_upstream_abi_and_parent_control_match'] = (all(
        file_sha256(source/'drivers/base/regmap'/name) == file_sha256(parent_source/'drivers/base/regmap'/name)
        for name in ('kconc-regmap.h', 'regmap.c', 'regmap-ram.c', 'Makefile'))
        and record.get('parent_control_sha256') == parent['patched_kcov_sha256']
        and file_sha256(fixed_source/'kernel/kcov.c') == parent['patched_kcov_sha256'])
    checks['k11_new_recorder_sources_match'] = (
        record.get('recorder_sources') == builder.snapshot(source, builder.RECORDER_SOURCES)
        and record.get('patched_kcov_sha256') == file_sha256(source/'kernel/kcov.c')
        and record['patched_kcov_sha256'] != parent['patched_kcov_sha256'])
    checks['k11_recorder_scope_matches'] = (record.get('recorder_scope') == dict(
        architecture='x86_64', entry='IDT', fred=False, xen=False,
        excludes='complete asynchronous IRQ wrapper before record or DI-stack mutation',
        synchronous_exceptions_unchanged=True, irq_enable_state_unchanged=True,
        remote_softirq='existing exception retained; nested remote/IRQ support not claimed')
        and all(config.get(name) in (None, 'n') for name in ('CONFIG_X86_FRED', 'CONFIG_XEN')))
    checks['k11_all_artifacts_match'] = (record.get('artifacts') == builder.snapshot(kernel_build, builder.ARTIFACTS)
        and record.get('regmap_objects') == builder.snapshot(kernel_build, builder.REGMAP_OBJECTS))
    # This is read-only: confirm that the concrete repaired sources contain the
    # exact declared patch, including the shared-body KUnit header and Kconfig.
    patch_check = subprocess.run(['git', '-C', str(source), 'apply', '--reverse', '--check', str(REPO/repair)],
        capture_output=True, text=True, timeout=30)
    checks['k11_declared_repair_present'] = patch_check.returncode == 0
    recorder_check = subprocess.run(['git', '-C', str(source), 'apply', '--reverse', '--check',
        str(REPO/builder.RECORDER_PATCH)], capture_output=True, text=True, timeout=30)
    checks['k11_declared_recorder_guard_present'] = recorder_check.returncode == 0
    return checks


def check_transport(lab, guest_build, evidence, expected_guest_cid):
    if type(expected_guest_cid) is not int or not 3 <= expected_guest_cid <= 0xfffffffe:
        raise ValueError('Expected a verified QEMU guest CID between 3 and 4294967294')
    ready = evidence / 'vsock-ready.json'
    stdout_path, stderr_path = evidence / 'vsock-server.stdout.jsonl', evidence / 'vsock-server.stderr.txt'
    runtime = LOCK['runtime']
    command = [sys.executable, str(REPO / '实验环境/maccconc/probes/vsock-server.py'),
               '--expected-peer-cid', str(expected_guest_cid), '--port', str(runtime['vsock_port']),
               '--timeout', '30', '--ready-file', str(ready)]
    result = {'server_command': command, 'expected_guest_cid': expected_guest_cid,
              'passed': False, 'scope': 'VSOCK transport, not GUI protocol'}
    process = None
    with stdout_path.open('w') as output, stderr_path.open('w') as errors:
        try:
            process = subprocess.Popen(command, stdout=output, stderr=errors)
            deadline = time.monotonic() + 8
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not ready.exists() or process.poll() is not None:
                raise RuntimeError('VSOCK server did not become ready')
            result['client'] = ssh(lab, [str(guest_build / 'bin/vsock-client'),
                                        str(runtime['host_vsock_cid']), str(runtime['vsock_port']), '30'])
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                result['server_error'] = 'server did not finish after the guest attempt'
        except (OSError, RuntimeError) as error:
            result['error'] = str(error)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if process is not None:
                result['server_exit_code'] = process.returncode
    result['server_stdout'] = stdout_path.read_text()
    result['server_stderr'] = stderr_path.read_text()
    messages = []
    for line in result['server_stdout'].splitlines():
        try:
            messages.append(json.loads(line))
        except ValueError:
            pass
    server = next((item for item in reversed(messages) if item.get('passed') is True), None)
    client = parsed_success(result.get('client', {}))
    if result.get('server_exit_code') == 0 and server and client and client.get('passed') is True:
        result['checks'] = {
            'nonce_match': all(isinstance(client.get(field), str) and
                               re.fullmatch(r'[0-9a-f]{64}', client[field]) is not None and
                               client[field] == server.get(field)
                               for field in ('guest_nonce', 'host_nonce')),
            'port_matches': client.get('port') == server.get('port') == runtime['vsock_port'],
            'client_target_host_cid': client.get('host_cid') == runtime['host_vsock_cid'],
            'client_observed_host_cid': client.get('observed_peer_cid') == runtime['host_vsock_cid'],
            'server_observed_guest_cid': server.get('observed_peer_cid') == expected_guest_cid,
            # getsockname reports the bind address; Linux autobind may keep ANY.
            'client_bind_cid_valid': client.get('socket_bind_cid') in
                                     (0xffffffff, expected_guest_cid),
        }
        result['passed'] = all(result['checks'].values())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-build', required=True, type=PurePosixPath)
    parser.add_argument('--kernel-build', type=Path)
    parser.add_argument('--build-lab', type=Path,
                        help='Lab containing the original K02 build evidence; useful for a later VM fork')
    parser.add_argument('--transport-only', action='store_true')
    args = parser.parse_args()
    result = {'task': 'K02', 'mode': 'transport-only' if args.transport_only else 'full',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed': False, 'checks': {}, 'errors': [], 'k03_scenario_run': False}
    evidence = None
    phase = 'preflight'
    exit_code = 1
    try:
        if not os.environ.get('LAB_DIR'):
            raise ValueError('LAB_DIR must explicitly identify the independent experimental guest')
        lab_dir = Path(os.environ['LAB_DIR']).expanduser().resolve()
        baseline = (Path.home() / 'os-concurrency-lab').resolve()
        if lab_dir == baseline or lab_dir.is_relative_to(REPO) or REPO.is_relative_to(lab_dir):
            raise ValueError('LAB_DIR must be separate from the baseline and delivery repository')
        fork = json.loads((lab_dir / 'evidence/baseline-fork.json').read_text())
        if Path(fork['target_lab']).resolve() != lab_dir or Path(fork['source_lab']).resolve() == lab_dir:
            raise ValueError('Independent baseline-fork identity does not match LAB_DIR')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        evidence = lab_dir / 'evidence' / f'k02-runtime-{stamp}-{uuid.uuid4().hex[:6]}'
        evidence.mkdir()
        result.update(lab_dir=str(lab_dir), guest_build=str(args.guest_build), evidence_directory=str(evidence))
        result['implementation_sha256'] = {
            relative: file_sha256(REPO / relative) for relative in (
                'scripts/verify-maccconc-runtime.py', 'configs/maccconc.lock.json',
                'configs/kernel/maccconc-x86_64.fragment',
                '实验环境/openeuler-x86_64/lab.py',
                '实验环境/maccconc/probes/vsock-server.py')}
        if not args.guest_build.is_absolute() or '..' in args.guest_build.parts:
            raise ValueError('--guest-build must be an absolute normalized guest path')
        launch = json.loads((lab_dir / 'evidence/last-launch.json').read_text())
        result['launch'] = launch
        phase = 'live-launch-identity'
        result['live_launch_identity'] = live_launch_identity(lab_dir, launch)
        result['checks']['live_launch_identity'] = result['live_launch_identity']['passed']
        network = command_option(launch['command'], '-netdev')
        port = re.search(r'hostfwd=tcp:127\.0\.0\.1:(\d+)-:22(?:,|$)', network)
        if port is None:
            raise ValueError('Cannot identify experimental SSH forwarding port from last-launch.json')
        if os.environ.get('LAB_SSH_PORT', port[1]) != port[1]:
            raise ValueError('LAB_SSH_PORT does not match the independent guest launch')
        os.environ['LAB_DIR'] = str(lab_dir)
        os.environ['LAB_SSH_PORT'] = port[1]
        spec = importlib.util.spec_from_file_location('k02_lab', REPO / '实验环境/openeuler-x86_64/lab.py')
        lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab)
        phase = 'qmp'
        result['qmp'] = {'status': lab.qmp('query-status'), 'kvm': lab.qmp('query-kvm'),
                         'cpus': lab.qmp('query-cpus-fast')}
        result['checks']['vm_running'] = result['qmp']['status'].get('running') is True
        if not result['checks']['vm_running']:
            raise RuntimeError('Experimental VM is not running')
        if not args.transport_only:
            phase = 'guest-runtime'
            build_lab = (args.build_lab or Path(fork['source_lab'])).expanduser().resolve()
            kernel_build = (args.kernel_build or build_lab / 'build/linux-2fc2e45b0cd7').expanduser().resolve()
            expected_release = (kernel_build / 'include/config/kernel.release').read_text().strip()
            result['kernel_build'] = str(kernel_build)
            result['build_lab'] = str(build_lab)
            result['expected_kernel_release'] = expected_release
            result['kernel_identity'] = kernel_identity(lab_dir, build_lab, kernel_build, launch)
            result['checks']['kernel_artifact_identity'] = result['kernel_identity']['passed']
            result['guest_command'] = ssh(lab, ['sudo', '-n', 'python3', '-'], timeout=150,
                                          input_text=f'BUILD = {str(args.guest_build)!r}\n' + GUEST_COLLECTOR)
            guest = parsed_success(result['guest_command'])
            if guest is None:
                raise RuntimeError('Guest collector failed; see guest_command')
            # Full .config is an artifact rather than a large inline JSON field.
            config_text = guest.pop('config_text', '')
            result['guest_command'].pop('stdout', None)
            (evidence / 'guest.config').write_text(config_text)
            guest['config_sha256'] = hashlib.sha256(config_text.encode()).hexdigest() if config_text else None
            actual = parse_config(config_text)
            required = parse_config((REPO / LOCK['build']['kernel']['fragment']).read_text())
            result['config_mismatches'] = {key: {'expected': value, 'actual': actual.get(key, 'n')}
                                           for key, value in required.items() if actual.get(key, 'n') != value}
            checks = result['checks']
            checks.update(kernel_release_matches=guest['kernel'] == expected_release,
                          guest_x86_64=guest['arch'] == 'x86_64', guest_root_collector=guest['euid'] == 0,
                          guest_is_openeuler='openEuler' in guest['os_release'],
                          kvm_enabled=result['qmp']['kvm'].get('enabled') is True,
                          four_cpus=guest['cpus'] == 4 and len(result['qmp']['cpus']) == 4,
                          kernel_config_matches=bool(config_text) and not result['config_mismatches'],
                          full_kernel_config_identity=bool(config_text) and
                              guest['config_sha256'] == result['kernel_identity']['config_sha256_now'])
            symbols = guest.get('regmap_symbols', {})
            checks['regmap_built_in_symbols'] = all(name in symbols and
                int(symbols[name]['address'], 16) != 0 and symbols[name]['module'] is None
                for name in ('regmap_read', 'regmap_write'))
            abi, kcov = parsed_success(guest['abi']), parsed_success(guest['kcov'])
            checks['guest_userspace_abi'] = bool(abi and abi.get('passed') is True)
            checks['kcov_memory_runtime'] = bool(kcov and kcov.get('passed') is True and
                kcov.get('kernel_record_bytes') == LOCK['runtime']['uapi_expected_x86_64']['memory_access_record_bytes'])
            checks['executor_dynamic_libraries'] = all(item.get('exit_code') == 0 and
                'not found' not in (item.get('stdout', '') + item.get('stderr', ''))
                for item in guest['ldd'].values())
            checks['executor_usage_entrypoints'] = all(item.get('exit_code') == 1 and
                'invocation: ' in item.get('stderr', '') and '<path to test .so>' in item.get('stderr', '')
                for item in guest['executor_usage'].values())
            build = guest.get('guest_build', {})
            entries = build.get('binaries', [])
            expected_names = {'kcov-autorace', 'kcov-terminal', 'kcov-vsock-client', 'kcov-probe', 'vsock-client'}
            checks['guest_binary_identity'] = build.get('passed') is True and len(entries) == 5 and \
                {item['name'] for item in entries} == expected_names and all(
                guest.get('binary_sha256', {}).get(item['name']) == item['sha256'] for item in entries)
            result['guest'] = guest
        phase = 'vsock'
        result['vsock'] = check_transport(lab, args.guest_build, evidence,
                                          result['live_launch_identity']['guest_vsock_cid'])
        result['checks']['vsock_bidirectional_nonce_match'] = result['vsock']['passed']
        result['passed'] = bool(result['checks']) and all(result['checks'].values())
        exit_code = 0 if result['passed'] else 1
    except (Exception, KeyboardInterrupt) as error:
        result['errors'].append({'phase': phase, 'type': type(error).__name__, 'message': str(error)})
        exit_code = 130 if isinstance(error, KeyboardInterrupt) else 1
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result['exit_code'] = exit_code
    if evidence is not None:
        (evidence / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

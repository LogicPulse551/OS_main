#!/usr/bin/env python3
"""Build a separate repaired K11 kernel from a verified K10 parent.

Never write accepted sources/output trees. Reconstruct the accepted K10 bytes,
apply one family repair patch, enable only the shared-body KUnit suite, and
build into a fresh output directory. Fresh samples/candidates are mandatory.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]
PROFILE_ID = 'kconc.k11.regmap-repair-v1'
CONTROL_PATCH = 'patches/maccconc/0003-k10-control.patch'
EXPECTED_PARENTS = {
    'rmw': 'e194d377fc07fdf5a50d8f243c92ea1366b38380e5729138c818256628953f16',
    'mutex': '3f978b6feec914d315d275b0ecbf71f4adbae1394f374a1f924ec8dd0c56118b'}
ARTIFACTS = ['arch/x86/boot/bzImage', 'vmlinux', '.config', 'System.map']
REGMAP_INPUTS = ['drivers/base/regmap/'+name for name in
    ('kconc-regmap.c', 'kconc-regmap.h', 'regmap.c', 'regmap-ram.c', 'Kconfig', 'Makefile')]
REGMAP_OBJECTS = ['drivers/base/regmap/'+name for name in
    ('kconc-regmap.o', 'regmap.o', 'regmap-ram.o')]
KUNIT_HEADER = 'drivers/base/regmap/kconc-regmap-kunit.h'


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            result.update(block)
    return result.hexdigest()


def artifact(path):
    path = Path(path)
    return dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)


def new_paths(lab, family, name):
    lab = Path(lab).resolve()
    stage = {'rmw': 'k06', 'mutex': 'k07'}.get(family)
    if stage is None or not re.fullmatch(r'linux-'+stage+r'-k11-[A-Za-z0-9][A-Za-z0-9._-]*', name):
        raise ValueError('Use linux-k06-k11-<suffix> for rmw or linux-k07-k11-<suffix> for mutex')
    if lab.is_relative_to(REPO) or REPO.is_relative_to(lab):
        raise ValueError('Build lab must be separate from the repository')
    source, build = lab/'sources'/name, lab/'build'/name
    for path in (source, build):
        if path.exists() or path.is_symlink():
            raise ValueError('Source/output must be new; keep failed builds: '+str(path))
        if path.resolve().parent != path.parent.resolve() or not path.parent.resolve().is_relative_to(lab):
            raise ValueError('Build path escaped the selected lab')
    return lab, source, build


def snapshot(root, names):
    root = Path(root).resolve()
    result = []
    for name in names:
        path = root/name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            raise RuntimeError('Expected ordinary accepted file: '+str(path))
        result.append(artifact(path))
    return result


def unchanged(rows):
    return all(Path(row['path']).is_file() and not Path(row['path']).is_symlink()
               and artifact(row['path']) == row for row in rows)


def config_values(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        else:
            match = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line)
            if not match:
                continue
            key, value = match.group(1), 'n'
        if key in result:
            raise RuntimeError('Duplicate config symbol: '+key)
        result[key] = value
    return result


def config_delta(before, after):
    old, new = config_values(before), config_values(after)
    return {key: dict(before=old.get(key), after=new.get(key))
            for key in sorted(old.keys() | new.keys()) if old.get(key) != new.get(key)}


def verify_parent(record_path, lab, family, locked_commit):
    record_path = Path(record_path).resolve()
    if (not record_path.is_relative_to(lab/'evidence/k10') or
            record_path.name != 'build-result.json' or record_path.is_symlink()):
        raise RuntimeError('Parent must be an original K10 build-result.json in this lab')
    parent = json.loads(record_path.read_text())
    stage = 'k06' if family == 'rmw' else 'k07'
    source = lab/'sources'/('linux-'+stage+'-k10-control-01')
    build = lab/'build'/('linux-'+stage+'-k10-control-01')
    if (parent.get('kind') != 'kconc.control-kernel.build' or parent.get('task') != 'K10'
            or parent.get('passed') is not True or parent.get('family') != family
            or parent.get('source_commit') != locked_commit
            or parent.get('source') != str(source) or parent.get('kernel_build') != str(build)
            or parent.get('accepted_baseline_unchanged') is not True):
        raise RuntimeError('Parent record is not the selected accepted K10 family')
    rows = snapshot(build, ARTIFACTS+REGMAP_OBJECTS)
    rows += snapshot(source, REGMAP_INPUTS+['kernel/kcov.c'])
    by_path = {row['path']: row for row in rows}
    for field, expected_count in [('artifacts', 4), ('regmap_sources', 6), ('regmap_objects', 3)]:
        if len(parent.get(field, [])) != expected_count:
            raise RuntimeError('Parent provenance incomplete: '+field)
        for row in parent[field]:
            if by_path.get(row['path']) != row:
                raise RuntimeError('Parent artifact/source changed: '+row['path'])
    if (sha(build/'arch/x86/boot/bzImage') != EXPECTED_PARENTS[family]
            or sha(source/'kernel/kcov.c') != parent['patched_kcov_sha256']):
        raise RuntimeError('Parent kernel/control identity differs')
    if not unchanged(parent['accepted_baseline']):
        raise RuntimeError('An earlier accepted baseline changed')
    rows += parent['accepted_baseline']
    rows.append(artifact(record_path))
    return parent, source, build, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-lab', type=Path, required=True)
    parser.add_argument('--family', choices=tuple(EXPECTED_PARENTS), required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--parent-build-record', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=6)
    args = parser.parse_args()
    try:
        if not 1 <= args.jobs <= 16:
            raise ValueError('Use 1..16 jobs')
        lab, source, build = new_paths(args.build_lab, args.family, args.name)
    except ValueError as error:
        parser.error(str(error))
    stage = 'k06' if args.family == 'rmw' else 'k07'
    repair_patch = f'patches/maccconc/0004-k11-{args.family}-repair.patch'
    os.environ['LAB_DIR'] = str(lab)
    spec = importlib.util.spec_from_file_location('k11_base_build', REPO/'scripts/build-maccconc.py')
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = lab/'evidence/k11'/('kernel-'+args.family+'-'+stamp)
    evidence.mkdir(parents=True)
    steps = []
    env = os.environ.copy()
    for name in ('KBUILD_OUTPUT', 'KBUILD_SRC', 'KCONFIG_CONFIG', 'O'):
        env.pop(name, None)
    env['KCFLAGS'] = base.LOCK['build']['kernel']['kcflags']

    def run(name, command, cwd=REPO):
        command = list(map(str, command))
        row = dict(name=name, command=command, cwd=str(cwd), KCFLAGS=env['KCFLAGS'],
                   exit_code=None, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   log=str(evidence/(name+'.log')))
        steps.append(row)
        (evidence/'steps.json').write_text(json.dumps(steps, indent=2)+'\n')
        print(name, flush=True)
        with Path(row['log']).open('w') as stream:
            completed = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        row.update(exit_code=completed.returncode, finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        (evidence/'steps.json').write_text(json.dumps(steps, indent=2)+'\n')
        if completed.returncode:
            raise RuntimeError('Build step failed: '+name+'; '+row['log'])
        return Path(row['log']).read_text()

    result = dict(kind='kconc.repaired-kernel.build', stage='kernel', task='K11',
        profile_id=PROFILE_ID, family=args.family, variant='shared-update-guard' if args.family == 'rmw' else 'shared-gate',
        passed=False, source=str(source), kernel_build=str(build), steps=str(evidence/'steps.json'))
    preserved = []
    try:
        parent, old_source, old_build, preserved = verify_parent(
            args.parent_build_record, lab, args.family, base.LOCK['sources']['linux']['commit'])
        result['accepted_parent_build_record'] = artifact(args.parent_build_record.resolve())
        (evidence/'accepted-baseline.json').write_text(json.dumps(preserved, indent=2)+'\n')
        run('verify-pinned-source', ['python3', REPO/'scripts/maccconc-sources.py', 'verify',
            '--component', 'linux', '--source-root', lab/'sources/k01'])
        head = run('verify-parent-source-head', ['git', '-C', old_source, 'rev-parse', 'HEAD']).strip()
        if head != base.LOCK['sources']['linux']['commit']:
            raise RuntimeError('Parent source HEAD is not pinned')
        identity = base.verify_llvm_identity()
        (evidence/'llvm-identity.json').write_text(json.dumps(identity, indent=2)+'\n')
        parent_input_names = [row['path'] for row in parent['team_inputs']]
        inputs = snapshot(REPO, parent_input_names+[repair_patch, 'scripts/build-k11-kernel.py'])
        actual_inputs = {str(Path(row['path']).relative_to(REPO)): row['sha256'] for row in inputs}
        if any(actual_inputs.get(row['path']) != row['sha256'] for row in parent['team_inputs']):
            raise RuntimeError('Accepted K10 repository inputs changed')
        source.mkdir(parents=True)
        run('clone', ['git', 'clone', '--shared', '--no-checkout', lab/'sources/k01/linux', source])
        run('checkout', ['git', '-C', source, 'checkout', '--detach', head])
        for name in ('kconc-regmap.c', 'kconc-regmap.h'):
            shutil.copyfile(REPO/f'kernel/{stage}'/name, source/'drivers/base/regmap'/name)
        for dest, fragment in [('Kconfig', 'Kconfig.fragment'), ('Makefile', 'Makefile.fragment')]:
            with (source/'drivers/base/regmap'/dest).open('a') as stream:
                stream.write('\n'+(REPO/f'kernel/{stage}'/fragment).read_text())
        run('check-control-patch', ['git', '-C', source, 'apply', '--check', REPO/CONTROL_PATCH])
        run('apply-control-patch', ['git', '-C', source, 'apply', REPO/CONTROL_PATCH])
        for name in REGMAP_INPUTS+['kernel/kcov.c']:
            if sha(source/name) != sha(old_source/name):
                raise RuntimeError('Reconstructed K10 parent differs: '+name)
        run('check-repair-patch', ['git', '-C', source, 'apply', '--check', REPO/repair_patch])
        run('apply-repair-patch', ['git', '-C', source, 'apply', REPO/repair_patch])
        repaired_sources = snapshot(source, REGMAP_INPUTS+[KUNIT_HEADER, 'kernel/kcov.c'])
        for name in ('kconc-regmap.h', 'regmap.c', 'regmap-ram.c', 'Makefile'):
            if sha(source/'drivers/base/regmap'/name) != sha(old_source/'drivers/base/regmap'/name):
                raise RuntimeError('Repair unexpectedly changed ABI/upstream core/build object list')
        if sha(source/'kernel/kcov.c') != parent['patched_kcov_sha256']:
            raise RuntimeError('Repair unexpectedly changed K10 control')
        run('team-diff', ['git', '-C', source, 'diff', '--binary'])
        build.mkdir(parents=True)
        shutil.copyfile(old_build/'.config', build/'.config')
        run('enable-repair-kunit', [source/'scripts/config', '--file', build/'.config',
            '--enable', 'KCONC_REGMAP_KUNIT_TEST'])
        make = ['make', '-C', source, 'O='+str(build), 'ARCH=x86_64', 'LLVM='+str(base.LLVM/'bin')+'/']
        run('olddefconfig', [*make, 'olddefconfig'])
        delta = config_delta(old_build/'.config', build/'.config')
        if delta != {'CONFIG_KCONC_REGMAP_KUNIT_TEST': {'before': None, 'after': 'y'}}:
            raise RuntimeError('Unexpected config delta: '+json.dumps(delta, sort_keys=True))
        config = config_values(build/'.config')
        if any(config.get(name) != 'y' for name in ('CONFIG_KUNIT', 'CONFIG_KUNIT_DEBUGFS',
                'CONFIG_KUNIT_DEFAULT_ENABLED', 'CONFIG_KUNIT_AUTORUN_ENABLED', 'CONFIG_KCONC_REGMAP_TEST')):
            raise RuntimeError('KUnit/entry required configuration unavailable')
        if (build/'source').resolve() != source or str(old_build) in (build/'Makefile').read_text():
            raise RuntimeError('Generated build paths do not exclusively select the new tree')
        config_sha = sha(build/'.config')
        shutil.copyfile(build/'.config', evidence/'effective.config')
        run('build', [*make, '-j'+str(args.jobs), 'bzImage'])
        release = run('kernelrelease', [*make, '-s', 'kernelrelease']).strip().splitlines()[-1]
        if '-kconc-'+stage not in release:
            raise RuntimeError('Family release identity missing')
        base.verify_llvm_identity()
        if not unchanged(inputs) or not unchanged(preserved) or not unchanged(repaired_sources):
            raise RuntimeError('Inputs, repaired sources or accepted baseline changed during build')
        if sha(build/'.config') != config_sha:
            raise RuntimeError('Config changed during build')
        result.update(passed=True, source_commit=head, kernel_release=release,
            team_inputs=[dict(path=str(Path(row['path']).relative_to(REPO)), sha256=row['sha256']) for row in inputs],
            control_patch_sha256=sha(REPO/CONTROL_PATCH),
            repair_patch=dict(path=repair_patch, sha256=sha(REPO/repair_patch)),
            build_script_sha256=sha(REPO/'scripts/build-k11-kernel.py'), original_family=stage,
            patched_kcov_sha256=parent['patched_kcov_sha256'],
            repaired_driver=artifact(source/'drivers/base/regmap/kconc-regmap.c'),
            kunit_header=artifact(source/KUNIT_HEADER), kunit_suite='kconc-k11-'+args.family,
            kunit_expected_cases=6 if args.family == 'rmw' else 4,
            kunit_runtime_status='not_run_by_builder', config_delta=delta,
            accepted_parent=preserved, accepted_baseline_unchanged=True,
            llvm_identity=base.artifact(base.LLVM/'build-identity.json'),
            artifacts=[artifact(build/name) for name in ARTIFACTS],
            regmap_sources=snapshot(source, REGMAP_INPUTS+[KUNIT_HEADER]),
            regmap_objects=snapshot(build, REGMAP_OBJECTS),
            checks=dict(original_artifacts_preserved=True, original_sources_preserved=True,
                accepted_parent_reconstructed=True, upstream_regmap_unchanged=True,
                native_request_abi_unchanged=True, exact_config_delta=True,
                new_source_and_output=True, pinned_compiler_verified=True),
            source_modifications='K10 control retained; caller operation repaired; ioctl and KUnit share actual operation body.',
            limitations=['This repairs declared caller-misuse examples, not an upstream regmap vulnerability.',
                'KUnit exercises functional operation bodies; user-copy/lifecycle and concurrent schedules need separate runtime checks.',
                'Fresh samples/candidates are required; original K10 addresses and replay bundles are never relabelled.',
                'A successful build does not establish KUnit success or concurrent regression acceptance.'])
    except BaseException as error:
        result['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        if preserved:
            result['accepted_baseline_unchanged'] = unchanged(preserved)
        (evidence/'build-result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()

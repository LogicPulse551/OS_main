#!/usr/bin/env python3
"""Build a separate K10 control kernel; never reuse an old output directory.

The original family config and regmap sources are unchanged. The only new
kernel-source difference is patches/maccconc/0003-k10-control.patch. A new
kernel needs fresh K08 samples/K09 witnesses before K10 replay; old addresses
and bundles must not be rebound by editing their identity fields.
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
PATCH = 'patches/maccconc/0003-k10-control.patch'
EXPECTED_KERNELS = {
    'rmw': '2afefc619b923ab2cfbca4ed9f0ba4533aec8a2498b22b2bf2491ec30996068f',
    'mutex': 'aff40127ad27bea211db1216749adecc7c27abbb745a5815a78757eea76b9968'}
ARTIFACTS = ['arch/x86/boot/bzImage', 'vmlinux', '.config', 'System.map']
REGMAP_INPUTS = ['drivers/base/regmap/'+name for name in
                 ('kconc-regmap.c', 'kconc-regmap.h', 'regmap.c', 'regmap-ram.c', 'Kconfig', 'Makefile')]
REGMAP_OBJECTS = ['drivers/base/regmap/'+name for name in ('kconc-regmap.o', 'regmap.o', 'regmap-ram.o')]


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            value.update(block)
    return value.hexdigest()


def new_paths(lab, family, name):
    """Reject collisions, traversal and a build lab inside the delivery repo."""
    lab = Path(lab).resolve()
    stage = {'rmw': 'k06', 'mutex': 'k07'}.get(family)
    if stage is None or not re.fullmatch(r'linux-'+stage+r'-k10-[A-Za-z0-9][A-Za-z0-9._-]*', name):
        raise ValueError('Use linux-k06-k10-<suffix> for rmw or linux-k07-k10-<suffix> for mutex')
    if lab.is_relative_to(REPO) or REPO.is_relative_to(lab):
        raise ValueError('Build lab must be separate from the repository')
    source, build = lab/'sources'/name, lab/'build'/name
    for path in (source, build):
        if path.exists() or path.is_symlink():
            raise ValueError('Source/output must be new; failed builds remain for inspection: '+str(path))
        if path.resolve().parent != path.parent.resolve() or not path.parent.resolve().is_relative_to(lab):
            raise ValueError('Build path escaped the selected lab')
    return lab, source, build


def snapshot(root, names):
    result = []
    for name in names:
        path = root/name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise RuntimeError('Expected ordinary accepted file: '+str(path))
        result.append(dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size))
    return result


def unchanged(rows):
    return all(Path(row['path']).is_file() and not Path(row['path']).is_symlink()
               and sha(row['path']) == row['sha256'] for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-lab', type=Path, required=True)
    parser.add_argument('--family', choices=tuple(EXPECTED_KERNELS), required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--jobs', type=int, default=6)
    args = parser.parse_args()
    try:
        if not 1 <= args.jobs <= 16:
            raise ValueError('Use 1..16 jobs')
        lab, source, build = new_paths(args.build_lab, args.family, args.name)
    except ValueError as error:
        parser.error(str(error))
    stage = 'k06' if args.family == 'rmw' else 'k07'
    old_source, old_build = lab/'sources'/('linux-'+stage+'-01'), lab/'build'/('linux-'+stage+'-01')
    os.environ['LAB_DIR'] = str(lab)
    spec = importlib.util.spec_from_file_location('k10_base_build', REPO/'scripts/build-maccconc.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = lab/'evidence/k10'/('kernel-'+args.family+'-'+stamp)
    evidence.mkdir(parents=True)
    steps = []
    env = os.environ.copy()
    # Prevent inherited build redirections from writing an accepted output tree.
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

    result = dict(kind='kconc.control-kernel.build', stage='kernel', task='K10', family=args.family, passed=False, source=str(source),
                  kernel_build=str(build), steps=str(evidence/'steps.json'))
    preserved = []
    try:
        preserved = snapshot(old_build, ARTIFACTS+REGMAP_OBJECTS)
        preserved += snapshot(old_source, REGMAP_INPUTS+['kernel/kcov.c'])
        if sha(old_build/'arch/x86/boot/bzImage') != EXPECTED_KERNELS[args.family]:
            raise RuntimeError('Accepted baseline kernel differs')
        (evidence/'accepted-baseline.json').write_text(json.dumps(preserved, indent=2)+'\n')
        run('verify-pinned-source', ['python3', REPO/'scripts/maccconc-sources.py', 'verify',
            '--component', 'linux', '--source-root', lab/'sources/k01'])
        head = run('verify-family-source-head', ['git', '-C', old_source, 'rev-parse', 'HEAD']).strip()
        if head != base.LOCK['sources']['linux']['commit']:
            raise RuntimeError('Family source is not the pinned kernel commit')
        identity = base.verify_llvm_identity()
        (evidence/'llvm-identity.json').write_text(json.dumps(identity, indent=2)+'\n')
        inputs = snapshot(REPO, [f'kernel/{stage}/'+name for name in
            ('kconc-regmap.c', 'kconc-regmap.h', 'Kconfig.fragment', 'Makefile.fragment')]
            +[f'configs/kernel/{stage}-regmap.fragment', f'scripts/build-{stage}-kernel.py',
              PATCH, 'scripts/build-k10-kernel.py'])
        source.mkdir(parents=True)
        run('clone', ['git', 'clone', '--shared', '--no-checkout', lab/'sources/k01/linux', source])
        run('checkout', ['git', '-C', source, 'checkout', '--detach', head])
        for name in ('kconc-regmap.c', 'kconc-regmap.h'):
            shutil.copyfile(REPO/f'kernel/{stage}'/name, source/'drivers/base/regmap'/name)
        for dest, fragment in [('Kconfig', 'Kconfig.fragment'), ('Makefile', 'Makefile.fragment')]:
            with (source/'drivers/base/regmap'/dest).open('a') as stream:
                stream.write('\n'+(REPO/f'kernel/{stage}'/fragment).read_text())
        # Reconstructing the family source must reproduce every relevant old byte.
        for name in REGMAP_INPUTS+['kernel/kcov.c']:
            if sha(source/name) != sha(old_source/name):
                raise RuntimeError('Original family source changed: '+name)
        run('check-control-patch', ['git', '-C', source, 'apply', '--check', REPO/PATCH])
        run('apply-control-patch', ['git', '-C', source, 'apply', REPO/PATCH])
        patched_kcov_sha256 = sha(source/'kernel/kcov.c')
        run('team-diff', ['git', '-C', source, 'diff', '--binary'])
        build.mkdir(parents=True)
        shutil.copyfile(old_build/'.config', build/'.config')
        make = ['make', '-C', source, 'O='+str(build), 'ARCH=x86_64', 'LLVM='+str(base.LLVM/'bin')+'/']
        run('olddefconfig', [*make, 'olddefconfig'])
        if sha(build/'.config') != sha(old_build/'.config'):
            raise RuntimeError('K10 must retain the exact family config including LOCALVERSION')
        if (build/'source').resolve() != source or str(old_build) in (build/'Makefile').read_text():
            raise RuntimeError('Generated build paths do not exclusively select the new tree')
        shutil.copyfile(build/'.config', evidence/'effective.config')
        run('build', [*make, '-j'+str(args.jobs), 'bzImage'])
        release = run('kernelrelease', [*make, '-s', 'kernelrelease']).strip().splitlines()[-1]
        if '-kconc-'+stage not in release:
            raise RuntimeError('Family release identity missing')
        base.verify_llvm_identity()
        if not unchanged(inputs) or not unchanged(preserved):
            raise RuntimeError('Build inputs or accepted baseline changed during the build')
        if sha(build/'.config') != sha(old_build/'.config'):
            raise RuntimeError('Config changed during build')
        if any(sha(source/name) != sha(old_source/name) for name in REGMAP_INPUTS):
            raise RuntimeError('New regmap source changed during build')
        if sha(source/'kernel/kcov.c') != patched_kcov_sha256:
            raise RuntimeError('New KCOV control source changed during build')
        result.update(passed=True, source_commit=head, kernel_release=release,
            team_inputs=[dict(path=str(Path(x['path']).relative_to(REPO)), sha256=x['sha256']) for x in inputs],
            control_patch_sha256=sha(REPO/PATCH), build_script_sha256=sha(REPO/'scripts/build-k10-kernel.py'), original_family=stage,
            patched_kcov_sha256=patched_kcov_sha256,
            accepted_baseline=preserved, accepted_baseline_unchanged=True,
            llvm_identity=base.artifact(base.LLVM/'build-identity.json'),
            artifacts=[base.artifact(build/name) for name in ARTIFACTS],
            regmap_sources=snapshot(source, REGMAP_INPUTS), regmap_objects=snapshot(build, REGMAP_OBJECTS),
            checks=dict(original_artifacts_preserved=True, original_regmap_sources_preserved=True,
                        exact_original_config=True, new_source_and_output=True,
                        original_regmap_source_bytes_reproduced=True, pinned_compiler_verified=True),
            regmap_object_provenance='Recompiled from byte-identical original family sources with the same pinned compiler and config; object bytes may differ due to source paths.',
            source_modifications='Only KCOV control patch beyond original K06/K07 regmap entry; original regmap core/RAM backend and exact family config retained.',
            original_build_script_role='The original family build script is recorded as source provenance only; this new script performs the isolated build.',
            limitations=['IRQ-stack guard covers the observed x86 IRQ-stack tail, not every outer IRQ-return path.',
                'A finite independent spin allowance does not guarantee scheduler progress.',
                'Fresh samples and K09 witnesses are required for the new kernel identity; old bundles are not relabelled.'])
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

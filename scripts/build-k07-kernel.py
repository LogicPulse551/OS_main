#!/usr/bin/env python3
"""Build an isolated K07 kernel from the pinned Linux plus the regmap test entry."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-lab', type=Path, required=True)
    parser.add_argument('--name', default='linux-k07-01')
    parser.add_argument('--jobs', type=int, default=6)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or not __import__('re').fullmatch(r'linux-k07-[A-Za-z0-9._-]+', args.name):
        parser.error('Use a linux-k07-* name and 1..16 jobs')
    lab = args.build_lab.resolve()
    if lab.is_relative_to(REPO) or REPO.is_relative_to(lab):
        parser.error('Build lab must be outside repository')
    os.environ['LAB_DIR'] = str(lab)
    spec = importlib.util.spec_from_file_location('base_build', REPO / 'scripts/build-maccconc.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    source = lab / 'sources' / args.name
    build = lab / 'build' / args.name
    if source.exists() or build.exists():
        parser.error('Source and output must be new directories; failed builds remain for inspection')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = lab / 'evidence/k07' / ('kernel-' + stamp)
    evidence.mkdir(parents=True)
    steps = []
    env = os.environ.copy(); env['KCFLAGS'] = base.LOCK['build']['kernel']['kcflags']
    def run(name, command, cwd=REPO):
        command = list(map(str, command))
        row = dict(name=name, command=command, cwd=str(cwd), KCFLAGS=env['KCFLAGS'], exit_code=None,
                   started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), log=str(evidence/(name+'.log')))
        steps.append(row)
        (evidence/'steps.json').write_text(json.dumps(steps, indent=2)+'\n')
        print(name, flush=True)
        with Path(row['log']).open('w') as log:
            p = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        row.update(exit_code=p.returncode, finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        (evidence/'steps.json').write_text(json.dumps(steps, indent=2)+'\n')
        if p.returncode: raise RuntimeError('Build step failed: '+name+'; '+row['log'])
    run('verify-pinned-source', ['python3', REPO/'scripts/maccconc-sources.py', 'verify', '--component', 'linux', '--source-root', lab/'sources/k01'])
    identity = base.verify_llvm_identity()
    (evidence/'llvm-identity.json').write_text(json.dumps(identity, indent=2)+'\n')
    run('clone', ['git', 'clone', '--shared', '--no-checkout', lab/'sources/k01/linux', source])
    run('checkout', ['git', '-C', source, 'checkout', '--detach', base.LOCK['sources']['linux']['commit']])
    inputs = []
    for rel in ['kernel/k07/kconc-regmap.c', 'kernel/k07/kconc-regmap.h', 'kernel/k07/Kconfig.fragment', 'kernel/k07/Makefile.fragment', 'configs/kernel/k07-regmap.fragment', 'scripts/build-k07-kernel.py']:
        inputs.append(dict(path=rel, sha256=base.sha256_file(REPO/rel)))
    for name in ('kconc-regmap.c', 'kconc-regmap.h'):
        shutil.copyfile(REPO/'kernel/k07'/name, source/'drivers/base/regmap'/name)
    for dest, fragment in [('Kconfig','Kconfig.fragment'), ('Makefile','Makefile.fragment')]:
        with (source/'drivers/base/regmap'/dest).open('a') as f:
            f.write('\n'+(REPO/'kernel/k07'/fragment).read_text())
    run('team-diff', ['git', '-C', source, 'diff', '--binary'])
    build.mkdir(parents=True)
    shutil.copyfile(lab/'build/linux-2fc2e45b0cd7/.config', build/'.config')
    make = ['make', '-C', source, 'O='+str(build), 'ARCH=x86_64', 'LLVM='+str(base.LLVM/'bin')+'/']
    run('merge-config', ['bash', source/'scripts/kconfig/merge_config.sh', '-m', '-O', build, build/'.config', REPO/'configs/kernel/k07-regmap.fragment'], source)
    run('olddefconfig', [*make,'olddefconfig'])
    config = (build/'.config').read_text().splitlines()
    required = [x for x in (REPO/'configs/kernel/maccconc-x86_64.fragment').read_text().splitlines()
                if x.startswith('CONFIG_') or x.startswith('# CONFIG_')]
    required += [x for x in (REPO/'configs/kernel/k07-regmap.fragment').read_text().splitlines()
                 if x.startswith('CONFIG_') or x.startswith('# CONFIG_')]
    # LOCALVERSION is intentionally unique; all tracing requirements remain.
    required = [x for x in required if not x.startswith(('CONFIG_LOCALVERSION=', 'CONFIG_LOCALVERSION_AUTO='))]
    assert all(x in config for x in required), [x for x in required if x not in config]
    shutil.copyfile(build/'.config', evidence/'effective.config')
    run('build', [*make, '-j'+str(args.jobs), 'bzImage'])
    run('kernelrelease', [*make, '-s', 'kernelrelease'])
    base.verify_llvm_identity()
    assert inputs == [dict(path=x['path'], sha256=base.sha256_file(REPO/x['path'])) for x in inputs]
    result = dict(stage='kernel', task='K07', source_commit=base.LOCK['sources']['linux']['commit'],
        source=str(source), kernel_build=str(build), team_inputs=inputs, steps=str(evidence/'steps.json'),
        llvm_identity=base.artifact(base.LLVM/'build-identity.json'),
        artifacts=[base.artifact(build/p) for p in ['arch/x86/boot/bzImage','vmlinux','.config','System.map']],
        source_modifications='Added built-in regmap test entry and its Kconfig/Makefile wiring; upstream regmap and RAM bus unchanged')
    (evidence/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__ == '__main__': main()

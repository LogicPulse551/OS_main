#!/usr/bin/env python3
"""Build a complete normal-O2 original image in a new external directory.

Read the pinned source commit and accepted config; never write into either.
Every attempted command and its output survive failures. No VM is started.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]


def sha(p):
    with Path(p).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(p, value):
    with p.open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-repository', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--llvm', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--jobs', type=int, default=8)
    a = p.parse_args()
    out = a.output.resolve()
    if out.is_relative_to(REPO) or REPO.is_relative_to(out) or out.exists():
        p.error('output must be a new directory outside the repository')
    if not 1 <= a.jobs <= 32:
        p.error('jobs must be between 1 and 32')
    lock = json.loads((REPO/'configs/maccconc.lock.json').read_text())
    # Locked commits are also explicit in the receipt, not inferred from a branch.
    commit = '2fc2e45b0cd75cd56f252a0872a6d039f46cc42b'
    if commit not in json.dumps(lock):
        raise ValueError('kernel pin changed; review this builder first')
    clang = a.llvm.resolve()/'bin/clang'
    if sha(clang) != 'f3765cf3cc48f6c60743fa433ddc50a5f535f892af6a2e14c9b6d1b8a5a06305':
        raise ValueError('compiler differs from the accepted pinned toolchain')
    if sha(a.config) != '1ac6bd19e34106ffb64cd65ec80b1c458e9ca9dc17cdb1015aa81eb39fbfa1a5':
        raise ValueError('base config differs from the accepted K02 original')
    out.mkdir(parents=True)
    (out/'logs').mkdir()
    source, build = out/'source', out/'performance'
    source.mkdir(); build.mkdir()
    receipt = dict(kind='kconc.build-receipt.v1', variant='original', purpose='performance',
                   passed=False, architecture='x86_64', source_commit=commit, team_patches=[],
                   compiler={'path': str(clang), 'sha256': sha(clang)},
                   parent_config={'path': str(a.config.resolve()), 'sha256': sha(a.config)},
                   source=str(source), build=str(build), steps=[],
                   started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    write(out/'entry.json', receipt)
    shutil.copyfile(__file__, out/'builder.py')
    shutil.copyfile(REPO/'configs/kernel/build-profiles.json', out/'build-profiles.json')

    def run(name, cmd):
        record = dict(name=name, command=list(map(str,cmd)), cwd=str(out))
        write(out/'logs'/(name+'.invocation.json'), record)
        with (out/'logs'/(name+'.stdout')).open('wb') as so, (out/'logs'/(name+'.stderr')).open('wb') as se:
            r = subprocess.run(record['command'], cwd=out, stdout=so, stderr=se,
                               env={**os.environ, 'KCONFIG_NOTIMESTAMP':'1'})
        record['exit_code'] = r.returncode
        receipt['steps'].append(record)
        write(out/'logs'/(name+'.result.json'), record)
        if r.returncode:
            raise RuntimeError(f'{name}: exit {r.returncode}; retained logs in {out}/logs')

    try:
        run('archive', ['git','-C',a.source_repository,'archive',commit,'-o',out/'source.tar'])
        receipt['source_archive_sha256'] = sha(out/'source.tar')
        run('extract', ['tar','-xf',out/'source.tar','-C',source])
        shutil.copyfile(a.config, build/'.config')
        profile = json.loads((out/'build-profiles.json').read_text())['performance']
        run('profile', [source/'scripts/config','--file',build/'.config',
                       *[arg for key in profile['forbidden'] for arg in ('--disable',key.removeprefix('CONFIG_'))]])
        make = ['make','-C',source,'O='+str(build),'ARCH=x86_64','LLVM='+str(a.llvm.resolve()/'bin')+'/']
        run('olddefconfig', make+['olddefconfig'])
        receipt['config_sha256'] = sha(build/'.config')
        run('bzImage', make+['-j'+str(a.jobs),'bzImage'])
        run('kernelrelease',make+['-s','kernelrelease'])
        receipt['artifacts'] = {name:{'path':str(build/name),'sha256':sha(build/name),'bytes':(build/name).stat().st_size}
                                for name in ['.config','vmlinux','arch/x86/boot/bzImage','System.map','drivers/base/regmap/.regcache.o.cmd']}
        receipt['passed'] = True
    except BaseException as e:
        receipt['error'] = repr(e)
        raise
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(out/'build-receipt.json', receipt)
        print(json.dumps({'passed': receipt['passed'], 'receipt':str(out/'build-receipt.json')}))


if __name__ == '__main__':
    main()

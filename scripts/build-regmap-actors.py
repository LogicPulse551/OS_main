#!/usr/bin/env python3
"""Build the RAM regmap worker module against the registered original test kernel."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
from kconc.artifacts import check_identity, check_ref, elf_id, read, ref, require, sha


def write_json(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def build(identity_path, out):
    folder = 'regmap-actors'
    module_name = 'regmap_actors'
    kind = 'kconc.regmap-actors.module.v1'
    require(not out.is_relative_to(REPO), 'build evidence belongs outside the repository')
    out.mkdir(parents=True, exist_ok=False)
    result = {'kind': kind, 'status': 'failed', 'steps': []}

    def run(name, argv):
        command = list(map(str,argv))
        row = {'name': name, 'command': command, 'exit': None}
        result['steps'].append(row)
        log = out / (name + '.log')
        with log.open('xb') as stream:
            proc = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        row.update(exit=proc.returncode, log=ref(log))
        require(proc.returncode == 0, f'{name} exited {proc.returncode}: {log}')
        return log

    try:
        result['identity'] = ref(identity_path)
        identity = check_identity(identity_path, expected_purpose='detection')
        require((identity['family'],identity['variant']) == ('linux-original','original'),
                'the original linux detection build is required')
        original = Path(identity['artifacts']['config']['path']).parent
        source = (original/'source').resolve(strict=True)
        compiler = Path(check_ref(identity['compiler'])['path'])
        config = identity['artifacts']['config']
        exports = ref(original/'vmlinux.symvers')
        require(run('source-head', ['git','-C',source,'rev-parse','HEAD']).read_text().strip() ==
                identity['source_commit'], 'unexpected kernel source revision')
        run('source-clean', ['git','--no-optional-locks','-C',source,'diff','--quiet','HEAD','--'])
        steps = read(read(identity['receipt']['path'])['steps'])
        flags = next(step['KCFLAGS'] for step in steps if step['name']=='build')
        result.update(identity_id=identity['identity_id'], kernel_build_id=identity['gnu_build_id'],
                      release=identity['release'], compiler=identity['compiler'], exports=exports, sources={})
        staged = out/'sources'
        staged.mkdir()
        with tempfile.TemporaryDirectory(prefix='kconc-actors-') as tmp:
            obj, mod = Path(tmp)/'objects', Path(tmp)/'module'
            obj.mkdir()
            mod.mkdir()
            shutil.copyfile(config['path'],obj/'.config')
            make = ['make','-C',source,'O='+str(obj),'ARCH=x86_64','LLVM='+str(compiler.parent)+'/',
                    'KCFLAGS='+flags,'-j4']
            run('olddefconfig', [*make,'olddefconfig'])
            run('prepare', [*make,'modules_prepare'])
            require(sha(obj/'.config')==config['sha256'], 'prepared module configuration differs from kernel')
            require((obj/'include/config/kernel.release').read_text().strip()==identity['release'],
                    'prepared module release differs from kernel')
            shutil.copyfile(exports['path'],obj/'Module.symvers')
            require(sha(obj/'Module.symvers')==exports['sha256'], 'export table changed while copying')
            names = ['Makefile', module_name + '.c']
            for name in names:
                src = REPO/'kernel'/folder/name
                shutil.copyfile(src,staged/name)
            for name in names:
                result['sources'][name] = ref(staged/name)
                shutil.copyfile(staged/name,mod/name)
            try:
                run('module', [*make,'M='+str(mod),'modules'])
            finally:
                compile_command = mod/('.' + module_name + '.o.cmd')
                if compile_command.is_file():
                    shutil.copyfile(compile_command,out/'module-compile-command.txt')
            binary = out/(module_name + '.ko')
            shutil.copyfile(mod/binary.name,binary)
        vermagic = run('vermagic',['modinfo','-F','vermagic',binary]).read_text().strip()
        require(vermagic.split()[0] == identity['release'], 'module vermagic mismatch')
        imports = {line.split()[-1] for line in run('imports',['nm','-u',binary]).read_text().splitlines()}
        exported = {line.split()[1] for line in Path(exports['path']).read_text().splitlines()}
        require(imports <= exported, 'undefined, unexported symbols: '+', '.join(sorted(imports-exported)))
        symbol_map = identity['artifacts']['symbols']
        native_exports = {name.removeprefix('__ksymtab_') for line in Path(symbol_map['path']).read_text().splitlines()
                          if (name := line.split()[-1]).startswith('__ksymtab_')}
        require(imports <= native_exports, 'module imports absent from the registered kernel export table')
        require('regmap_update_bits_base' in imports, 'module does not call the kernel regmap update API')
        for artifact in (config, exports, result['identity']):
            check_ref(artifact)
        result.update(status='passed', module=ref(binary), module_build_id=elf_id(binary),
                      config=config, kernel_symbols=symbol_map, vermagic=vermagic, imports=sorted(imports))
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    write_json(out/'receipt.json',result)
    if result['status'] != 'passed':
        print(result['error'],file=sys.stderr)
    print(out/'receipt.json', flush=True)
    return 0 if result['status']=='passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    sys.exit(build(args.identity.resolve(),args.out.resolve()))

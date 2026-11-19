"""Content-bound kernel identities. These are local build receipts, not proofs.

Imports only the implemented K02/K10/K11 and I01 builders. Unknown or future
optimization builders fail closed until their output/proof connection exists.
"""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO/'configs/kernel/build-profiles.json'
PIN = '2fc2e45b0cd75cd56f252a0872a6d039f46cc42b'
CLANG_SHA = 'f3765cf3cc48f6c60743fa433ddc50a5f535f892af6a2e14c9b6d1b8a5a06305'
KINDS = {'original', 'repaired', 'optimized'}


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def ref(path):
    # Keep lexical tool paths: clang is a symlink but Kbuild records the driver.
    path = Path(os.path.abspath(path))
    require(path.is_file(), f'missing regular file: {path}')
    return dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)


def check_ref(value):
    actual = ref(value['path'])
    require(actual['sha256'] == value['sha256'], f'artifact hash mismatch: {value["path"]}')
    require('bytes' not in value or actual['bytes'] == value['bytes'], 'artifact size mismatch')
    return actual


def seal(value):
    value = {k:v for k,v in value.items() if k != 'identity_id'}
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {**value, 'identity_id': hashlib.sha256(encoded).hexdigest()}


def notes_id(data):
    ids, pos = [], 0
    while pos + 12 <= len(data):
        ns, ds, kind = struct.unpack_from('<III', data, pos)
        pos += 12
        end = pos + ((ns+3)&~3) + ((ds+3)&~3)
        require(end <= len(data), 'truncated ELF note')
        name = data[pos:pos+ns].rstrip(b'\0')
        pos += (ns+3)&~3
        desc = data[pos:pos+ds]
        pos += (ds+3)&~3
        if name == b'GNU' and kind == 3:
            ids.append(desc.hex())
    require(len(ids) == 1 and bool(ids[0]), 'expected exactly one GNU build ID')
    return ids[0]


def elf_id(path):
    with Path(path).open('rb') as f:
        header = f.read(64)
        require(header[:6] == b'\x7fELF\x02\x01', 'only ELF64 little endian supported')
        require(struct.unpack_from('<H', header, 18)[0] == 62, 'only x86_64 supported')
        off = struct.unpack_from('<Q', header, 40)[0]
        size, count = struct.unpack_from('<HH', header, 58)
        require(size == 64 and 0 < count < 65535, 'unsupported ELF section table')
        allnotes = b''
        for i in range(count):
            f.seek(off + i*size); s = f.read(size)
            if struct.unpack_from('<I', s, 4)[0] == 7:
                start, length = struct.unpack_from('<QQ', s, 24)
                require(length < 1024*1024, 'oversized note section')
                f.seek(start); allnotes += f.read(length)
    return notes_id(allnotes)


def config_values(text):
    values = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=',1); values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values


def check_profile(purpose, config, command):
    profiles = read(POLICY)
    require(purpose in ('detection','performance'), 'unknown build purpose')
    policy = profiles[purpose]; values = config_values(config)
    for key, value in policy['required'].items():
        require(values.get(key) == value, f'{purpose}: required {key}={value}')
    for key in policy['forbidden']:
        require(values.get(key, 'n') == 'n', f'{purpose}: forbidden {key}')
    require(re.search(r'(^|\s)-O2(\s|$)', command), 'normal O2 command required')
    markers = ('-fsanitize=kernel-address', '-fsanitize-coverage=', '-fsanitize=thread')
    if purpose == 'performance':
        require(not any(x in command for x in markers), 'instrumented command in performance build')
    else:
        require('-fsanitize=kernel-address' in command and '-fsanitize-coverage=' in command,
                'detection command lacks the required instrumentation')
    return policy['measurement_eligible']


def from_receipt(path, parent_path=None, depth=0):
    require(depth < 5, 'parent chain too deep')
    path = Path(path).resolve(); r = read(path)
    require(r.get('source_commit') == PIN, 'unregistered source commit')
    original_i01 = r.get('kind') == 'kconc.build-receipt.v1'
    legacy = r.get('task') in ('K10','K11')
    k02 = (r.get('stage') == 'kernel' and
           set(r) == {'stage','source_commit','artifacts','steps','llvm_identity'})
    require(original_i01 or legacy or k02, 'unregistered builder')
    variant = 'repaired' if r.get('task') == 'K11' else 'original'
    purpose = 'performance' if original_i01 else 'detection'
    family = 'regmap-'+r['family'] if legacy else 'linux-original'
    require(not original_i01 or (r.get('variant') == variant and r.get('purpose') == purpose),
            'builder variant or purpose mismatch')
    require(not (original_i01 or legacy) or r.get('passed') is True, 'build receipt did not pass')
    if legacy:
        expected_kind = 'kconc.control-kernel.build' if r['task'] == 'K10' else 'kconc.repaired-kernel.build'
        require(r.get('kind') == expected_kind and r.get('family') in ('rmw','mutex'), 'legacy builder mismatch')
        require(r.get('checks') and all(x is True for x in r['checks'].values()), 'legacy build checks failed')
    steps = r['steps'] if original_i01 else read(r['steps'])
    require(isinstance(steps,list) and steps and all(s.get('exit_code') == 0 for s in steps), 'build commands failed')
    raw = list(r['artifacts'].values()) if original_i01 else r['artifacts']
    artifacts = [check_ref(x) for x in raw]
    image = next(x for x in artifacts if x['path'].endswith('/arch/x86/boot/bzImage'))
    build = Path(image['path']).parents[3]
    bound = {}
    for key, name in [('image','arch/x86/boot/bzImage'),('vmlinux','vmlinux'),('config','.config'),('symbols','System.map')]:
        bound[key] = next(x for x in artifacts if Path(x['path']) == build/name)
    command = ref(build/'drivers/base/regmap/.regcache.o.cmd')
    command_text = Path(command['path']).read_text().splitlines()[0]
    driver = command_text.split(':=',1)[1].strip().split()[0]
    compiler = ref(driver)
    require(compiler['sha256'] == CLANG_SHA, 'compiler not the accepted pinned LLVM')
    eligible = check_profile(purpose, Path(bound['config']['path']).read_text(), command_text)
    inputs = []
    for item in r.get('team_inputs',[]):
        actual = ref(REPO/item['path'])
        require(actual['sha256'] == item['sha256'], 'team input drift: '+item['path'])
        inputs.append(actual)
    dependencies = []
    if not original_i01:
        dependencies.append(ref(r['steps']))
    if original_i01:
        dependencies.append(check_ref(r['compiler']))
        dependencies.append(check_ref(r['parent_config']))
        require(sha(path.parent/'source.tar') == r['source_archive_sha256'], 'source archive drift')
        dependencies.append(ref(path.parent/'source.tar'))
    elif k02:
        dependencies.append(check_ref(r['llvm_identity']))
    parent, relation = None, None
    if variant == 'repaired':
        require(parent_path is not None, 'repair requires its original parent identity')
        parent = ref(parent_path)
        old = check_identity(parent_path, depth=depth+1)
        require(old['variant'] == 'original' and old['family'] == family and old['purpose'] == purpose,
                'repair parent family/purpose/role mismatch')
        require(old['artifacts']['image']['sha256'] != bound['image']['sha256'], 'repair cannot alias its original')
        expected = check_ref(r['accepted_parent_build_record'])
        require(old['receipt']['sha256'] == expected['sha256'], 'repair parent receipt mismatch')
        dependencies.append(expected)
        if 'repaired_parent_build_record' in r:
            dependencies.append(check_ref(r['repaired_parent_build_record']))
        patch = ref(REPO/r['repair_patch']['path'])
        require(patch['sha256'] == r['repair_patch']['sha256'], 'repair patch mismatch')
        relation = dict(kind='repair', parent_identity_id=old['identity_id'], patch=patch,
                        correctness='historical bounded regression; identity binding is not a correctness proof')
    else:
        require(parent_path is None, 'original must not take a repair parent')
    result = dict(schema_version=1, kind='kconc.artifact-identity', status='generated', variant=variant,
                  purpose=purpose, family=family, architecture='x86_64', source_commit=PIN,
                  receipt=ref(path), dependencies=dependencies, team_inputs=inputs,
                  compiler=compiler, policy=ref(POLICY), artifacts=bound, command=command,
                  release=(build/'include/config/kernel.release').read_text().strip(),
                  gnu_build_id=elf_id(bound['vmlinux']['path']), parent=parent, relation=relation,
                  performance_config_eligible=eligible, optimization_proof=None)
    return seal(result)


def missing(variant, purpose, family, reason, parent_path=None):
    require(variant in ('repaired','optimized'), 'only future derived variants can be absent')
    require(purpose in ('detection','performance') and bool(reason), 'purpose and reason required')
    require(isinstance(family,str) and bool(family), 'family required')
    parent = ref(parent_path) if parent_path else None
    if parent:
        p = check_identity(parent_path)
        require(p['family'] == family and p['purpose'] == purpose, 'missing variant parent mismatch')
    return seal(dict(schema_version=1, kind='kconc.artifact-identity', status='not_generated',
                     variant=variant, purpose=purpose, family=family, parent=parent,
                     parent_identity_id=p['identity_id'] if parent else None,
                     reason=reason, artifacts=None, optimization_proof=None))


def check_identity(path, expected_purpose=None, depth=0):
    value = read(path)
    require(value == seal(value), 'identity digest mismatch')
    require(value.get('status') == 'generated', 'variant_not_generated: no usable artifact')
    require(expected_purpose is None or value.get('purpose') == expected_purpose, 'purpose mismatch')
    check_ref(value['receipt'])
    if value.get('parent'):
        check_ref(value['parent'])
    current = from_receipt(value['receipt']['path'], value['parent']['path'] if value.get('parent') else None, depth)
    require(value == current, 'identity differs from its actual build receipt/config/artifacts')
    return value


def check_guest(identity, guest, config, notes):
    guest = dict(guest)
    guest['gnu_build_id'] = notes_id(notes)
    guest['config_sha256'] = hashlib.sha256(config).hexdigest()
    require(guest['config_sha256'] == identity['artifacts']['config']['sha256'], 'guest config mismatch')
    require(guest['gnu_build_id'] == identity['gnu_build_id'], 'guest build ID mismatch')
    require(guest['release'] == identity['release'], 'guest release mismatch')
    require('kconc.identity='+identity['identity_id'] in guest['cmdline'].split(), 'guest identity token mismatch')
    require(not guest['modules'].strip(), 'unregistered loaded modules')
    return guest


def check_loaded(identity, runtime, out):
    """Read the already running local VM; never start, stop or modify its disk."""
    from .cli import runtime_lock
    require(sys.platform == 'linux', 'loaded identity checks run in WSL Debian')
    lab = Path(runtime['lab_dir']).resolve()
    with runtime_lock(runtime):
        launch_path = lab/'evidence/last-launch.json'
        launch = read(launch_path)
        pid = int((lab/'run/qemu.pid').read_text())
        argv = [x.decode() for x in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if x]
        def option(args, key):
            require(args.count(key) == 1, 'ambiguous or missing QEMU option: '+key)
            return args[args.index(key)+1]
        require(option(argv,'-kernel') == identity['artifacts']['image']['path'], 'running QEMU image mismatch')
        require(argv == launch['command'], 'running QEMU argv differs from launch receipt')
        require(option(argv,'-qmp') == 'unix:'+str(lab/'run/qmp.sock')+',server=on,wait=off', 'QEMU lab mismatch')
        token = 'kconc.identity='+identity['identity_id']
        require(token in option(argv,'-append').split(), 'launch identity token mismatch')
        port = runtime['ssh_port']
        require(re.search(r'(?:^|,)hostfwd=tcp:127\.0\.0\.1:'+str(port)+r'-:22(?:,|$)',option(argv,'-netdev')),
                'SSH port does not belong to this QEMU')
        a = launch['kernel_artifact']
        expected = identity['artifacts']['image']
        require(a['path'] == expected['path'] and a['bytes'] == expected['bytes'] and
                a['sha256_before_launch'] == a['sha256_after_launch'] == expected['sha256'] == sha(expected['path']),
                'launch image hashes differ')
        probe = '''import base64,gzip,json,pathlib,os
P=pathlib.Path
print(json.dumps(dict(config=base64.b64encode(gzip.decompress(P('/proc/config.gz').read_bytes())).decode(),notes=base64.b64encode(P('/sys/kernel/notes').read_bytes()).decode(),release=os.uname().release,cmdline=P('/proc/cmdline').read_text(),boot_id=P('/proc/sys/kernel/random/boot_id').read_text().strip(),modules=P('/proc/modules').read_text(),os_release=P('/etc/os-release').read_text())))
'''
        ssh = ['ssh','-i',str(lab/'keys/id_ed25519'),'-p',str(port),'-o','IdentitiesOnly=yes',
               '-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes',
               '-o','UserKnownHostsFile='+str(lab/'keys/known_hosts'),'lab@127.0.0.1','python3 -']
        (out/'guest-probe.py').write_text(probe)
        (out/'guest-command.json').write_text(json.dumps(ssh,indent=2))
        p = subprocess.run(ssh,input=probe.encode(),capture_output=True,timeout=45)
        (out/'guest.stdout').write_bytes(p.stdout); (out/'guest.stderr').write_bytes(p.stderr)
        require(p.returncode == 0, f'guest probe exited {p.returncode}')
        g = json.loads(p.stdout)
        config = base64.b64decode(g.pop('config'), validate=True)
        notes = base64.b64decode(g.pop('notes'), validate=True)
        (out/'guest.config').write_bytes(config); (out/'guest.notes').write_bytes(notes)
        g = check_guest(identity, g, config, notes)
        (out/'guest.json').write_text(json.dumps(g,indent=2))
        # Evidence files are snapshots; the live process must still be the same.
        require(argv == [x.decode() for x in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if x],
                'QEMU changed during identity check')
        fork = read(lab/'evidence/baseline-fork.json')
        require(fork['target_lab'] == str(lab), 'VM fork identity mismatch')
        require(sha(fork['frozen_snapshot']) == fork['frozen_overlay_sha256'], 'frozen userspace disk changed')
        executable = Path(f'/proc/{pid}/exe').resolve()
        qemu = subprocess.run([executable,'--version'],capture_output=True,text=True,check=True)
        return dict(identity_id=identity['identity_id'], loaded=True, guest=g, qemu_pid=pid,
                    launch=launch, launch_receipt=ref(launch_path), qemu_version=qemu.stdout,
                    qemu_executable=ref(executable),
                    userspace_fork=ref(lab/'evidence/baseline-fork.json'),
                    frozen_userspace_sha256=fork['frozen_overlay_sha256'],
                    seed=ref(lab/'seed/seed.img'),
                    boundary='Boot-time artifact/config identity; not memory attestation, a performance run, or compiler correctness')


def dispatch(task, out, envelope):
    from .cli import OperationError, save
    try:
        identity = check_identity(task['inputs']['identity'])
        save(out/'identity.json', identity)
        result = dict(identity_id=identity['identity_id'], variant=identity['variant'],
                      purpose=identity['purpose'], artifact_checked=True, loaded=False)
        if task['operation'] == 'artifact.loaded':
            result.update(check_loaded(identity, task['runtime'], out))
        envelope['data'] = result
    except (ValueError, KeyError, OSError, StopIteration, subprocess.SubprocessError) as e:
        raise OperationError('artifact_identity_failed', str(e)) from e

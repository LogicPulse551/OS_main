"""Run complete API operations on one private RAM register in the original test kernel."""
from collections import Counter
from itertools import islice
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .artifacts import REPO, check_identity, check_ref, elf_id, notes_id, read, ref, require, sha
from .multi_regmap import plan_cases, verify_case

FIXTURE = REPO/'kernel/regmap-actors'
STEP = re.compile(r'REGACT step=(\d+) role=(\d+) pid=(\d+) before=(\d+) after=(\d+) rc=(-?\d+)$', re.M)
TRACE = re.compile(r'^\s*(\S+)-(\d+)\s+\[\d+\].*?regmap_reg_(read|write): regmap_actors reg=(\w+) val=(\w+)$', re.M)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True, help='Receipt from build-regmap-actors.py')
    p.add_argument('--disk', type=Path, required=True, help='Read-only openEuler guest disk')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--threads', type=int, choices=range(2,6))
    mode.add_argument('--replay', type=Path, help='Cold replay of a recorded actors run')
    p.add_argument('--max-switches', type=int, help='Maximum changes of role between consecutive updates')
    p.add_argument('--budget', type=int, help='Maximum schedules in this boot (1 to 128)')
    p.add_argument('--start', type=int, help='Skip this many plans in the same bounded search')
    p.add_argument('--max-active', type=int, help='Check the maximum number of occupied bits after each update')
    p.add_argument('--out', type=Path, required=True)
    return p


def save(path, obj):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(obj, stream, indent=2)


def one(pattern, data, label):
    hits = re.findall(pattern, data, flags=re.M)
    require(len(hits) == 1, 'missing or repeated '+label)
    return hits[0]


def check_case(threads, order, block, module_id, index):
    wire = ''.join(map(str,order))
    require(block.splitlines()[0] == f'CASE {index} {wire}', 'planned case header mismatch')
    require(one(r'^END (\d+ load=\d+ unload=\d+ clean=\d+)$', block, 'case end') ==
            f'{index} load=0 unload=0 clean=1', 'case did not complete load and cleanup')
    require(notes_id(bytes.fromhex(one(r'^MODULE_NOTES (\w+)$',block,'module notes'))) == module_id,
            'guest module build ID differs')
    require(len(re.findall(r'REGACT clean$',block,re.M)) == 1, 'module teardown not observed')
    fields = ('step','role','pid','before','after','rc')
    rows = [dict(zip(fields,map(int,line))) for line in STEP.findall(block)]
    value, rc = one(r'REGACT final=(\d+) rc=(-?\d+)$',block,'independent readback')
    require(rc == '0', 'final read failed')
    observed = verify_case(threads, order, rows, int(value))
    traces = TRACE.findall(block)
    buffered, written = map(int,one(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)',block,'trace counts'))
    require(buffered == written and buffered >= len(traces), 'trace buffer lost events')
    require(len(traces) == 4*len(order)+1, 'unexpected number of real regmap accesses')
    for step,row in enumerate(rows):
        expected = [('read',row['before']),('read',row['before']),('write',row['after']),('read',row['after'])]
        actual = []
        for name,pid,op,reg,val in traces[4*step:4*step+4]:
            require(name == 'regactor/'+str(row['role']) and int(pid)==row['pid'] and int(reg,16)==0,
                    f'wrong trace role, PID or register at step {step}')
            actual.append((op,int(val,16)))
        require(actual == expected, f'tracepoint values or access order differ at step {step}')
    owner,pid,op,reg,last = traces[-1]
    require(owner == 'insmod' and int(pid) not in observed['pids'].values() and op == 'read'
            and int(reg,16)==0 and int(last,16)==int(value), 'independent regmap readback differs')
    return dict(observed, index=index, order=order, rows=rows, regmap_events=len(traces))


def decode(serial, plan, identity, module_id, require_plan_token=False):
    require('PRETTY_NAME="openEuler 24.03 (LTS-SP3)"' in serial, 'guest userspace differs')
    require(one(r'^RELEASE (\S+)$',serial,'kernel release') == identity['release'] and
            one(r'^CONFIG (\w+)$',serial,'config') == identity['artifacts']['config']['sha256'] and
            notes_id(bytes.fromhex(one(r'^KERNEL_NOTES (\w+)$',serial,'kernel notes'))) == identity['gnu_build_id'] and
            'kconc.identity='+identity['identity_id'] in one(r'^CMDLINE (.+)$',serial,'command line').split(),
            'guest kernel identity differs')
    require('regmap_actors.ko: OK' in serial.splitlines(), 'module file digest not observed')
    cmdline = one(r'^CMDLINE (.+)$',serial,'command line').split()
    tokens = [arg for arg in cmdline if arg.startswith('kconc.actors_plan=')]
    if tokens or require_plan_token:
        digest = hashlib.sha256(json.dumps(plan,indent=2).encode()).hexdigest()
        require(tokens==['kconc.actors_plan='+digest], 'booted search plan or property differs')
    nonce = one(r'^NONCE ([0-9a-f]{32})$',serial,'guest nonce')
    parts = re.split(r'(?=^CASE \d+ [0-4]+$)',serial,flags=re.M)[1:]
    indices = [int(p.split(' ',2)[1]) for p in parts]
    require(indices == list(range(len(parts))) and len(parts)<=len(plan['orders']), 'case index sequence differs')
    cases = []
    for i,order in enumerate(plan['orders']):
        if i >= len(parts):
            cases.append(dict(index=i,order=order,status='not_observed'))
            continue
        try:
            cases.append(check_case(plan['threads'],order,parts[i],module_id,i))
        except ValueError as error:
            cases.append(dict(index=i,order=order,status='failed',reason=str(error)))
    clean = (re.findall(r'^(?:IIO|K14)_SUPERVISOR_EXIT (\d+)$',serial,re.M) == ['0']
             and not re.search(r'Kernel panic|Oops:|BUG:|WARNING: CPU:',serial))
    return nonce, cases, clean


def make_plan(threads, depth, budget, start=0):
    require(type(budget) is int and 1 <= budget <= 128, 'use a per-boot budget of 1 to 128')
    require(type(depth) is int and threads-1 <= depth <= 2*threads-1,
            f'for {threads} actors choose a switch bound from {threads-1} to {2*threads-1}')
    require(type(start) is int and start >= 0, 'start must be a nonnegative index')
    plan = plan_cases(threads, depth, start+budget)
    require(start < plan['total_eligible'], 'start exceeds this bounded search')
    plan['orders'] = list(islice(plan['orders'],start,None))
    plan.update(selected=len(plan['orders']), budget=budget, unexplored=plan['total_eligible']-len(plan['orders']))
    if start:
        plan['start'] = start
    return plan


def unverified_cases(plan, raw):
    entered = {int(i) for i in re.findall(r'^CASE (\d+) ',raw,re.M)}
    return [dict(index=i,order=order,status='unverified' if i in entered else 'not_observed')
            for i,order in enumerate(plan['orders'])]


def capacity(cases, limit):
    """A set bit represents an occupied slot in this test client's protocol."""
    witnesses = []
    evaluated = 0
    for case in cases:
        if case['status'] != 'passed':
            continue
        evaluated += 1
        for row in case['rows']:
            active = row['after'].bit_count()
            if active > limit:
                witnesses.append(dict(case=case['index'],order=case['order'],step=row['step'],
                                      role=row['role'],register=row['after'],active=active))
                break
    return dict(max_active=limit,evaluated=evaluated,unevaluated=len(cases)-evaluated,
                paths_with_violation=len(witnesses),witnesses=witnesses)


def recorded_plan(reference):
    saved = read(check_ref(reference['plan'])['path'])
    census = make_plan(saved['threads'],saved['max_switches'],saved['budget'],saved.get('start',0))
    require(all(saved[k]==census[k] for k in ('selected','total_eligible','unexplored'))
            and saved['counts_by_depth']=={str(d):v for d,v in census['counts_by_depth'].items()},
            'recorded search limits differ from the schedule space')
    orders = saved['orders']
    require(len(orders)==saved['selected'] and len({tuple(order) for order in orders})==len(orders)
            and all(sum(a!=b for a,b in zip(order,order[1:]))<=saved['max_switches'] for order in orders),
            'recorded orders exceed search limits or repeat')
    # Replay the schedules that actually ran, even if future versions rank them differently.
    return saved


def initrd(path, module, plan):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in ('dev','sysroot','payload'):
            (root/name).mkdir()
        payload = root/'payload'
        subprocess.run(['gcc','-static','-O2',REPO/'scripts/iio-path/init.c','-o',root/'init'],check=True)
        shutil.copyfile(FIXTURE/'observe.sh',payload/'observe.sh')
        shutil.copyfile(module['path'],payload/'regmap_actors.ko')
        (payload/'module.sha256').write_text(module['sha256']+'  regmap_actors.ko\n')
        with (payload/'plans').open('w') as stream:
            for i,order in enumerate(plan['orders']):
                print(i,plan['threads'],''.join(map(str,order)),file=stream)
        names = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        archive = subprocess.run(['cpio','--quiet','-o','-H','newc','--owner=0:0'],cwd=root,
                                 input=('\n'.join(names)+'\n').encode(), stdout=subprocess.PIPE,check=True)
        path.write_bytes(gzip.compress(archive.stdout,mtime=0))


def run(args):
    out = args.out.resolve()
    require(not out.is_relative_to(REPO), 'keep raw execution records outside the repository')
    out.mkdir(parents=True,exist_ok=False)
    result = dict(kind='kconc.regmap-actors.v1',mode='replay' if args.replay else 'record',status='failed')
    try:
        receipt = read(args.build)
        require(receipt['kind']=='kconc.regmap-actors.module.v1' and receipt['status']=='passed','module build failed')
        identity = check_identity(check_ref(receipt['identity'])['path'],expected_purpose='detection')
        require(identity['family']=='linux-original' and identity['variant']=='original' and
                receipt['identity_id']==identity['identity_id'] and receipt['kernel_build_id']==identity['gnu_build_id'],
                'expected the original detection kernel for this module')
        for filename in ('Makefile','regmap_actors.c'):
            snapshot = check_ref(receipt['sources'][filename])
            if not args.replay:
                require(snapshot['sha256']==sha(FIXTURE/filename),'fixture source drift')
        module = check_ref(receipt['module'])
        require(elf_id(module['path'])==receipt['module_build_id'], 'module ELF mismatch')
        disk = ref(args.disk)
        result.update(build=ref(args.build), identity_id=identity['identity_id'], kernel_build_id=identity['gnu_build_id'],
                      module=module,module_build_id=receipt['module_build_id'],disk=disk, reference=None)
        if args.replay:
            require(all(v is None for v in (args.budget,args.start,args.max_switches,args.max_active)),
                    'a replay uses the recorded schedule, budget and property')
            reference_path = args.replay/'result.json' if args.replay.is_dir() else args.replay
            previous = read(reference_path)
            require(previous['kind']==result['kind'] and previous['mode']=='record' and previous['status']=='passed'
                    and previous['guest_clean'] is True and previous['exit_code']==0
                    and all(result[key]==previous[key] for key in ('build','module','identity_id','disk',
                                                                    'kernel_build_id','module_build_id')),
                    'reference was not recorded on this build and disk')
            plan = recorded_plan(previous)
            require(previous['threads']==plan['threads'], 'archived thread count differs from plan')
            raw = Path(check_ref(previous['serial'])['path']).read_text(errors='replace')
            old_nonce,old_cases,healthy = decode(raw,plan,identity,receipt['module_build_id'])
            require(healthy and old_cases==previous['cases'] and all(c['status']=='passed' for c in old_cases)
                    and old_nonce==previous['guest_nonce'], 'reference differs from its raw evidence')
            if 'max_active' in plan:
                require(capacity(old_cases,plan['max_active'])==previous['capacity'],
                        'archived property differs from the observed register values')
            else:
                require('capacity' not in previous, 'reference contains an unrequested property')
            result['reference'] = ref(reference_path)
        else:
            plan = make_plan(args.threads,args.max_switches,args.budget,0 if args.start is None else args.start)
            if args.max_active is not None:
                plan['max_active'] = args.max_active
        if 'max_active' in plan:
            require(type(plan['max_active']) is int and 0 <= plan['max_active'] <= plan['threads'],
                    'max-active must be between zero and the number of roles')
        save(out/'plan.json',plan)
        result.update(plan=ref(out/'plan.json'),threads=plan['threads'])
        result['cases']=unverified_cases(plan,'')
        initrd(out/'initrd.gz',module,plan)
        cmd = ['qemu-system-x86_64','-accel','kvm','-cpu','host','-smp','4','-m','4096','-no-reboot',
               '-nodefaults','-display','none','-monitor','none','-serial','file:'+str(out/'serial.log'),
               '-kernel',identity['artifacts']['image']['path'],'-initrd',str(out/'initrd.gz'),
               '-append',('console=ttyS0 panic=-1 loglevel=4 kconc.identity='+identity['identity_id']
                          +' kconc.actors_plan='+result['plan']['sha256']),
               '-drive',f'file={disk["path"]},format=qcow2,if=virtio,readonly=on']
        save(out/'launch.json',dict(command=cmd,identity_id=identity['identity_id'],initrd=ref(out/'initrd.gz'),
                                    observer=ref(FIXTURE/'observe.sh'),module=module))
        with (out/'qemu.log').open('wb') as log:
            try:
                proc = subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=120+12*len(plan['orders']))
                result['exit_code']=proc.returncode
            except subprocess.TimeoutExpired:
                result.update(timed_out=True,exit_code=None)
        raw = (out/'serial.log').read_text(errors='replace') if (out/'serial.log').is_file() else ''
        result['cases']=unverified_cases(plan,raw)
        nonce,cases,healthy = decode(raw,plan,identity,receipt['module_build_id'],require_plan_token=True)
        result.update(guest_nonce=nonce,cases=cases,guest_clean=healthy)
        if 'max_active' in plan:
            result['capacity'] = capacity(cases,plan['max_active'])
        require(sha(args.disk)==disk['sha256'], 'read-only guest disk digest differs')
        require(healthy and result['exit_code']==0 and all(c['status']=='passed' for c in cases),
                'guest, path or state failed verification; see result.json and serial.log')
        if args.replay:
            require(nonce!=old_nonce, 'expected a separate cold boot')
            require(result.get('capacity')==previous.get('capacity'), 'replayed capacity witnesses differ')
            # Logical roles and observed state are stable across boots. Linux PIDs may change.
            for old,current in zip(old_cases,cases,strict=True):
                fields = ('step','role','before','after','rc')
                require([[r[k] for k in fields] for r in old['rows']]==
                        [[r[k] for k in fields] for r in current['rows']], 'replayed state path differs')
        result['status']='passed'
    except Exception as error:
        result['error']=str(error)
        raise ValueError(f'{error} (evidence: {out})') from error
    finally:
        if 'cases' in result:
            result['case_counts']=dict(Counter(c['status'] for c in result['cases']))
            if 'max_active' in plan and 'capacity' not in result:
                result['capacity']=capacity(result['cases'],plan['max_active'])
        if (out/'serial.log').is_file():
            result['serial']=ref(out/'serial.log')
        save(out/'result.json',result)
    return dict(status=result['status'],mode=result['mode'],threads=plan['threads'],executed=len(cases),
                paths_over_active_limit=result.get('capacity',{}).get('paths_with_violation'),
                eligible=plan['total_eligible'],unexplored=plan['unexplored'],
                observed_depths=dict(Counter(c['switches'] for c in cases)),result=str(out/'result.json'))


def main(argv=None):
    result = run(parser().parse_args(argv))
    print(json.dumps(result, indent=2))
    return 0

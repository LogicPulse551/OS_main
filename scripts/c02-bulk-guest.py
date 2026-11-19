#!/usr/bin/env python3
"""Collect one BMA400-shaped regmap benchmark run in the disposable guest."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


MODULE = 'kconc_c02_bulk'
DEBUG = Path('/sys/kernel/debug/kconc-c02-bulk')
TRACE = Path('/sys/kernel/tracing')
PROBES = {'r03bulk': 'regmap_bulk_read', 'r03noop': 'regmap_parse_inplace_noop'}


def guest_helper():
    for name in ('guest.py', 'c02-bench-guest.py'):
        path = Path(__file__).with_name(name)
        if path.is_file():
            spec = importlib.util.spec_from_file_location('c02_common', path)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            return helper
    raise FileNotFoundError('Upload c02-bench-guest.py alongside this script')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def loaded():
    return any(line.split()[0] == MODULE for line in Path('/proc/modules').read_text().splitlines())


def observers(helper):
    state = helper.observers()
    state['events_enabled'] = (TRACE/'events/enable').read_text().strip()
    return state


def quiet(state):
    return (state['tracing_on'] == '0' and state['tracer'] == 'nop' and
            state['kprobe_events'] is not None and not state['kprobe_events'].strip() and
            state['events_enabled'] == '0' and not state['perf_pids'])


def change_event(spec):
    # kprobe_events is a tracefs command stream. O_TRUNC would remove other definitions.
    fd = os.open(TRACE/'kprobe_events', os.O_WRONLY)
    try:
        line = (spec + '\n').encode()
        require(os.write(fd, line) == len(line), 'short kprobe event write')
    finally:
        os.close(fd)


def enable_probes(report, created):
    report['trace_before'] = (TRACE/'trace').read_text()
    (TRACE/'trace').write_text('')
    for name, symbol in PROBES.items():
        change_event(f'p:c02r03/{name} {symbol}')
        created.append(name)
        (TRACE/'events/c02r03'/name/'enable').write_text('1')
    report['probe_definitions'] = (TRACE/'kprobe_events').read_text()
    (TRACE/'tracing_on').write_text('1')
    report['observer_during'] = (TRACE/'tracing_on').read_text().strip()
    require(report['observer_during'] == '1', 'tracing did not start')


def read_trace(report):
    trace = (TRACE/'trace').read_text()
    report['trace'] = trace
    report['trace_stats'] = {p.parent.name:p.read_text() for p in (TRACE/'per_cpu').glob('cpu*/stats')}
    report['probe_profile'] = (TRACE/'kprobe_profile').read_text()
    pid = report['insertion']['pid']
    rows = [line for line in trace.splitlines() if re.search(rf'-{pid}\s', line)]
    for name, key in [('r03bulk','bulk_calls'),('r03noop','noop_calls')]:
        hits = [line for line in rows if re.search(rf'\b{name}:',line)]
        report[key] = len(hits)
        require(all(re.search(r'\[0*2\]',line) for line in hits),'probe hit outside CPU 2')
        profile = re.search(rf'^\s*(?:\S*/)?{name}\s+\d+\s+(\d+)\s*$', report['probe_profile'],re.M)
        require(profile and int(profile[1]) == 0, 'probe missed hits: '+name)
    require(report['bulk_calls'] == 16 and report['noop_calls'] in (0,96),'unexpected observed path counts')
    require(report['trace_stats'] and all(re.search(r'^overrun:\s+0$',v,re.M) for v in report['trace_stats'].values()),
            'trace buffer overrun or missing stats')


def validate(result, mode, calls, warmups, samples):
    require(result['mode'] == mode and (result['calls'],result['warmups'],result['samples']) == (calls,warmups,samples),
            'module parameter mismatch')
    if mode == 'check':
        expected_data = '123456789abc'
        require(len(result['checks']) == 8 and not result['rows'], 'unexpected check count')
        for row, (bits, fail) in zip(result['checks'],[(b,f) for b in (8,16) for f in range(4)]):
            n = fail or 3
            wire = bytes(0x84+i*(16//bits) for i in range(n)).ljust(3,b'\0').hex()
            data = (expected_data[0:4*(fail-1)].ljust(12,'c') if fail else
                    ('34127856bc9a' if bits == 16 else expected_data))
            converter = 'regmap_parse_inplace_noop' if bits == 8 else 'regmap_parse_16_be_inplace'
            require((row['bits'],row['fail_at'],row['rc'],row['transfers'],row['wire'],row['lengths'],
                     row['data'],row['converter'],row['result']) ==
                    (bits,fail,[0,-5,-110,-121][fail],n,wire,('02'*n).ljust(6,'0'),data,converter,0),
                    f'{bits}-bit transfer check failed at {fail}')
    else:
        require(len(result['rows']) == warmups+samples and not result['checks'],'unexpected batch count')
        for i, row in enumerate(result['rows']):
            require((row['sample'],row['warmup'],row['cycles'],row['bus_reads'],row['cpu_start'],row['cpu_end'],row['result']) ==
                    (i if i < warmups else i-warmups,int(i<warmups),calls,3*calls,2,2,0) and row['elapsed_ns'] > 0,
                    'unexpected counters, CPU or time in batch '+str(i))


def run(operation, module, report):
    helper = guest_helper()
    require(os.geteuid() == 0, 'use the disposable guest root account')
    expected = os.environ.get('C02_MODULE_SHA256')
    if not expected:
        expected = Path(str(module)+'.sha256').read_text().split()[0]
    report['expected_module_sha256'] = expected
    report['module_sha256'] = hashlib.sha256(module.read_bytes()).hexdigest()
    require(re.fullmatch('[a-f0-9]{64}',expected) and report['module_sha256'] == expected, 'module SHA256 mismatch')
    report['observers_before'] = observers(helper)
    require(quiet(report['observers_before']), 'prepare the disposable guest before measuring')
    require(not loaded() and not DEBUG.exists(), 'benchmark already active')
    report['dmesg_before'] = helper.command(['dmesg','--color=never'])
    require(report['dmesg_before']['exit_code'] == 0,'dmesg unavailable')
    report['kernel_release'] = os.uname().release
    report['kernel_cmdline'] = Path('/proc/cmdline').read_text().strip()
    created = []
    observe = operation == 'observe'
    mode = 'bench' if observe else operation
    calls, warmups, samples = (16,0,1) if observe else (20000,2,4)
    errors = report['errors']
    try:
        if observe:
            enable_probes(report,created)
        report['insertion'] = helper.command(['taskset','-c','2','insmod',str(module),
                                              f'mode={mode}',f'calls={calls}',f'warmups={warmups}',f'samples={samples}'])
        if observe:
            (TRACE/'tracing_on').write_text('0')
            read_trace(report)
        require(report['insertion']['exit_code'] == 0 and loaded(),'module insertion failed')
        report['results_raw'] = (DEBUG/'results').read_text()
        report['results'] = json.loads(report['results_raw'])
        validate(report['results'], mode, calls, warmups, samples)
    except Exception as exc:
        errors.append(repr(exc))
    finally:
        if observe:
            try:
                (TRACE/'tracing_on').write_text('0')
                if 'trace' not in report:
                    report['trace'] = (TRACE/'trace').read_text()
            except OSError as exc:
                errors.append(repr(exc))
            for name in reversed(created):
                try:
                    (TRACE/'events/c02r03'/name/'enable').write_text('0')
                    change_event('-:c02r03/'+name)
                except OSError as exc:
                    errors.append(repr(exc))
        report['cleanup'] = helper.command(['rmmod',MODULE]) if loaded() else dict(exit_code=0,already_absent=True)
        report['module_absent'] = not loaded()
        report['result_directory_absent'] = not DEBUG.exists()
        report['dmesg_after'] = helper.command(['dmesg','--color=never'])
        after = report['dmesg_after']['stdout']
        before = report['dmesg_before']['stdout']
        require(after.startswith(before),'kernel log lost its starting position')
        report['kernel_warnings'] = [line for line in after[len(before):].splitlines()
                                     if re.search(r'WARNING:|BUG:|Oops:|KASAN:|KFENCE:|kernel panic|general protection fault',
                                                  line,re.I)]
        report['observers_after'] = observers(helper)
        require(report['dmesg_after']['exit_code'] == 0 and not report['kernel_warnings'], 'kernel log check failed')
        require(report['cleanup']['exit_code'] == 0 and report['module_absent'] and
                report['result_directory_absent'] and quiet(report['observers_after']), 'cleanup incomplete')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=('check','bench','raw','observe'))
    p.add_argument('module',type=Path)
    args = p.parse_args()
    report = dict(operation=args.operation, passed=False, errors=[])
    try:
        run(args.operation,args.module,report)
        report['passed'] = not report['errors']
    except Exception as exc:
        report['errors'].append(repr(exc))
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

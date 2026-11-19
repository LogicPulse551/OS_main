#!/usr/bin/env python3
"""Run and retain a regcache benchmark on the project's disposable guest."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

MODULE = 'kconc_c02_bench'
TRACE = Path('/sys/kernel/tracing')

def command(argv):
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = p.communicate()
    return dict(argv=argv, pid=p.pid, exit_code=p.returncode, stdout=stdout, stderr=stderr)

def loaded():
    return any(line.split()[0] == MODULE for line in Path('/proc/modules').read_text().splitlines())

def observers():
    processes = []
    for p in Path('/proc').glob('[0-9]*/comm'):
        try:
            if p.read_text().strip() == 'perf': processes.append(int(p.parent.name))
        except (OSError, ProcessLookupError): pass
    return dict(perf_pids=processes,
        tracing_on=(TRACE/'tracing_on').read_text().strip() if (TRACE/'tracing_on').exists() else None,
        tracer=(TRACE/'current_tracer').read_text().strip() if (TRACE/'current_tracer').exists() else None,
        kprobe_events=(TRACE/'kprobe_events').read_text() if (TRACE/'kprobe_events').exists() else None)

def inventory():
    return dict(release=os.uname().release, cmdline=Path('/proc/cmdline').read_text(),
        config_sha256=hashlib.sha256(gzip.decompress(Path('/proc/config.gz').read_bytes())).hexdigest(),
        notes=base64.b64encode(Path('/sys/kernel/notes').read_bytes()).decode(),
        cpu_online=Path('/sys/devices/system/cpu/online').read_text().strip(),
        modules=Path('/proc/modules').read_text(), observers=observers(),
        tools={n:shutil.which(n) for n in ['perf','dnf','taskset','insmod','rmmod','mount']})

def prepare():
    records=[]
    for kind,path in [('debugfs','/sys/kernel/debug'),('tracefs',str(TRACE))]:
        p=command(['mountpoint','-q',path]);records.append(p)
        if p['exit_code']:
            p=command(['mount','-t',kind,'none',path]);records.append(p)
            if p['exit_code']:raise RuntimeError(p)
    (TRACE/'tracing_on').write_text('0')
    (TRACE/'current_tracer').write_text('nop')
    (TRACE/'events/enable').write_text('0')
    return dict(commands=records, inventory=inventory())

def run(a):
    report=dict(passed=False, parameters={k:getattr(a,k) for k in ['samples','warmups','quick','diagnostic','case_id','scale']},
        module_sha256=hashlib.sha256(a.module.read_bytes()).hexdigest(), observers_before=observers(),
        dmesg_before=command(['dmesg','--color=never']), cleanup=None)
    if loaded():raise RuntimeError('Previous benchmark module is still loaded')
    args=[str(a.module),f'samples={a.samples}',f'warmups={a.warmups}',f'quick={a.quick}',f'diagnostic={a.diagnostic}',f'case_id={a.case_id}',f'scale={a.scale}']
    try:
        r=command(['taskset','-c','2','insmod',*args]);report['insertion']=r
        if r['exit_code']:
            report['error']='module insertion failed; raw rows are in dmesg_after'
        else:
            report['module_loaded']=loaded()
            report['results']=json.loads(Path('/sys/kernel/debug/kconc-c02/results').read_text())
            report['passed']=report['module_loaded'] and all(r['result']==0 for r in report['results']['rows'])
    except BaseException as e:
        report['error']=repr(e)
    finally:
        report['cleanup']=command(['rmmod',MODULE]) if loaded() else dict(exit_code=0,already_absent=True)
        report['module_absent']=not loaded()
        report['result_directory_absent']=not Path('/sys/kernel/debug/kconc-c02').exists()
        report['dmesg_after']=command(['dmesg','--color=never'])
        report['observers_after']=observers()
        report['passed']=bool(report['passed'] and report['cleanup']['exit_code']==0 and report['module_absent'] and report['result_directory_absent'])
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=['inventory','prepare','run'])
    p.add_argument('--module',type=Path,default=Path('/home/lab/c02/kconc-c02-bench.ko'))
    p.add_argument('--samples',type=int,default=3);p.add_argument('--warmups',type=int,default=2)
    p.add_argument('--quick',type=int,default=0);p.add_argument('--diagnostic',type=int,default=0)
    p.add_argument('--case-id',type=int,default=5);p.add_argument('--scale',type=int,default=1)
    a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('Use the disposable guest root account')
    result=inventory() if a.operation=='inventory' else prepare() if a.operation=='prepare' else run(a)
    print(json.dumps(result,ensure_ascii=False))
    if result.get('passed') is False:raise SystemExit(1)

if __name__=='__main__':main()

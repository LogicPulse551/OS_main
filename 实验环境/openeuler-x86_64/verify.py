#!/usr/bin/env python3
"""Read back the running environment and save evidence; no benchmark claims."""
import datetime
import json
from pathlib import Path
import subprocess
import lab

GUEST_SCRIPT = r'''
import json, os, pathlib, platform, subprocess, urllib.request
def run(args):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=25)
    return {'exit_code':p.returncode,'output':p.stdout.strip()}
result={
 'os_release':pathlib.Path('/etc/os-release').read_text(),
 'kernel':platform.release(), 'arch':platform.machine(),
 'cpu_count':os.cpu_count(),
 'cpu_online':pathlib.Path('/sys/devices/system/cpu/online').read_text().strip(),
 'memory':pathlib.Path('/proc/meminfo').read_text().splitlines()[:3],
 'root_mount':run(['findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','/']),
 'sudo':run(['sudo','-n','true']),
 'system_state':run(['systemctl','is-system-running']),
 'failed_units':run(['systemctl','--failed','--no-legend','--no-pager']),
 'cloud_init':run(['rpm','-q','cloud-init']),
 'ssh_policy':run(['sudo','-n','sshd','-T']),
 'persistence_marker':pathlib.Path('/home/lab/lab-persistence-marker').read_text().strip()
   if pathlib.Path('/home/lab/lab-persistence-marker').exists() else None,
}
try:
 with urllib.request.urlopen('https://repo.openeuler.org/openEuler-24.03-LTS-SP3/virtual_machine_img/x86_64/openEuler-24.03-LTS-SP3-x86_64.qcow2.xz.sha256sum',timeout=25) as response:
    result['outbound_https']={'status':response.status,'checksum':response.read(1024).decode().strip()}
except Exception as error:
 result['outbound_https']={'error':str(error)}
result['ssh_policy']['output']='\n'.join(line for line in result['ssh_policy']['output'].splitlines()
 if line.split()[0] in ('passwordauthentication','kbdinteractiveauthentication','permitrootlogin','pubkeyauthentication'))
print(json.dumps(result))
'''

def main():
    vm=lab.qmp('query-status'); kvm=lab.qmp('query-kvm')
    proc=subprocess.run(lab.ssh_args()+['python3','-'],input=GUEST_SCRIPT,text=True,
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=True)
    guest=json.loads(proc.stdout)
    result={'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'qemu':subprocess.check_output(['qemu-system-x86_64','--version'],text=True).splitlines()[0],
            'host_arch':subprocess.check_output(['uname','-m'],text=True).strip(),
            'vm':vm,'kvm':kvm,'qmp_cpu_count':len(lab.qmp('query-cpus-fast')),
            'guest':guest}
    checks={'running':vm.get('running') is True,
            'kvm_enabled':kvm.get('enabled') is True,
            'guest_is_openeuler':'ID="openEuler"' in guest['os_release'] or 'ID=openEuler' in guest['os_release'],
            'guest_arch':guest['arch']=='x86_64',
            'four_cpus':guest['cpu_count']==4 and result['qmp_cpu_count']==4,
            'sudo':guest['sudo']['exit_code']==0,
            'outbound_https':guest['outbound_https'].get('status')==200,
            'ssh_password_disabled':'passwordauthentication no' in guest['ssh_policy']['output'],
            'ssh_root_disabled':'permitrootlogin no' in guest['ssh_policy']['output']}
    result['checks']=checks
    target=lab.LAB/'evidence/environment-check.json'
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if not all(checks.values()):
        raise SystemExit('Some environment checks failed; see evidence JSON.')

if __name__ == '__main__':
    main()

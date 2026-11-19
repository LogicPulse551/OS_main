#!/usr/bin/env python3
"""One-time fallback for an official image that does not process NoCloud."""
import base64
import getpass
import os
from pathlib import Path
import shlex
import sys
import pexpect
import lab

def main(initial_password=None):
    os.umask(0o077)
    key=(lab.LAB/'keys/id_ed25519.pub').read_text().strip()
    script='''set -eu
if ! id lab >/dev/null 2>&1; then useradd -m -s /bin/bash lab; fi
install -d -m 700 -o lab -g lab /home/lab/.ssh
printf '%s\\n' KEY_VALUE > /home/lab/.ssh/authorized_keys
chown lab:lab /home/lab/.ssh/authorized_keys
chmod 600 /home/lab/.ssh/authorized_keys
printf '%s\\n' 'lab ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-os-concurrency-lab
chmod 440 /etc/sudoers.d/90-os-concurrency-lab
visudo -cf /etc/sudoers.d/90-os-concurrency-lab
hostnamectl set-hostname oe-kernel-lab
cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-kernel-lab || true
# Put the lab policy first: sshd uses the first obtained value for each option.
python3 - <<'INNER'
from pathlib import Path
p=Path('/etc/ssh/sshd_config'); old=p.read_text()
header='# os-concurrency-lab policy\\nPasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin no\\nPubkeyAuthentication yes\\n'
if not old.startswith('# os-concurrency-lab policy\\n'):
    p.write_text(header+old)
INNER
sshd -t
passwd -l root >/dev/null
systemctl reload sshd
echo LAB_PROVISION_OK
'''.replace('KEY_VALUE',shlex.quote(key))
    encoded=base64.b64encode(script.encode()).decode()
    command='printf %s '+shlex.quote(encoded)+' | base64 -d | bash'
    args=lab.ssh_args()
    args=[a.replace('BatchMode=yes','BatchMode=no').replace('lab@127.0.0.1','root@127.0.0.1') for a in args]
    args += ['-o','NumberOfPasswordPrompts=1',command]
    child=pexpect.spawn(args[0],args[1:],encoding='utf-8',timeout=90,echo=False)
    index=child.expect([r'(?i)password:',pexpect.EOF])
    if index == 0:
        password=initial_password if initial_password is not None else getpass.getpass('Official image initial root password: ')
        child.sendline(password)
        password=None
        child.expect(pexpect.EOF)
    output=child.before
    child.close()
    print(output)
    if child.exitstatus != 0 or 'LAB_PROVISION_OK' not in output:
        raise SystemExit('Provisioning did not finish; inspect the guest before retrying.')

if __name__ == '__main__':
    main()

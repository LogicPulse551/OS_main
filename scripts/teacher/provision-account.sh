#!/bin/bash
# Runs inside the pristine guest's disposable overlay before an experimental boot.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if getent passwd lab >/dev/null; then
    echo 'Expected a pristine guest without an existing teacher account' >&2
    exit 1
fi
useradd --create-home --shell /bin/bash --groups wheel lab
passwd --lock lab >/dev/null
install -o lab -g lab -m 0700 -d /home/lab/.ssh
install -o lab -g lab -m 0600 /dev/null /home/lab/.ssh/authorized_keys
printf '%s\n' 'lab ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/kconc-session
chmod 0440 /etc/sudoers.d/kconc-session
visudo -cf /etc/sudoers.d/kconc-session >/dev/null
if command -v restorecon >/dev/null; then
    restorecon -RF /home/lab/.ssh /etc/sudoers.d/kconc-session
fi

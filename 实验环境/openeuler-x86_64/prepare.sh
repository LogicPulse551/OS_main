#!/usr/bin/env bash
set -euo pipefail
umask 077
LAB_DIR="${LAB_DIR:-$HOME/os-concurrency-lab}"
BASE_NAME=openEuler-24.03-LTS-SP3-x86_64.qcow2
BASE_URL=https://repo.openeuler.org/openEuler-24.03-LTS-SP3/virtual_machine_img/x86_64
EXPECTED_SHA256=fff27c52fd7b9921d46c11215488737162a86e91819de2bf5a75743fabd1291f
mkdir -p "$LAB_DIR"/{images,keys,run,logs,seed,evidence,bin}
exec 9>"$LAB_DIR/run/control.lock"
flock -n 9 || { printf 'Another lifecycle operation is active.\n' >&2; exit 1; }
if [[ -f "$LAB_DIR/run/qemu.pid" ]] && kill -0 "$(cat "$LAB_DIR/run/qemu.pid")" 2>/dev/null; then
  printf 'Stop the VM before preparing its disks or seed.\n' >&2
  exit 1
fi
cd "$LAB_DIR/images"
curl -fL --retry 3 --connect-timeout 20 "$BASE_URL/$BASE_NAME.xz.sha256sum" -o official.sha256sum
if [[ ! -f "$BASE_NAME.xz" ]]; then
  curl -fL --retry 5 --connect-timeout 20 --speed-limit 1024 --speed-time 60 -C - "$BASE_URL/$BASE_NAME.xz" -o "$BASE_NAME.xz.partial"
  printf '%s  %s\n' "$EXPECTED_SHA256" "$BASE_NAME.xz.partial" | sha256sum -c -
  mv "$BASE_NAME.xz.partial" "$BASE_NAME.xz"
fi
printf '%s  %s\n' "$EXPECTED_SHA256" "$BASE_NAME.xz" | sha256sum -c -
sha256sum -c official.sha256sum
if [[ ! -f "$BASE_NAME" ]]; then
  xz -dc "$BASE_NAME.xz" > "$BASE_NAME.partial"
  qemu-img check "$BASE_NAME.partial"
  mv "$BASE_NAME.partial" "$BASE_NAME"
  chmod 444 "$BASE_NAME"
fi
qemu-img info --output=json "$BASE_NAME" > "$LAB_DIR/evidence/base-image.json"
if [[ ! -f "$LAB_DIR/images/experiment.qcow2" ]]; then
  qemu-img create -f qcow2 -F qcow2 -b "$LAB_DIR/images/$BASE_NAME" "$LAB_DIR/images/experiment.qcow2"
fi
if [[ ! -f "$LAB_DIR/keys/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C os-concurrency-lab -f "$LAB_DIR/keys/id_ed25519"
fi
python3 - "$LAB_DIR" <<'PY'
import pathlib, sys
p=pathlib.Path(sys.argv[1]); key=(p/'keys/id_ed25519.pub').read_text().strip()
(p/'seed/user-data').write_text('''#cloud-config
hostname: oe-kernel-lab
manage_etc_hosts: true
disable_root: true
ssh_pwauth: false
users:
  - name: lab
    groups: [wheel]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - '''+key+'''
''')
(p/'seed/meta-data').write_text('instance-id: oe-kernel-lab-20261107\nlocal-hostname: oe-kernel-lab\n')
PY
if [[ ! -f "$LAB_DIR/seed/seed.img" ]]; then
  cloud-localds "$LAB_DIR/seed/seed.img" "$LAB_DIR/seed/user-data" "$LAB_DIR/seed/meta-data"
fi
printf 'Prepared: %s\n' "$LAB_DIR"

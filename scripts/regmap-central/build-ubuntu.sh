#!/usr/bin/env bash
# Build the Ubuntu source package and the regmap configuration used for these runs.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo 'usage: bash build-ubuntu.sh linux_6.8.0-31.31.dsc NEW_DIR' >&2
    exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
dsc=$(realpath "$1")
dst=$(realpath -m "$2")
printf '%s  %s\n' 6689c76a5d61f282ef01adf3ef9d9afa0fc8316e1575a10a0a212d6987e9633e "$dsc" | sha256sum -c -
mkdir "$dst"
cd "$(dirname "$dsc")"
awk '/^Checksums-Sha256:/{on=1;next} on && /^ /{print $1 "  " $3; next} {on=0}' "$dsc" > "$dst/source.sha256"
sha256sum -c "$dst/source.sha256"
dpkg-source --no-check -x "$dsc" "$dst/src"
# REGMAP is selected by real subsystem users. The RAM module needs the core in
# the minimal kernel even when all hardware drivers are disabled.
cat >> "$dst/src/drivers/base/regmap/Kconfig" <<'END_CONFIG'

config KCONC_NORMAL_REGMAP_TEST
	bool "Build regmap for normal two-role tests"
	select REGMAP
END_CONFIG
mkdir "$dst/obj"
cp "$here/ubuntu.config" "$dst/obj/.config"
make -C "$dst/src" O="$dst/obj" olddefconfig
for opt in SMP MODULES MODULE_UNLOAD REGMAP TRACING FTRACE EXT4_FS VIRTIO_BLK; do
    grep -qx "CONFIG_$opt=y" "$dst/obj/.config"
done
make -C "$dst/src" O="$dst/obj" -j"${JOBS:-4}" bzImage modules

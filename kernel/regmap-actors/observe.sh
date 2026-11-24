#!/bin/bash
set -euo pipefail
cd /run/iio
dmesg -n 1
test "$(cat /sys/block/vda/ro)" = 1
test -z "$(cat /proc/modules)"
grep '^PRETTY_NAME=' /etc/os-release
echo "RELEASE $(uname -r)"
echo "CMDLINE $(cat /proc/cmdline)"
echo "NONCE $(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
echo "KERNEL_NOTES $(od -An -v -tx1 /sys/kernel/notes | tr -d ' \n')"
gzip -dc /proc/config.gz | sha256sum | awk '{print "CONFIG",$1}'
sha256sum -c module.sha256
tr=/sys/kernel/tracing
mount -t tracefs tracefs "$tr"
echo global > "$tr/trace_clock"
for ev in regmap_reg_read regmap_reg_write; do
    echo 1 > "$tr/events/regmap/$ev/enable"
done
dmesg -c | grep -E 'BUG:|WARNING: CPU:|Oops:' || true
while read -r seq threads order; do
    echo "CASE $seq $order"
    echo 0 > "$tr/tracing_on"
    echo > "$tr/trace"
    echo 1 > "$tr/tracing_on"
    load=0
    unload=0
    insmod ./regmap_actors.ko threads="$threads" order="$order" || load=$?
    if (( load == 0 )); then
        echo "MODULE_NOTES $(od -An -v -tx1 /sys/module/regmap_actors/notes/.note.gnu.build-id | tr -d ' \n')"
        rmmod regmap_actors || unload=$?
    fi
    echo 0 > "$tr/tracing_on"
    cat "$tr/trace" | awk '/entries-in-buffer\/entries-written:/ || /regmap_reg_(read|write): regmap_actors reg=/'
    dmesg -c | grep -E 'REGACT |BUG:|WARNING: CPU:|Oops:' || true
    clean=0
    if test -z "$(cat /proc/modules)"; then clean=1; fi
    echo "END $seq load=$load unload=$unload clean=$clean"
    test "$clean" -eq 1
done < plans

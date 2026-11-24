#!/bin/bash
set -eu -o pipefail
trap 'echo "GUEST_FAILURE line=$LINENO status=$?"; dmesg | tail -16' ERR
cd /run/iio
T=/sys/kernel/tracing
test "$(cat /sys/block/vda/ro)" = 1
echo "TRIBOOT $(cat /proc/sys/kernel/random/boot_id) readonly=1"
echo "KERNELNOTES $(od -An -v -tx1 /sys/kernel/notes | tr -d ' \n')"
mountpoint -q "$T" || mount -t tracefs tracefs "$T"
echo 0 > "$T/tracing_on"
echo global > "$T/trace_clock"
echo 0 > "$T/events/enable"
for kind in read write; do echo 1 > "$T/events/regmap/regmap_reg_$kind/enable"; done
while read -r prop variant order; do
    echo "CASE_BEGIN $prop $variant $order"
    test ! -d /sys/module/regmap_three_check
    dmesg -C
    echo > "$T/trace"
    echo 1 > "$T/tracing_on"
    sha256sum "$variant.ko"
    insmod "./$variant.ko" property="$prop" variant="$variant" order="$order"
    dir=/sys/module/regmap_three_check
    echo "MODNOTES $(od -An -v -tx1 "$dir/notes/.note.gnu.build-id" | tr -d ' \n')"
    echo "PARAMS $(cat "$dir/parameters/property") $(cat "$dir/parameters/variant") $(cat "$dir/parameters/order")"
    rmmod regmap_three_check
    test ! -d "$dir"
    echo 0 > "$T/tracing_on"
    dmesg
    cat "$T/trace"
    awk '/^overrun:|^commit overrun:|^dropped events:/{print "BUFFER", $0}' "$T"/per_cpu/cpu*/stats
    echo "CASE_END"
done < cases.tsv
echo 0 > "$T/events/enable"
echo "SUITE_CLEAN"

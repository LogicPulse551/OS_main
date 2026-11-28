#!/bin/bash
set -Eeuo pipefail
trap 'echo "GUEST_FAILURE line=$LINENO status=$?"; dmesg | tail -12' ERR
payload=/run/k14
T=/sys/kernel/tracing
result=/run/iio-capture
mkdir -p "$result"
mount -t ext4 /dev/vdb "$result"
cd "$result"
boot=$(cat /proc/sys/kernel/random/boot_id)
echo "BOOT $boot"
test "$(cat /sys/block/vda/ro)" = 1
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug
mountpoint -q "$T" || mount -t tracefs tracefs "$T"
insmod "$payload/board.ko"
devices=()
for dev in /sys/bus/iio/devices/iio:device*; do
    if [[ -r "$dev/in_accel_x_raw" && -r "$dev/in_accel_y_raw" ]]; then devices+=("$dev"); fi
done
test "${#devices[@]}" = 1
device=${devices[0]}
sensor=$(dirname "$(readlink -f "$device")")
driver=$(basename "$(readlink -e "$sensor/driver")")
board=$(modinfo -F name "$payload/board.ko")
test "$(cat "$device/buffer/enable")" = 0
cp /sys/kernel/notes kernel.notes
cp "/sys/module/$board/notes/.note.gnu.build-id" board.notes
mode=
for arg in $(cat /proc/cmdline); do
    case "$arg" in iio.mode=*) mode=${arg#iio.mode=} ;; esac
done
printf 'boot_id=%s\niio_name=%s\nbound_driver=%s\nboard_module=%s\nmode=%s\n' \
       "$boot" "$(cat "$device/name")" "$driver" "$board" "$mode" > run.env
sha256sum "$payload/read-axes" "$payload/board.ko" "$payload/observe.sh" > guest-payload.sha256
echo 0 > "$T/tracing_on"
echo nop > "$T/current_tracer"
echo global > "$T/trace_clock"
echo 2048 > "$T/buffer_size_kb"
echo 0 > "$T/events/enable"
test "$(basename "$(readlink -e "$sensor/subsystem")")" = i2c
client=${sensor##*/}
[[ "$client" =~ ^([0-9]+)-([[:xdigit:]]{4})$ ]]
printf 'bus=i2c\ni2c_client=%s\ni2c_adapter_nr=%s\ni2c_address=%s\n' \
    "$client" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" >> run.env
test -d "$T/events/regmap"
for event in i2c_write i2c_read i2c_reply i2c_result; do
    test -r "$T/events/i2c/$event/format"
done
for group in regmap i2c; do
    if [[ -d "$T/events/$group" ]]; then
        echo 1 > "$T/events/$group/enable"
        for file in "$T/events/$group"/*/format; do
            printf '\nEVENT %s\n' "$file"; cat "$file"
        done
    else
        echo "UNAVAILABLE $group"
    fi
done > formats.txt
echo > "$T/trace"
echo 1 > "$T/tracing_on"
capture() { "$payload/read-axes" "$device" "$@" >> ops.tsv; }
case "$mode" in
    train)
        capture seq t01 X t02 Y
        capture seq t03 Y t04 X
        capture seq t05 X t06 Y
        capture seq t07 Y t08 X ;;
    xy-first) capture seq xy1 X xy2 Y; capture seq yx1 Y yx2 X ;;
    yx-first) capture seq yx1 Y yx2 X; capture seq xy1 X xy2 Y ;;
    natural)
        for n in 01 02 03 04 05 06 07 08; do capture parallel "nx$n" X "ny$n" Y; done ;;
    *) echo "unknown mode $mode"; exit 1 ;;
esac
echo 0 > "$T/tracing_on"
cat "$T/trace" > trace.txt
for file in "$T"/per_cpu/cpu*/stats; do echo "$file"; cat "$file"; done > stats.txt
echo 0 > "$T/events/enable"
echo "${sensor##*/}" > "$sensor/driver/unbind"
test ! -e "$device/name"
rmmod "$board"
test ! -d "/sys/module/$board"
echo 'cleaned=1' >> run.env
sha256sum -- *.words ops.tsv trace.txt run.env formats.txt stats.txt kernel.notes board.notes guest-payload.sha256 > capture.sha256
echo "CAPTURE $(sha256sum capture.sha256)"
cd /
umount "$result"

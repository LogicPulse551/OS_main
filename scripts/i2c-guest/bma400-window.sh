#!/bin/bash
set -Eeuo pipefail
trap 'echo "GUEST_FAILURE line=$LINENO status=$?"; dmesg | tail -16' ERR
payload=/run/k14
T=/sys/kernel/tracing
result=/run/iio-capture
mkdir -p "$result"
mount -t ext4 /dev/vdb "$result"
cd "$result"
boot=$(cat /proc/sys/kernel/random/boot_id)
echo "BOOT $boot"
test "$(cat /sys/block/vda/ro)" = 1
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
test "$driver" = bma400
test "$(cat "$device/name")" = bma400
test "$(basename "$(readlink -e "$sensor/subsystem")")" = i2c
test "$(cat "$device/buffer/enable")" = 0
client=${sensor##*/}
[[ "$client" =~ ^([0-9]+)-([[:xdigit:]]{4})$ ]]
adapter=${BASH_REMATCH[1]}
address=${BASH_REMATCH[2]}
cp /sys/kernel/notes kernel.notes
cp "/sys/module/$board/notes/.note.gnu.build-id" board.notes
mode=
for arg in $(cat /proc/cmdline); do
    case "$arg" in iio.mode=*) mode=${arg#iio.mode=} ;; esac
done
params="/sys/module/$board/parameters"
case "$mode" in
    natural)
        count=96; owner=none; control=none
        test ! -e "$params/replay_arm" ;;
    active-X|active-Y)
        count=1; owner=${mode#active-}; control=adapter
        test -w "$params/replay_arm"; test -r "$params/replay_state" ;;
    *) echo "unknown mode $mode"; exit 1 ;;
esac
printf 'boot_id=%s\niio_name=bma400\nbound_driver=%s\nboard_module=%s\nmode=%s\n' \
    "$boot" "$driver" "$board" "$mode" > run.env
printf 'bus=i2c\ni2c_client=%s\ni2c_adapter_nr=%s\ni2c_address=%s\n' \
    "$client" "$adapter" "$address" >> run.env
printf 'group_count=%s\nowner=%s\ncontrol=%s\n' "$count" "$owner" "$control" >> run.env
sha256sum "$payload/read-pair" "$payload/board.ko" "$payload/observe.sh" > guest-payload.sha256
echo 0 > "$T/tracing_on"
echo nop > "$T/current_tracer"
echo global > "$T/trace_clock"
grep -q '\[global\]' "$T/trace_clock"
echo 'trace_clock=global' >> run.env
echo 4096 > "$T/buffer_size_kb"
echo 0 > "$T/events/enable"
printf '%s\n' 'p:iio_window/bma_enter bma400_read_raw' \
    'r:iio_window/bma_exit bma400_read_raw' \
    "p:iio_window/board_enter $board:board_xfer" \
    "r:iio_window/board_exit $board:board_xfer" >> "$T/kprobe_events"
test -r "$T/events/i2c/i2c_read/format"
test -r "$T/events/i2c/i2c_reply/format"
for group in regmap i2c iio_window; do
    echo 1 > "$T/events/$group/enable"
    for file in "$T/events/$group"/*/format; do
        printf '\nEVENT %s\n' "$file"; cat "$file"
    done
done > formats.txt
echo > "$T/trace"
echo 1 > "$T/tracing_on"
rc=0
"$payload/read-pair" "$device" "$mode" "$params" > ops.tsv || rc=$?
echo 0 > "$T/tracing_on"
echo "reader_exit=$rc" >> run.env
cat "$T/trace" > trace.txt
for file in "$T"/per_cpu/cpu*/stats; do echo "$file"; cat "$file"; done > stats.txt
cat "$T/kprobe_profile" > probes.txt
echo 0 > "$T/events/enable"
for name in board_exit board_enter bma_exit bma_enter; do
    echo "-:iio_window/$name" >> "$T/kprobe_events"
done
echo "${sensor##*/}" > "$sensor/driver/unbind"
test ! -e "$device/name"
rmmod "$board"
test ! -d "/sys/module/$board"
echo 'cleaned=1' >> run.env
files=(ops.tsv trace.txt run.env formats.txt stats.txt probes.txt kernel.notes board.notes guest-payload.sha256)
if [[ -e control.txt ]]; then files+=(control.txt); fi
sha256sum -- "${files[@]}" > capture.sha256
echo "CAPTURE $(sha256sum capture.sha256)"
cd /
umount "$result"


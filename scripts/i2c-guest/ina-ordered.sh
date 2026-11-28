#!/bin/bash
set -Eeuo pipefail
trap 'echo "GUEST_FAILURE line=$LINENO status=$?"; dmesg | tail -24' ERR
payload=/run/k14
trace=/sys/kernel/tracing
result=/run/hwmon-capture
mkdir -p "$result"
mount -t ext4 /dev/vdb "$result"
cd "$result"
# All assignments in this file are bound into and hashed with the initrd.
source "$payload/profile.env"
boot=$(cat /proc/sys/kernel/random/boot_id)
echo "BOOT $boot"
test "$(cat /sys/block/vda/ro)" = 1
mountpoint -q "$trace" || mount -t tracefs tracefs "$trace"
shopt -s nullglob
deps=("$payload"/dep-*.ko)
for file in "${deps[@]}"; do insmod "$file"; done
if [[ -f "$payload/driver.ko" ]]; then insmod "$payload/driver.ko"; fi
insmod "$payload/board.ko"
board=$(modinfo -F name "$payload/board.ko")
devices=()
for dev in /sys/class/hwmon/hwmon*; do
    if [[ "$(cat "$dev/name")" = "$hwmon_name" && -r "$dev/$channel_a" && -r "$dev/$channel_b" ]]; then
        devices+=("$dev")
    fi
done
test "${#devices[@]}" = 1
device=${devices[0]}
sensor=$(readlink -e "$device/device")
driver=$(basename "$(readlink -e "$sensor/driver")")
test "$driver" = "$expected_driver"
test "$(basename "$(readlink -e "$sensor/subsystem")")" = i2c
client=${sensor##*/}
[[ "$client" =~ ^([0-9]+)-([[:xdigit:]]{4})$ ]]
adapter=${BASH_REMATCH[1]}
address=${BASH_REMATCH[2]}
cp /sys/kernel/notes kernel.notes
cp "/sys/module/$board/notes/.note.gnu.build-id" board.notes
driver_target=$driver_symbol
driver_module=builtin
if [[ -f "$payload/driver.ko" ]]; then
    driver_module=$(modinfo -F name "$payload/driver.ko")
    test "$(basename "$(readlink -e "$sensor/driver/module")")" = "$driver_module"
    cp "/sys/module/$driver_module/notes/.note.gnu.build-id" driver.notes
    driver_target="$driver_module:$driver_symbol"
fi
mode=
for arg in $(cat /proc/cmdline); do
    case "$arg" in iio.mode=*) mode=${arg#iio.mode=} ;; esac
done
params="/sys/module/$board/parameters"
case "$mode" in
    train) count=4; owner=none; control=none ;;
    ordered) count=2; owner=none; control=none ;;
    natural) count=96; owner=none; control=none ;;
    active-A|active-B) count=1; owner=${mode#active-}; control=adapter ;;
    *) echo "unknown mode $mode"; exit 1 ;;
esac
if [[ "$control" = adapter ]]; then
    test -w "$params/replay_arm"; test -r "$params/replay_state"; test -n "$selector"
else
    test ! -e "$params/replay_arm"
fi
printf 'boot_id=%s\nhwmon_name=%s\nbound_driver=%s\nboard_module=%s\nmode=%s\n' \
       "$boot" "$hwmon_name" "$driver" "$board" "$mode" > run.env
printf 'driver_module=%s\ndriver_symbol=%s\ncore_symbol=%s\nchannel_a=%s\nchannel_b=%s\n' \
       "$driver_module" "$driver_symbol" "$core_symbol" "$channel_a" "$channel_b" >> run.env
printf 'bus=i2c\ni2c_client=%s\ni2c_adapter_nr=%s\ni2c_address=%s\n' "$client" "$adapter" "$address" >> run.env
printf 'group_count=%s\nowner=%s\ncontrol=%s\n' "$count" "$owner" "$control" >> run.env
sha256sum "$payload"/* > guest-payload.sha256
echo 0 > "$trace/tracing_on"
echo nop > "$trace/current_tracer"
echo global > "$trace/trace_clock"
grep -q '\[global\]' "$trace/trace_clock"
echo 'trace_clock=global' >> run.env
echo 8192 > "$trace/buffer_size_kb"
echo 0 > "$trace/events/enable"
printf '%s\n' "p:hw_window/driver_enter $driver_target" "r:hw_window/driver_exit $driver_target" \
    "p:hw_window/board_enter $board:board_xfer" "r:hw_window/board_exit $board:board_xfer" >> "$trace/kprobe_events"
if [[ -n "$core_symbol" ]]; then
    printf '%s\n' "p:hw_window/core_enter $core_symbol" "r:hw_window/core_exit $core_symbol" >> "$trace/kprobe_events"
fi
for group in regmap i2c hw_window; do
    echo 1 > "$trace/events/$group/enable"
    for f in "$trace/events/$group"/*/format; do printf '\nEVENT %s\n' "$f"; cat "$f"; done
done > formats.txt
echo > "$trace/trace"
echo 1 > "$trace/tracing_on"
rc=0
"$payload/read-pair" "$device" "$mode" "$params" "$channel_a" "$channel_b" "$selector" > ops.tsv || rc=$?
echo 0 > "$trace/tracing_on"
printf 'reader_exit=%s\n' "$rc" >> run.env
cat "$trace/trace" > trace.txt
for file in "$trace"/per_cpu/cpu*/stats; do echo "$file"; cat "$file"; done > stats.txt
cat "$trace/kprobe_profile" > probes.txt
echo 0 > "$trace/events/enable"
for f in "$trace/events/hw_window"/*/format; do
    probe=$(basename "$(dirname "$f")")
    echo "-:hw_window/$probe" >> "$trace/kprobe_events"
done
echo "$client" > "$sensor/driver/unbind"
test ! -e "$device/name"
rmmod "$board"
test ! -d "/sys/module/$board"
if [[ -f "$payload/driver.ko" ]]; then
    rmmod "$driver_module"; test ! -d "/sys/module/$driver_module"
fi
for (( i=${#deps[@]}-1; i>=0; i-- )); do rmmod "$(modinfo -F name "${deps[i]}")"; done
echo 'cleaned=1' >> run.env
files=(ops.tsv trace.txt run.env formats.txt stats.txt probes.txt kernel.notes board.notes guest-payload.sha256)
if [[ -f driver.notes ]]; then files+=(driver.notes); fi
if [[ -f control.txt ]]; then files+=(control.txt); fi
sha256sum -- "${files[@]}" > capture.sha256
echo "CAPTURE $(sha256sum capture.sha256)"
cd /
umount "$result"
exit "$rc"

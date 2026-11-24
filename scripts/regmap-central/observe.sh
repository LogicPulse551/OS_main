#!/bin/bash
set -euo pipefail
trap 'echo "GUEST_FAILURE line=$LINENO status=$?"' ERR
cd /run/iio
trace=/sys/kernel/tracing
module=/sys/module/regmap_central
notes() {
    od -An -v -tx1 "$1" | tr -d ' \n'
}
test "$(cat /sys/block/vda/ro)" = 1
if [[ -r /proc/sys/kernel/random/boot_id ]]; then
    boot_id=$(cat /proc/sys/kernel/random/boot_id)
    echo BOOT_ID_SOURCE kernel
else
    raw=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    test "${#raw}" = 32
    boot_id="${raw:0:8}-${raw:8:4}-${raw:12:4}-${raw:16:4}-${raw:20:12}"
    echo BOOT_ID_SOURCE guest_random
fi
echo "CENTRAL_BOOT $boot_id readonly=1"
echo "GUEST_RELEASE $(uname -r)"
echo "KERNELNOTES $(notes /sys/kernel/notes)"
selected=()
read -ra args < /proc/cmdline
for arg in "${args[@]}"; do
    case "$arg" in central.case=*) selected+=("${arg#central.case=}") ;; esac
done
test "${#selected[@]}" = 1
case "${selected[0]}" in
    ABA|ABCA) route=${selected[0]}; wrong=0 ;;
    WRONG) route=ABCA; wrong=1 ;;
    *) echo "UNKNOWN_CASE ${selected[0]}"; exit 2 ;;
esac
echo "CASE_BEGIN ${selected[0]}"
echo "MODULE_SHA256 $(sha256sum regmap_central.ko | cut -d' ' -f1)"
test ! -d "$module"
mountpoint -q "$trace" || mount -t tracefs tracefs "$trace"
echo 0 > "$trace/tracing_on"
echo global > "$trace/trace_clock"
echo 0 > "$trace/events/enable"
echo 'prev_comm ~ "regactor/*" || next_comm ~ "regactor/*"' > "$trace/events/sched/sched_switch/filter"
echo 'comm ~ "regactor/*"' > "$trace/events/sched/sched_waking/filter"
echo 'comm ~ "regactor/*"' > "$trace/events/sched/sched_wakeup/filter"
for event in regmap/regmap_reg_read regmap/regmap_reg_write sched/sched_switch sched/sched_waking sched/sched_wakeup; do
    echo 1 > "$trace/events/$event/enable"
done
echo > "$trace/trace"
dmesg -C
echo 1 > "$trace/tracing_on"
load=0
insmod ./regmap_central.ko route="$route" wrong_grant="$wrong" || load=$?
echo "LOAD_EXIT $load"
status=$load
if [[ -d $module ]]; then
    if [[ -r $module/notes/.note.gnu.build-id ]]; then
        echo "MODNOTES $(notes "$module/notes/.note.gnu.build-id")"
    else
        echo "MISSING_MODNOTES"
        status=1
    fi
    if [[ -r $module/parameters/route && -r $module/parameters/wrong_grant ]]; then
        actual_route=$(cat "$module/parameters/route")
        actual_wrong=$(cat "$module/parameters/wrong_grant")
        case "$actual_wrong" in Y) actual_wrong=1 ;; N) actual_wrong=0 ;; esac
        echo "PARAMS $actual_route $actual_wrong"
        if [[ $actual_route != "$route" || $actual_wrong != "$wrong" ]]; then status=1; fi
    else
        echo "MISSING_PARAMS"
        status=1
    fi
    unload=0
    rmmod regmap_central || unload=$?
    echo "UNLOAD_EXIT $unload"
    if ((unload != 0)); then status=$unload; fi
elif ((load == 0)); then
    echo "UNLOAD_NOT_ATTEMPTED absent"
    status=1
else
    echo "UNLOAD_NOT_ATTEMPTED absent"
fi
echo 0 > "$trace/tracing_on"
if [[ -d $module ]] || grep -q '^regmap_central ' /proc/modules; then
    echo "MODULE_ABSENT 0"
    status=1
else
    echo "MODULE_ABSENT 1"
fi
echo DMESG_BEGIN
dmesg --color=never
echo DMESG_END
echo TRACE_BEGIN
awk '/regmap_reg_(read|write):[[:space:]]+regmap_actors[[:space:]]/ || (/sched_(switch|waking|wakeup):/ && /regactor\//)' "$trace/trace"
echo TRACE_END
for file in "$trace"/per_cpu/cpu*/stats; do
    cpu=${file%/stats}
    if ! awk -v cpu="${cpu##*/cpu}" '/^(overrun|commit overrun|dropped events):/ {
        print "BUFFER cpu=" cpu, $0; n++; if ($NF != 0) bad=1
    } END {exit (n!=3 || bad)}' "$file"; then status=1; fi
done
echo 0 > "$trace/events/enable"
echo "CASE_END $status"
exit "$status"

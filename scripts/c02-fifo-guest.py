#!/usr/bin/env python3
"""Run an ordered batch of private FIFO modules on the disposable performance guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

import guest as common  # Uploaded alongside this runner by the existing C02 guest lifecycle.

ROOT = Path(__file__).resolve().parent
MODULE = "kconc_fifo"
LIVE = Path("/sys/module") / MODULE
MASK = 2**32 - 1
SPACE = (1, 8, 31, 64, 7, 32, 63, 16)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def quiet():
    state = common.observers()
    state["events"] = (common.TRACE / "events/enable").read_text().strip()
    require(state["tracing_on"] == "0" and state["tracer"] == "nop" and not state["perf_pids"]
            and state["events"] == "0" and state["kprobe_events"] is not None
            and not state["kprobe_events"].strip(), repr(state))
    return state


def reference(calls):
    cursor = MASK - 17
    total = offsets = 0
    for i in range(calls):
        offset = cursor % 4096
        n = min(4096 - offset, SPACE[i % 8])
        cursor = (cursor + n) & MASK
        offsets += offset
        total += n
    return total, offsets, cursor


def live_build_id():
    note = (LIVE / "notes/.note.gnu.build-id").read_bytes()
    ns, ds, kind = struct.unpack_from("<III", note)
    require(kind == 3 and note[12:12+ns] == b"GNU\0", "invalid module note")
    offset = 12 + ((ns + 3) & ~3)
    return note[offset:offset+ds].hex()


def run_slot(slot, identity, record):
    ko = ROOT / (slot["variant"] + ".ko")
    record["sha256"] = hashlib.sha256(ko.read_bytes()).hexdigest()
    require(record["sha256"] == identity["ko_sha256"], "module file hash mismatch")
    require(not LIVE.exists(), "previous FIFO module still loaded")
    local = slot.get("local_only", False)
    n = slot["calls"]
    try:
        record["insert"] = common.command(["taskset", "-c", "2", "insmod", str(ko),
                                           f"calls={n}", f"local_only={int(local)}"])
        require(record["insert"]["exit_code"] == 0 and LIVE.exists(), "module init or functional check failed")
        record["loaded_build_id"] = live_build_id()
        require(record["loaded_build_id"] == identity["build_id"], "unexpected loaded module")
        values = {p.name:p.read_text().strip() for p in (LIVE / "parameters").iterdir()}
        record["parameters"] = values
        total, offsets, cursor = reference(n)
        for name, expected in dict(compiled_variant=identity["number"], calls=n, cpu_start=2, cpu_end=2,
                                   transferred=total, offset_sum=offsets if local else 0,
                                   out_end=cursor, in_end=(cursor+4096)&MASK).items():
            require(int(values[name]) == expected, f"{name}: {values[name]} vs {expected}")
        require(values["local_only"].lower() == ("y" if local else "n"), "mode mismatch")
        elapsed = int(values["elapsed_ns"])
        require(elapsed > 0, "empty clock interval")
    finally:
        if LIVE.exists():
            record["remove"] = common.command(["rmmod", MODULE])
            require(record["remove"]["exit_code"] == 0 and not LIVE.exists(), "module cleanup failed")
    return dict(slot, elapsed_ns=elapsed)


def main():
    plan = json.loads((ROOT / "fifo-plan.json").read_text())
    report = dict(passed=False, slots=[], rows=[])
    try:
        require(os.geteuid() == 0, "disposable guest root required")
        report["quiet_before"] = quiet()
        before = common.command(["dmesg", "--color=never"])
        require(before["exit_code"] == 0, "unable to read kernel log")
        report["log_before_sha256"] = hashlib.sha256(before["stdout"].encode()).hexdigest()
        for slot in plan["slots"]:
            record = dict(slot=slot, passed=False)
            report["slots"].append(record)
            row = run_slot(slot, plan["variants"][slot["variant"]], record)
            record["passed"] = True
            report["rows"].append(row)
        report["quiet_after"] = quiet()
        after = common.command(["dmesg", "--color=never"])
        require(after["exit_code"] == 0 and after["stdout"].startswith(before["stdout"]), "kernel log unavailable")
        report["kernel_log_delta"] = after["stdout"][len(before["stdout"]):]
        require(not re.search(r"WARNING:|BUG:|Oops:|general protection fault|kernel panic|Call Trace:",
                              report["kernel_log_delta"], re.I), "kernel diagnostics during batch")
        report["passed"] = True
    except Exception as exc:
        report["error"] = repr(exc)
        report["failure_dmesg"] = common.command(["dmesg", "--color=never"])
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Collect one pinned, synchronous BMA400 operation after the guest has booted."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

DEBUG = Path("/sys/kernel/debug/kconc-bma400-perf")


def load_script(filename, module_name):
    spec = importlib.util.spec_from_file_location(module_name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect(action, report):
    common = load_script("c02-bench-guest.py", "c02_common")
    bulk = load_script("c02-bulk-guest.py", "c02_bulk")
    if action == "prepare":
        report.update(common.prepare())
        report.update(boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      os_release=Path("/etc/os-release").read_text(),
                      root_mount=next(row for row in Path("/proc/self/mountinfo").read_text().splitlines()
                                      if row.split()[4] == "/"),
                      vda2=Path("/sys/class/block/vda2/dev").read_text().strip())
        bulk.require((DEBUG/"run").exists() and not (DEBUG.parent/"kconc-c06-observer").exists(),
                     "wrong functional / timing build")
        return
    bulk.require(os.sched_getaffinity(0) == {2}, "pin this writer to guest CPU 2")
    report["observers_before"] = bulk.observers(common)
    bulk.require(bulk.quiet(report["observers_before"]), "observers active before measurement")
    before = common.command(["dmesg", "--color=never"])
    report["dmesg_before"] = before
    created = []
    mode = "check" if action == "check" else "bench"
    try:
        if action == "profile":
            bulk.PROBES["r03bulk"] = "kconc_bma400_bulk_read"
            bulk.enable_probes(report, created)
        (DEBUG/"run").write_text(mode + "\n")
        report["results_raw"] = (DEBUG/"results").read_text()
        report["results"] = json.loads(report["results_raw"])
        if action == "profile":
            (bulk.TRACE/"tracing_on").write_text("0")
            report["writer_pid"] = os.getpid()
            # C02 identifies the task that called into the kernel by this key.
            report["insertion"] = {"pid": os.getpid()}
            try:
                bulk.read_trace(report)
            finally:
                report.pop("insertion")
        params = (20000,2,4) if action == "time" else (16,0,1)
        bulk.validate(report["results"], mode, *params)
    finally:
        if action == "profile":
            (bulk.TRACE/"tracing_on").write_text("0")
            for name in reversed(created):
                (bulk.TRACE/"events/c02r03"/name/"enable").write_text("0")
                bulk.change_event("-:c02r03/" + name)
        report["observers_after"] = bulk.observers(common)
        bulk.require(bulk.quiet(report["observers_after"]), "observers still active")
        after = common.command(["dmesg", "--color=never"])
        report["dmesg_after"] = after
        bulk.require(before["exit_code"] == after["exit_code"] == 0 and after["stdout"].startswith(before["stdout"]),
                     "kernel log missing or truncated")
        report["kernel_warnings"] = [l for l in after["stdout"][len(before["stdout"]):].splitlines()
                                     if re.search(r"WARNING: CPU:|BUG:|Oops:|Kernel panic|general protection fault", l)]
        bulk.require(not report["kernel_warnings"], "kernel diagnostic during fixture operation")
        entries = [p.name for p in (DEBUG.parent/"regmap").glob("*")]
        report["final_regmap_entries"] = entries
        bulk.require("dummy-c02-bulk" not in entries and os.sched_getaffinity(0) == {2}, "incomplete fixture cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check", "profile", "time"))
    args = parser.parse_args()
    result = {"action": args.action, "passed": False}
    try:
        collect(args.action, result)
        result["passed"] = True
    except Exception as error:
        result["error"] = repr(error)
    print(json.dumps(result))
    return int(not result["passed"])


if __name__ == "__main__":
    sys.exit(main())

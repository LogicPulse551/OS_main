"""Place the four QEMU vCPU threads before booting the private two-worker fixture."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from .cli import now, save


HOST_CPUS = (2, 4, 6, 8)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("QEMU time budget expired")
    return seconds


class Monitor:
    def __init__(self, channel, stream, deadline, record):
        self.channel = channel
        self.stream = stream
        self.deadline = deadline
        self.record = record

    def receive(self):
        self.channel.settimeout(remaining(self.deadline))
        line = self.stream.readline(262145)
        require(line.endswith(b"\n") and len(line) <= 262144, "Missing or oversized QMP message")
        return json.loads(line)

    def request(self, command):
        self.channel.settimeout(remaining(self.deadline))
        self.channel.sendall(json.dumps({"execute": command, "id": command}).encode() + b"\n")
        while True:
            msg = self.receive()
            if "event" in msg:
                self.record["events"].append(msg)
                continue
            require(msg.get("id") == command and "return" in msg, f"QMP {command} failed: {msg}")
            self.record["commands"].append({"command": command, "utc": now(), "result": msg["return"]})
            return msg["return"]


def pin_threads(pid, cpus, record):
    allowed = set(os.sched_getaffinity(0))
    helpers = allowed.difference(HOST_CPUS)
    require(set(HOST_CPUS) <= allowed and helpers, "Host lacks the four registered CPUs and a helper CPU")
    record["host_allowed"] = sorted(allowed)
    topology = {}
    for cpu in sorted(allowed):
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        topology[cpu] = {key: (base/key).read_text().strip() for key in
                         ("physical_package_id", "core_id", "thread_siblings_list")}
    record["host_topology"] = topology
    require(len({(topology[c]["physical_package_id"], topology[c]["core_id"]) for c in HOST_CPUS}) == 4,
            "Registered host CPUs do not belong to four distinct reported cores")
    by_index = {cpu["cpu-index"]: cpu["thread-id"] for cpu in cpus}
    require(len(cpus) == len(set(by_index.values())) == 4 and set(by_index) == set(range(4)),
            "Expected four independent QEMU vCPU threads")
    vcpus = {tid: index for index, tid in by_index.items()}
    tasks = Path(f"/proc/{pid}/task")
    listed = {int(p.name) for p in tasks.iterdir()}
    record["task_ids_before"] = sorted(listed)
    require(set(vcpus) <= listed and pid not in vcpus, "QMP named a thread outside the QEMU vCPU set")
    receipts = record["threads"]
    # Place the main thread first so new helpers it creates inherit the helper mask.
    for tid in [pid, *sorted(listed - {pid})]:
        index = vcpus.get(tid)
        target = {HOST_CPUS[index]} if index is not None else helpers
        before = sorted(os.sched_getaffinity(tid))
        name = (tasks/str(tid)/"comm").read_text().strip()
        os.sched_setaffinity(tid, target)
        after = os.sched_getaffinity(tid)
        receipts.append({"tid": tid, "comm": name, "vcpu": index, "before": before, "after": sorted(after)})
        require(after == target, f"Affinity readback failed for QEMU thread {tid}")
    record["task_ids_after"] = sorted(int(p.name) for p in tasks.iterdir())
    require(record["task_ids_after"] == record["task_ids_before"], "QEMU thread set changed during placement")


def check_receipt(record):
    """Validate a completed placement receipt before it can be used as a reference."""
    try:
        require(record["exit"] == record["child_returncode"] == 0 and record["resumed"] is True
                and not record.get("error"), "Host placement did not complete")
        commands = record["commands"]
        require([c["command"] for c in commands] ==
                ["qmp_capabilities", "query-status", "query-cpus-fast", "cont", "query-status"],
                "Incomplete placement monitor commands")
        paused = commands[1]["result"]
        require(paused["running"] is False and paused["status"] in ("prelaunch", "paused")
                and commands[3]["result"] == {} and commands[4]["result"]["running"] is True,
                "Missing QEMU pause or resume receipt")
        times = [record["started_utc"], *(c["utc"] for c in commands[:3]), record["placement_verified_utc"],
                 *(c["utc"] for c in commands[3:]), record["finished_utc"]]
        require(times == sorted(times), "Placement receipts out of order")
        cores = {int(i): (v["physical_package_id"], v["core_id"]) for i,v in record["host_topology"].items()}
        allowed = set(record["host_allowed"])
        helpers = sorted(allowed.difference(HOST_CPUS))
        require(set(cores) == allowed and helpers and len({cores[i] for i in HOST_CPUS}) == 4,
                "Placement topology does not match the required CPUs")
        vcpus = commands[2]["result"]
        tids = {c["thread-id"]: c["cpu-index"] for c in vcpus}
        require(len(vcpus) == len(tids) == 4 and set(tids.values()) == set(range(4)), "Invalid QMP vCPU map")
        rows = record["threads"]
        observed = sorted(r["tid"] for r in rows)
        require(len(observed) == len(set(observed)) and record["task_ids_before"] == record["task_ids_after"] ==
                observed and set(tids) <= set(observed) and record["pid"] in observed and record["pid"] not in tids,
                "Incomplete QEMU task membership")
        for row in rows:
            index = tids.get(row["tid"])
            require(row["vcpu"] == index and row["after"] == (helpers if index is None else [HOST_CPUS[index]]),
                    "Placement receipt differs from registered vCPU or helper affinity")
    except (TypeError, KeyError, IndexError, AttributeError) as exc:
        raise ValueError("Malformed host placement receipt") from exc


def run_pinned(argv, log, out, timeout):
    path = out/"host-placement.json"
    require(not path.exists(), "Placement receipt already exists")
    deadline = time.monotonic() + timeout
    proc = None
    record = {"started_utc": now(), "argv": argv, "commands": [], "events": [], "threads": [],
              "resumed": False}
    code = 125
    try:
        require("-S" in argv and argv.count("-qmp") == 1 and argv[argv.index("-qmp")+1] == "stdio",
                "Placement requires paused startup and a private stdio monitor")
        parent, child = socket.socketpair()
        with parent:
            with child:
                proc = subprocess.Popen(argv, stdin=child, stdout=child, stderr=log)
            record["pid"] = proc.pid
            with parent.makefile("rb") as stream:
                monitor = Monitor(parent, stream, deadline, record)
                record["greeting"] = monitor.receive()
                require("QMP" in record["greeting"], "Missing QMP greeting")
                monitor.request("qmp_capabilities")
                paused = monitor.request("query-status")
                require(paused["running"] is False and paused["status"] in ("prelaunch", "paused"),
                        "Guest started before placement")
                pin_threads(proc.pid, monitor.request("query-cpus-fast"), record)
                record["placement_verified_utc"] = now()
                save(path, record)
                monitor.request("cont")
                record["resumed"] = True
                require(monitor.request("query-status")["running"] is True, "QEMU did not resume")
                save(path, record)
                code = proc.wait(timeout=remaining(deadline))
    except (TimeoutError, subprocess.TimeoutExpired) as exc:
        record["error"] = str(exc)
        code = 124
    except (OSError, ValueError, IndexError, KeyError, TypeError) as exc:
        record["error"] = str(exc)
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        record.update(exit=code, finished_utc=now(), child_returncode=proc.returncode if proc else None)
        save(path, record)
    return code

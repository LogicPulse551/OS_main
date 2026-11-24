"""Learn and compare complete normal IIO reads using passive, build-bound traces."""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid


SCHEMA = "kconc.iio-read-path.v1"
THREE_AXIS_SCHEMA = "kconc.iio-three-read-path.v1"
IDENTITY = ("kernel_build_id", "kernel_sha256", "vmlinux_sha256", "config_sha256",
            "board_sha256", "board_build_id", "initrd_sha256")
WIDTH = {0: 2, 1: 1, 2: 1, 3: 5, 4: 1, 5: 1, 15: 1}
FTRACE = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*\d+\]\s+.*?\d+\.\d+:\s+(\w+):\s*(.*)")
MARKER = re.compile(r"IIO_(BEGIN|END) key=([A-Za-z0-9_-]+) axis=([XYZ])(?: rc=(-?\d+) value=(-?\d+))?$")
# Location and transfer shape are public regmap event fields. Payload values,
# timestamps, dynamic addresses and command-line labels do not classify a read.
FIELDS = re.compile(r"\b(reg|register|count|len|length|bytes|nregs)=((?:0x)?[a-fA-F0-9]+)\b")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_json(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def identity(meta):
    result = {name: meta[name] for name in IDENTITY}
    for name, value in result.items():
        size = 40 if name.endswith("build_id") else 64
        require(isinstance(value, str) and re.fullmatch(f"[a-f0-9]{{{size}}}", value),
                f"invalid {name}")
    return result


@dataclass
class Read:
    key: str
    axis: str
    tid: int
    size: int
    error: int
    value: int
    count: int
    begin: int = -1
    end: int = -1
    pcs: list = field(default_factory=list)
    regmap: list = field(default_factory=list)
    driver: list = field(default_factory=list)

    def path(self):
        return {"driver": self.driver, "regmap": self.regmap}

    def returned(self):
        return [self.error, self.size, self.value]


def entry_pcs(blob, count):
    require(0 < count < 131072 - 5 and len(blob) == 8 * count, "KCOV length mismatch")
    words = struct.unpack(f"<{count}Q", blob)
    pcs = []
    i = 0
    while i < count:
        word = words[i]
        kind = word >> 60
        width = WIDTH.get(kind)
        require(width is not None and i + width <= count, "malformed KCOV record")
        require(kind not in (4, 5), "passive trace contains scheduler control")
        if kind == 0:
            pcs.append(hex((word & 0x00ffffffffffffff) | 0xff00000000000000))
        i += width
    require(pcs, "no function entries in passive KCOV")
    return pcs


def attach_trace(trace, reads):
    active = {}
    for line_no, line in enumerate(trace.splitlines(), 1):
        capacity = re.search(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)", line)
        if capacity:
            require(capacity[1] == capacity[2], "overwritten trace buffer")
        require("LOST EVENTS" not in line.upper(), "lost ftrace records")
        row = FTRACE.search(line)
        if not row:
            require("IIO_BEGIN" not in line and "IIO_END" not in line, "unparsed operation marker")
            continue
        tid, event, payload = int(row[1]), row[2], row[3].strip()
        if event in ("tracing_mark_write", "trace_marker") and payload.startswith("IIO_"):
            marker = MARKER.fullmatch(payload)
            require(marker is not None, "malformed operation marker")
            boundary, key, axis, rc, value = marker.groups()
            op = reads.get(key)
            require(op is not None and op.tid == tid and op.axis == axis, "marker/table mismatch")
            if boundary == "BEGIN":
                require(tid not in active and op.begin < 0 and rc is None, "duplicate operation begin")
                active[tid] = op
                op.begin = line_no
            else:
                require(active.get(tid) is op and rc is not None, "unpaired operation end")
                require((int(rc), int(value)) == (-op.error, op.value), "return evidence mismatch")
                op.end = line_no
                del active[tid]
        elif event.startswith("regmap_") and tid in active:
            active[tid].regmap.append([event, dict(FIELDS.findall(payload))])
    require(not active and all(0 < op.begin < op.end for op in reads.values()), "unclosed reads")


def load_capture(slot):
    meta = read_json(slot / "build.json")
    identity(meta)
    uuid.UUID(meta["boot_id"])
    require(read_json(slot / "capture-result.json").get("passed") is True, "capture failed")
    reads = {}
    inputs = ["ops.tsv", "trace.txt", "build.json", "stats.txt"]
    for line in (slot / "ops.tsv").read_text().splitlines():
        key, axis, *numbers = line.split("\t")
        require(re.fullmatch(r"[A-Za-z0-9_-]+", key) and axis in ("X", "Y", "Z")
                and key not in reads and len(numbers) == 5, "invalid operation table")
        op = Read(key, axis, *(int(n) for n in numbers))
        require(op.tid > 0 and op.size > 0 and op.error == 0, "normal sysfs read did not complete")
        filename = key + ".words"
        inputs.append(filename)
        op.pcs = entry_pcs((slot / filename).read_bytes(), op.count)
        reads[key] = op
    require(reads, "empty operation table")
    stats = (slot / "stats.txt").read_text()
    dropped = re.findall(r"^(?:overrun|commit overrun|dropped events):\s*(\d+)", stats, re.M)
    require(dropped and all(int(value) == 0 for value in dropped), "missing stats or dropped events")
    attach_trace((slot / "trace.txt").read_text(errors="replace"), reads)
    return meta, reads, {name: sha_file(slot / name) for name in inputs}


def linux_command(argv, text=None):
    command = (["wsl.exe", "-d", "Debian", "--exec"] if os.name == "nt" else []) + argv
    return subprocess.run(command, input=text, capture_output=True, check=True,
                          encoding="utf-8", errors="replace").stdout


def make_symbols(meta, pcs):
    """Map all observed entry IPs, including those outside IIO, with one DWARF lookup."""
    elf = meta["vmlinux"]
    require(linux_command(["sha256sum", "--", elf]).split()[0] == meta["vmlinux_sha256"],
            "symbol image digest mismatch")
    pc_list = sorted(pcs)
    text = linux_command(["addr2line", "-a", "-f", "-i", "-e", elf], "\n".join(pc_list) + "\n")
    records = {}
    address = None
    for line in text.splitlines():
        if re.fullmatch(r"0x[0-9a-fA-F]+", line):
            address = hex(int(line, 16))
            records[address] = []
        else:
            require(address is not None, "invalid addr2line output")
            records[address].append(line.strip())
    require(set(records) == set(pcs), "incomplete DWARF lookup")
    result = {}
    for address, fields in records.items():
        require(len(fields) % 2 == 0, "incomplete inline frames")
        tokens = []
        for function, location in zip(fields[::2], fields[1::2]):
            # Source ownership is assigned by kernel subsystem, before observing any axes.
            owned = re.search(r"(?:^|/)(drivers/iio/[^/:]+/(?:[^:]+?)\.c):", location)
            if owned:
                token = owned[1] + "::" + function
                if token not in tokens:
                    tokens.append(token)
        result[address] = tokens
    return result


def project(meta, reads, known=None):
    known = dict(known or {})
    pcs = set(pc for op in reads.values() for pc in op.pcs)
    missing = pcs.difference(known)
    if missing:
        known.update(make_symbols(meta, missing))
    for op in reads.values():
        op.driver = [token for pc in op.pcs for token in known[pc]]
    return known


def train(meta, reads, hashes, symbols):
    signatures, returns, counts = {}, {}, {}
    axes = "XYZ" if meta.get("mode") == "train3" else "XY"
    require({op.axis for op in reads.values()} == set(axes), "missing or unexpected training axis")
    for axis in axes:
        rows = [op for op in reads.values() if op.axis == axis]
        require(len(rows) >= 2, f"need repeated training reads for {axis}")
        counts[axis] = len(rows)
        signature = rows[0].path()
        require(signature["driver"], "training has no driver-owned IIO entry")
        require(signature["regmap"], "training has no regmap observations")
        require(all(op.path() == signature for op in rows), f"unstable {axis} training path")
        signatures[axis] = signature
        returns[axis] = sorted(set(tuple(op.returned()) for op in rows))
    require(len({digest_json(s["regmap"]) for s in signatures.values()}) == len(axes),
            "public regmap transcript does not distinguish every axis")
    drivers = [s["driver"] for s in signatures.values()]
    return {"schema": THREE_AXIS_SCHEMA if axes == "XYZ" else SCHEMA,
            "identity": identity(meta), "training_boot_id": meta["boot_id"],
            "training_raw_sha256": hashes, "training_counts": counts, "signature": signatures,
            "returned": {axis: [list(row) for row in values] for axis, values in returns.items()},
            "driver_path_distinguishes_axes": len(set(map(tuple, drivers))) == len(axes),
            "common_driver_functions": sorted(set.intersection(*map(set, drivers))),
            "symbols": symbols}


def compare(reference, pair, order):
    axes = set(reference["signature"])
    require(axes in (set("XY"), set("XYZ")) and set(order) == axes
            and len(order) == len(pair) == len(axes), "order differs from registered axes")
    reasons, details = [], []
    for op, axis in zip(pair, order):
        matches = [kind for kind, sig in reference["signature"].items() if op.path() == sig]
        if matches != [axis]:
            reasons.append(f"{op.key}: intermediate path differs from {axis}")
        if op.axis != axis or op.returned() not in reference["returned"][axis]:
            reasons.append(f"{op.key}: operation or result mismatch")
        details.append({"key": op.key, "expected": axis, "identified_by_path": matches,
                        "tid": op.tid, "begin_line": op.begin, "end_line": op.end,
                        "returned": op.returned(), "path": op.path()})
    if any(left.end >= right.begin for left, right in zip(pair, pair[1:])):
        reasons.append("complete read ordering differs")
    if len(pair) == 3 and len({op.tid for op in pair}) != 3:
        reasons.append("three independently identified readers are required")
    return {"passed": not reasons, "reasons": reasons, "observations": details}


def negative_checks(reference, pair, order):
    require(compare(reference, pair, order)["passed"], "untampered pair did not match")
    changed = deepcopy(pair)
    a, b = ((order.index("Y"), order.index("Z")) if len(order) == 3 else (0, 1))
    changed[a].regmap, changed[b].regmap = changed[b].regmap, changed[a].regmap
    swapped = compare(reference, changed, order)
    changed = deepcopy(pair)
    stream = changed[0].regmap
    for j in range(1, len(stream)):
        if stream[j] != stream[j - 1]:
            stream[j], stream[j - 1] = stream[j - 1], stream[j]
            break
    else:
        raise ValueError("no distinct adjacent intermediate events for order control")
    reordered = compare(reference, changed, order)
    return {"passed": not swapped["passed"] and not reordered["passed"],
            "scope": "offline copies of projected middle events; original delivery, endpoints and labels retained",
            "exchanged_regmap_paths": swapped, "reversed_adjacent_regmap_events": reordered}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kconc iio")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("discover", "verify", "negative"):
        command = sub.add_parser(name)
        command.add_argument("--capture", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name != "discover":
            command.add_argument("--reference", type=Path, required=True)
            command.add_argument("--order", choices=("XY", "YX", "XYZ", "XZY", "YXZ", "YZX", "ZXY", "ZYX"), required=True)
            command.add_argument("--keys", nargs="+", required=True)
    args = parser.parse_args(argv)
    try:
        meta, reads, hashes = load_capture(args.capture)
        if args.command == "discover":
            require(meta.get("mode") in ("train", "train3"), "discovery requires a training capture")
            symbols = project(meta, reads)
            result = train(meta, reads, hashes, symbols)
            result["certificate_sha256"] = digest_json(result)
            passed = True
        else:
            reference = read_json(args.reference)
            seal = reference.pop("certificate_sha256")
            schema = THREE_AXIS_SCHEMA if len(args.order) == 3 else SCHEMA
            require(digest_json(reference) == seal and reference["schema"] == schema, "invalid certificate")
            require(reference["identity"] == identity(meta), "capture identity differs from reference")
            require(reference["training_boot_id"] != meta["boot_id"], "same boot as training")
            require(len(args.keys) == len(args.order) == len(set(args.keys)), "expected distinct trial keys for each axis")
            selected = {key: reads[key] for key in args.keys}
            project(meta, selected, reference["symbols"])
            pair = list(selected.values())
            result = (negative_checks if args.command == "negative" else compare)(reference, pair, args.order)
            result.update(order=args.order, boot_id=meta["boot_id"], identity=identity(meta),
                          reference_sha256=seal, capture_raw_sha256=hashes)
            passed = result["passed"]
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {"passed": False, "diagnostic": str(error), "command": args.command}
        passed = False
    try:
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"passed": passed, "record": str(args.out), "diagnostic": result.get("diagnostic")}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

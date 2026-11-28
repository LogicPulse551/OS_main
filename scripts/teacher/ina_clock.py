"""Pair two views of one stopped ftrace global buffer and judge INA219 events in ns."""
import argparse
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
OLD = ROOT / "ina_public.py"
TEXT = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*(\d+)\]\s+\S+\s+(\d+)\.(\d{6}):\s+(\w+):\s*(.*)$")
RAW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(?::\s+(?=(?:0x)?[0-9a-fA-F]+\s+:\s+KCONC_I2C_CTRL\b))?(.*)$")
TYPE = re.compile(r"(?:type:\s*)?(\d+)(?:\s+\?)?")
HEADER = re.compile(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)")


def require(p, message):
    if not p:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Stamp:
    raw_line: int
    ns: int
    tid: int
    cpu: int


def rows(lines, pattern, raw):
    records = []
    for lineno, line in enumerate(lines, 1):
        require("LOST EVENTS" not in line.upper(), f"lost events at line {lineno}")
        if not line.strip() or line.lstrip().startswith("#") and not records:
            continue
        match = pattern.match(line) if raw else pattern.search(line)
        if match is not None:
            records.append([lineno, *match.groups()])
        else:
            require(records, f"unparsed preamble at line {lineno}")
            # A formatted print may contain an embedded newline. Its payload is
            # checked below; a broken event header can never silently disappear.
            records[-1][-1] += "\n" + line
    counts = HEADER.findall("\n".join(lines))
    require(len(counts) == 1 and int(counts[0][0]) == int(counts[0][1]) == len(records),
            f"incomplete {'raw' if raw else 'normal'} buffer ({len(records)} records)")
    return records


def join_views(cap):
    normal_path, raw_path = cap / "trace.txt", cap / "trace-raw.txt"
    seal = {n:h for h,n in (line.split() for line in (cap / "capture.sha256").read_text().splitlines())}
    for path in (normal_path, raw_path, cap / "formats.txt"):
        require(seal.get(path.name) == digest(path), "unsealed or changed " + path.name)
    normal = rows(normal_path.read_text().splitlines(), TEXT, False)
    raw = rows(raw_path.read_text().splitlines(), RAW, True)
    require(len(normal) == len(raw), "views have different event counts")
    known = dict((n,int(i)) for n,i in re.findall(r"^name: (\w+)\nID: (\d+)$", (cap/"formats.txt").read_text(), re.M))
    found, by_id, stamps = {}, {}, {}
    prev = -1
    for shown, original in zip(normal, raw):
        lineno, tid, cpu, sec, usec, name, detail = shown
        raw_line, raw_tid, raw_cpu, timestamp, payload = original
        tid, cpu, ns = int(tid), int(cpu), int(timestamp)
        require((tid,cpu) == (int(raw_tid), int(raw_cpu)), f"TID/CPU mismatch at normal line {lineno}")
        require(prev <= ns and (ns + 500)//1000 == int(sec)*1_000_000 + int(usec),
                f"global order or kernel-rounded timestamp mismatch at normal line {lineno}")
        prev = ns
        type_match = TYPE.fullmatch(payload.strip())
        if type_match is not None:
            type_id = int(type_match[1])
            require(known.get(name, type_id) == type_id and
                    found.setdefault(name,type_id) == type_id and by_id.setdefault(type_id,name) == name,
                    f"event ID mismatch at normal line {lineno}")
            require(name in known or name in ("driver_enter","driver_exit","board_enter","board_exit",
                                             "core_enter","core_exit"), f"unrecognised event {name}")
        else:
            # TRACE_PRINT and TRACE_BPRINT emit the IP, then message text.
            # Validate the complete request/phase/reader payload, even if the
            # raw handler places it on its own line.
            message = re.fullmatch(r"\s*#?\s*(?:0x)?[0-9a-fA-F]+\s*:?\s+(.*?)\s*",payload,re.S)
            if message and message[1].startswith("# "):
                content = message[1][2:]
            else:
                content = message[1] if message else None
            require(name in ("tracing_mark_write","trace_marker","defer_selected_reply") and
                    content is not None and content.strip() == detail.strip(),
                    f"raw message disagrees with {name} at normal line {lineno}: {payload!r}")
        stamps[lineno] = Stamp(raw_line, ns, tid, cpu)
    return stamps, {"rows":len(stamps),"normal_sha256":seal["trace.txt"],"raw_sha256":seal["trace-raw.txt"],
                    "event_ids":found,"display":"(global_ns + 500) // 1000"}


def check(mode, cap, package, owner, rules):
    stamps, transport = join_views(cap)
    spec = importlib.util.spec_from_file_location("ina219_window", OLD)
    judge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(judge)
    # Supply parsed records with their original ns to the unchanged window and
    # receipt rules. The existing judge still verifies guest/driver identity,
    # per-channel outputs, capture seals, and the declared control mode.
    old_read, old_events = judge.hw.read_trace, judge.clock.events

    def timestamp(e):
        stamp = stamps[e.line]
        require(e.tid == stamp.tid, "decoder disagrees on task identity")
        return replace(e,ns=stamp.ns)

    def read_trace(directory, groups):
        return {k:[timestamp(e) for e in v] for k,v in old_read(directory,groups).items()}

    judge.hw = SimpleNamespace(**(vars(judge.hw) | {"read_trace":read_trace}))
    judge.clock = SimpleNamespace(**(vars(judge.clock) | {"events":lambda lines:[timestamp(e) for e in old_events(lines)]}))
    result = judge.check(mode, cap, package, owner, rules)
    result["transport"] = transport
    for h in result["hits"]:
        for e in [*h["events"],h["owner_driver_exit"],h["peer_driver_enter"]]:
            e.update(raw_line=stamps[e["line"]].raw_line,cpu=stamps[e["line"]].cpu)
    if "witness" in result:
        for e in [*result["witness"]["events"],*result["witness"]["ends"]]:
            e.update(raw_line=stamps[e["line"]].raw_line,cpu=stamps[e["line"]].cpu)
    return result

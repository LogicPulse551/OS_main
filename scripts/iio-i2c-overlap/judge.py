"""Judge two ordinary BMA400 reads from one guest's driver and adapter events."""
import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "iio-path"))
from capture import guest_id
from i2c_verify import BUS_SEQUENCE, combined_read, bus_shape


TRACE = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*\d+\]\s+.*?(\d+)\.(\d{1,9}):\s+(\w+):\s*(.*)")
MARKER = re.compile(r"IIO_(BEGIN|END) key=g(\d{3})([xy]) axis=([XY])(?: rc=(-?\d+) value=(-?\d+))?")
PROBES = ("bma_enter", "bma_exit", "board_enter", "board_exit")
ORDER = ("IIO_BEGIN", "bma_enter", "regmap_hw_read_start", "i2c_write", "i2c_read",
         "board_enter", "board_exit", "i2c_reply", "i2c_result", "regmap_hw_read_done",
         "regmap_bulk_read", "bma_exit", "IIO_END")
AXES = {"X": (4, "2301", 291), "Y": (6, "3402", 564)}
BUILD = ("kernel_build_id", "kernel_sha256", "config_sha256", "vmlinux_sha256",
         "board_build_id", "board_sha256", "initrd_sha256")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_json(path):
    return json.loads(path.read_bytes())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class Event:
    line: int
    ns: int
    tid: int
    name: str
    detail: str


def load_meta(capture, package, groups):
    manifest = {}
    for row in (capture / "capture.sha256").read_text().splitlines():
        expected, name = row.split()
        require(bool(re.fullmatch(r"[a-z][a-z0-9.-]*", name)) and name not in manifest,
                "malformed transport manifest")
        require(digest(capture / name) == expected, f"capture digest differs: {name}")
        manifest[name] = expected
    require(set(("trace.txt", "ops.tsv", "kernel.notes", "board.notes", "stats.txt",
                 "probes.txt", "run.env")).issubset(manifest), "incomplete transport evidence")
    seal = digest(capture / "capture.sha256")
    log = (capture / "serial.log").read_text(errors="replace").replace("\r", "")
    require(re.findall(r"^CAPTURE ([a-f0-9]{64})  capture.sha256$", log, re.M) == [seal],
            "serial capture seal differs")
    meta = read_json(capture / "build.json")
    env = dict(row.split("=", 1) for row in (capture / "run.env").read_text().splitlines())
    require(all(meta.get(k) == v for k, v in env.items()), "build and run identities differ")
    require(read_json(capture / "capture-result.json").get("passed") is True, "capture failed")
    require(all((meta[k] == package[k]) for k in BUILD), "capture/package identities differ")
    for kind in ("kernel", "board"):
        require(guest_id(capture / (kind + ".notes")) == meta[kind + "_build_id"],
                f"wrong live {kind} build")
    boot = str(UUID(meta["boot_id"]))
    require(re.findall(r"^BOOT ([0-9a-f-]{36})$", log, re.M) == [boot], "boot ID differs")
    require(env["iio_name"] == env["bound_driver"] == "bma400" and env["bus"] == "i2c",
            "wrong sensor or bus")
    require(env["cleaned"] == "1" and int(env["reader_exit"]) == 0
            and int(env["group_count"]) == groups, "guest read/cleanup/number of groups differs")
    require(env.get("trace_clock") == "global", "uncertified trace clock")
    return meta, manifest


def parse_stats(capture, groups):
    stats = (capture / "stats.txt").read_text()
    blocks = re.split(r"^/sys/kernel/tracing/per_cpu/cpu\d+/stats\s*$", stats, flags=re.M)[1:]
    require(blocks, "missing per-CPU trace stats")
    for block in blocks:
        for key in ("overrun", "commit overrun", "dropped events"):
            require(re.findall(r"^" + key + r":\s*(\d+)\s*$", block, re.M) == ["0"],
                    "missing or nonzero tracing stats: " + key)
    counters = {}
    for line in (capture / "probes.txt").read_text().splitlines():
        fields = line.split()
        if fields and fields[0].split("/")[-1].split(":")[-1] in PROBES:
            probe = fields[0].split("/")[-1].split(":")[-1]
            require(len(fields) == 3 and probe not in counters, "invalid probe counter row")
            counters[probe] = [int(n) for n in fields[1:]]
    require(set(counters) == set(PROBES), "missing probe counters")
    require(all(hits >= groups * 2 and lost == 0 for hits, lost in counters.values()),
            "missing or missed driver/adapter probes")
    return counters


def parse_trace(lines, groups):
    active, ops = {}, {}
    capacity = re.findall(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)", "\n".join(lines))
    require(len(capacity) == 1 and capacity[0][0] == capacity[0][1], "trace overrun or missing header")
    for number, line in enumerate(lines, 1):
        require("LOST EVENTS" not in line.upper(), "lost events")
        row = TRACE.search(line)
        if not row:
            require("IIO_BEGIN" not in line and "IIO_END" not in line, "unparsed operation marker")
            continue
        tid, seconds, fraction, name, payload = row.groups()
        tid = int(tid)
        event = Event(number, int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0")),
                      tid, name, payload)
        if name in ("trace_marker", "tracing_mark_write") and payload.startswith("IIO_"):
            m = MARKER.fullmatch(payload)
            require(m is not None, "malformed operation boundary")
            edge, group, suffix, axis, rc, value = m.groups()
            key = (int(group), axis)
            require(axis == suffix.upper() and 1 <= key[0] <= groups, "incorrect group or axis")
            event = replace(event, name="IIO_" + edge)
            if edge == "BEGIN":
                require(rc is None and key not in ops and tid not in active, "duplicate read")
                active[tid] = key
                ops[key] = [event]
            else:
                require(active.pop(tid, None) == key and int(rc) == 0 and int(value) == AXES[axis][2],
                        "mismatched or invalid read return")
                ops[key].append(event)
        elif tid in active and (name.startswith(("regmap_", "i2c_")) or name in PROBES):
            ops[active[tid]].append(event)
    require(not active and len(ops) == 2 * groups, "incomplete read pair")
    return ops


def check_operation(events, axis, row, meta):
    require(tuple(e.name for e in events) == ORDER, "incorrect event sequence: " + ",".join(e.name for e in events))
    require(all(a.ns <= b.ns for a,b in zip(events, events[1:])), "backwards per-thread timestamp")
    event = {e.name:e for e in events}
    for probe in ("bma_enter", "bma_exit"):
        require(re.search(r"\bbma400_read_raw\b", event[probe].detail), "wrong native driver probe")
    for probe in ("board_enter", "board_exit"):
        require(re.search(r"\bboard_xfer\b", event[probe].detail), "wrong software adapter probe")
    selector, reply, value = AXES[axis]
    require(row[1] == axis and [int(i) for i in row[2:]] ==
            [events[0].tid, len(str(value)) + 1, 0, value], "reader table versus actual call differs")
    bus = combined_read([(e.line,e.name,e.detail) for e in events if e.name in BUS_SEQUENCE], value)
    shape = bus_shape(bus, meta)
    require(shape["register"] == selector and bus["reply_hex"] == reply, "incorrect selector/bytes")
    return event


def window(owner, peer):
    times = (owner["i2c_read"], owner["board_enter"], peer["bma_enter"],
             owner["board_exit"], owner["i2c_reply"])
    if not all(a.ns < b.ns and a.line < b.line for a, b in zip(times, times[1:])):
        return None
    require(peer["i2c_write"].line > owner["i2c_result"].line
            and peer["bma_exit"].line > owner["board_exit"].line, "unexpected peer transaction while first read pending")
    return list(times)


def control(capture, meta, manifest, owner):
    rows = {}
    if not owner:
        require(meta.get("control") == "none" and "control.txt" not in manifest, "active control in passive capture")
        return None
    require(meta.get("control") == "adapter" and meta.get("owner") == owner and "control.txt" in manifest,
            "missing frozen adapter control")
    for row in (capture / "control.txt").read_text().splitlines():
        phase, *tokens = row.split()
        require(phase not in rows, "repeated controller receipt")
        rows[phase] = dict(token.split("=", 1) for token in tokens)
    require(list(rows)==["before","armed","seen","after"], "incomplete controller receipt")
    require([x["phase"] for x in rows.values()] == ["idle","armed","pending","done"],
            "adapter phases out of order")
    seen, after = rows["seen"], rows["after"]
    for key in ("seq","reg","tid","start_ns","delay_ms"):
        require(seen[key] == after[key], "different adapter transaction in " + key)
    require(int(seen["seq"]) == 1 and int(seen["reg"]) == AXES[owner][0] and int(seen["tid"]) > 0
            and int(seen["end_ns"]) == 0 and int(seen["delay_ms"]) > 0
            and int(after["end_ns"]) > int(seen["start_ns"]) > 0, "incorrect adapter completion")
    return rows


def judge(capture, package, groups, owner=None, negative=False):
    meta, manifest = load_meta(capture, package, groups)
    probes = parse_stats(capture, groups)
    receipts = control(capture, meta, manifest, owner)
    lines = (capture / "trace.txt").read_text().splitlines()
    ops = parse_trace(lines, groups)
    table = {}
    for row in (capture / "ops.tsv").read_text().splitlines():
        cols = row.split()
        require(len(cols)==6 and cols[0] not in table, "bad reader table")
        table[cols[0]] = cols
    require(len(table)==groups*2, "reader count differs")
    hits = []
    last_line = 0
    for i in range(1,groups+1):
        pair = {axis: check_operation(ops[i,axis], axis, table[f"g{i:03d}{axis.lower()}"], meta)
                for axis in AXES}
        require(pair["X"]["IIO_BEGIN"].tid != pair["Y"]["IIO_BEGIN"].tid, "same task for both axes")
        require(min(p["IIO_BEGIN"].line for p in pair.values()) > last_line, "interleaved case groups")
        last_line = max(p["IIO_END"].line for p in pair.values())
        for axis, other in (("X","Y"),("Y","X")):
            if owner and axis != owner:
                continue
            a, b = pair[axis], pair[other]
            if receipts:
                require(a["board_enter"].tid == int(receipts["seen"]["tid"]), "controlled a different task")
            seq = window(a,b)
            if seq:
                hits.append({"group":i,"owner":axis,"peer":other,"owner_tid":seq[0].tid,"peer_tid":seq[2].tid,
                    "events":[asdict(e) for e in seq],
                    "reads":{axis:{n:asdict(a[n]) for n in ("IIO_BEGIN","bma_enter","i2c_write","bma_exit","IIO_END")},
                             other:{n:asdict(b[n]) for n in ("IIO_BEGIN","bma_enter","i2c_write","bma_exit","IIO_END")}}})
    hits.sort(key=lambda h:h["events"][2]["line"])
    neg = None
    if negative:
        require(hits, "matching reference required for negative")
        h = hits[0]
        a = {e.name:e for e in ops[h["group"],h["owner"]]}
        b = {e.name:e for e in ops[h["group"],h["peer"]]}
        # Move the peer's driver entry to the far side of the response in an evidence copy.
        # The read calls, caller TIDs, bytes and actual return records are identical.
        altered = dict(b)
        altered["bma_enter"] = replace(b["bma_enter"], line=a["i2c_reply"].line+1, ns=a["i2c_reply"].ns+1)
        neg = {"rejected":window(a,altered) is None,"original_peer_entry":asdict(b["bma_enter"]),
               "changed_peer_entry":asdict(altered["bma_enter"]),
               "unchanged_ends":[asdict(p["IIO_END"]) for p in (a,b)]}
        require(neg["rejected"], "equal-result wrong-window copy accepted")
    return {"valid":True,"matched":bool(hits),"complete_groups":groups,"hits":hits,
            "boot_id":meta["boot_id"],"kernel_build_id":meta["kernel_build_id"],"board_build_id":meta["board_build_id"],
            "checks":{"clock":meta["trace_clock"],"probe_counts":probes,"capture_sha256":digest(capture/"capture.sha256"),
                      "reads":groups*2,"cleaned":True,"board_control":receipts},"negative":neg}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--package",type=Path,required=True)
    p.add_argument("--groups",type=int,required=True)
    p.add_argument("--owner",choices=("X","Y"))
    p.add_argument("--negative",action="store_true")
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    try:
        result=judge(args.capture, read_json(args.package), args.groups, args.owner, args.negative)
    except (ValueError,KeyError,TypeError,OSError,IndexError) as error:
        result={"valid":False,"matched":False,"error":str(error)}
    with args.out.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)
        stream.write("\n")
    return int(not result["valid"] or (args.owner is not None and not result["matched"]))


if __name__=="__main__":
    sys.exit(main())

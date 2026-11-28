"""Learn each selected hwmon channel's bus path and verify independent cold captures."""
import argparse
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import sys
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "iio-path"))
from capture import guest_id
from i2c_verify import MESSAGE, REGMAP, RESULT

TRACE = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*\d+\]\s+.*?(\d+)\.(\d{1,9}):\s+(\w+):\s*(.*)")
MARK = re.compile(r"HWMON_(BEGIN|END) key=g(\d{3})([ab]) channel=([AB])(?: rc=(-?\d+) value=(-?\d+))?")
PROBES = ("driver_enter", "driver_exit", "board_enter", "board_exit", "core_enter", "core_exit")
BUS = ("regmap_hw_read_start", "i2c_write", "i2c_read", "board_enter", "board_exit",
       "i2c_reply", "i2c_result", "regmap_hw_read_done")
COUNTS = {"train": 4, "ordered": 2, "natural": 96, "active": 1}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Event:
    line: int
    ns: int
    tid: int
    name: str
    detail: str


def inputs(cap, pkg, mode):
    manifest = {}
    for row in (cap / "capture.sha256").read_text().splitlines():
        h, name = row.split()
        require(re.fullmatch(r"[a-z][a-z0-9.-]*", name) and name not in manifest and digest(cap / name) == h,
                "invalid capture hash/name: " + name)
        manifest[name] = h
    require(set(("trace.txt", "ops.tsv", "run.env", "kernel.notes", "board.notes", "probes.txt", "stats.txt")) <= manifest.keys(),
            "incomplete capture")
    log = (cap / "serial.log").read_text(errors="replace").replace("\r", "")
    require(re.findall(r"^CAPTURE ([a-f0-9]{64})  capture.sha256$", log, re.M) == [digest(cap / "capture.sha256")],
            "missing or mismatched serial seal")
    require(json.loads((cap / "capture-result.json").read_bytes())["passed"] is True, "guest capture failed")
    env = dict(row.split("=", 1) for row in (cap / "run.env").read_text().splitlines())
    meta = json.loads((cap / "build.json").read_bytes())
    require(all(meta.get(k) == v for k,v in env.items()), "guest/build receipt differs")
    for k in ("kernel_build_id", "kernel_sha256", "vmlinux_sha256", "config_sha256", "board_build_id", "board_sha256", "initrd_sha256"):
        require(meta[k] == pkg[k], "build mismatch " + k)
    require(guest_id(cap / "kernel.notes") == meta["kernel_build_id"] and guest_id(cap / "board.notes") == meta["board_build_id"],
            "wrong live kernel or board")
    if "driver.notes" in manifest:
        require(guest_id(cap / "driver.notes") == pkg["driver_build_id"], "wrong native module")
    require(re.findall(r"^BOOT ([0-9a-f-]{36})$", log, re.M) == [str(UUID(meta["boot_id"]))], "wrong serial boot")
    require(env.get("trace_clock") == "global" and env["cleaned"] == "1" and int(env["reader_exit"]) == 0, "capture clock/cleanup")
    require(env["bus"] == "i2c" and int(env["group_count"]) == COUNTS[mode], "wrong bus or pair count")
    require(env["channel_a"] != env["channel_b"] and env["bound_driver"] and env["hwmon_name"], "missing hwmon binding")
    blocks=(cap / "stats.txt").read_text().split("/sys/kernel/tracing/per_cpu/")[1:]
    require(blocks, "missing per-CPU tracing statistics")
    for block in blocks:
        for field in ("overrun", "commit overrun", "dropped events"):
            require(re.findall(r"^" + field + r":\s*(\d+)\s*$", block, re.M) == ["0"], "trace stats " + field)
    counters = {}
    for row in (cap / "probes.txt").read_text().splitlines():
        cols = row.split()
        if len(cols) == 3:
            p = re.split(r"[:/]", cols[0])[-1]
            if p in PROBES:
                require(p not in counters, "duplicated probe")
                counters[p] = [int(cols[1]), int(cols[2])]
    for p in PROBES[:4]:
        require(p in counters and counters[p][0] >= 2 * COUNTS[mode] and counters[p][1] == 0, "missing/missed probe: " + p)
    return meta, manifest


def read_trace(cap, groups):
    lines = (cap / "trace.txt").read_text().splitlines()
    header = re.findall(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)", "\n".join(lines))
    require(len(header) == 1 and header[0][0] == header[0][1], "incomplete trace buffer")
    operations, pending = {}, {}
    for n, line in enumerate(lines, 1):
        require("LOST EVENTS" not in line.upper(), "lost records")
        row = TRACE.search(line)
        if not row:
            require("HWMON_BEGIN" not in line and "HWMON_END" not in line, "unparsed operation boundary")
            continue
        tid, seconds, fraction, name, payload = row.groups()
        tid = int(tid)
        e = Event(n, int(seconds) * 10**9 + int(fraction.ljust(9, "0")), tid, name, payload.strip())
        if name in ("trace_marker", "tracing_mark_write") and payload.startswith("HWMON_"):
            m = MARK.fullmatch(payload)
            require(m, "malformed operation boundary " + payload)
            edge, group, suffix, channel, rc, val = m.groups()
            key = int(group), channel
            require(suffix.upper() == channel and 1 <= key[0] <= groups, "wrong operation group")
            if edge == "BEGIN":
                require(tid not in pending and key not in operations and rc is None, "duplicate begin")
                pending[tid] = key
                operations[key] = [replace(e, name=edge)]
            else:
                require(pending.pop(tid, None) == key and rc == "0" and val is not None, "failed call or wrong end")
                operations[key].append(replace(e, name=edge))
        elif tid in pending and (name.startswith(("regmap_", "i2c_")) or name in PROBES):
            operations[pending[tid]].append(e)
    require(not pending and len(operations) == groups * 2, "incomplete operation set")
    rows = {}
    for row in (cap / "ops.tsv").read_text().splitlines():
        key, ch, tid, size, rc, val = row.split()
        require(key not in rows and int(rc) == 0 and int(size) == len(val) + 1, "invalid read table rows")
        rows[key] = (ch, int(tid), int(val))
    require(len(rows) == 2 * groups, "bad number of returned operations")
    for (g, ch), record in operations.items():
        val = int(MARK.fullmatch(record[-1].detail)[6])
        require(rows[f"g{g:03d}{ch.lower()}"] == (ch, record[0].tid, val), "reader result and trace differ")
        require(all(a.ns <= b.ns for a,b in zip(record,record[1:])), "nonmonotone task events")
    return operations


def one(record, name):
    hits = [e for e in record if e.name == name]
    require(len(hits) == 1, f"expected one {name}, saw {len(hits)}")
    return hits[0]


def transaction(rows, meta):
    require(tuple(e.name for e in rows) == BUS, "incomplete combined regmap/I2C transaction")
    start, done = [REGMAP.fullmatch(rows[i].detail) for i in (0, 7)]
    require(start and done and start.groups() == done.groups(), "regmap target/count changed")
    bus, device, reg = int(start[1]), int(start[2], 16), int(start[3], 16)
    require((bus, device) == (int(meta["i2c_adapter_nr"]), int(meta["i2c_address"], 16)) and
            f"{bus}-{device:04x}" == meta["i2c_client"], "unexpected I2C device")
    write, read, reply = [MESSAGE.fullmatch(rows[i].detail) for i in (1, 2, 5)]
    require(write and read and reply, "malformed I2C messages")
    require(all((bus, device) == (int(m[1]), int(m[3],16)) for m in (write,read,reply)), "bus identity differs")
    require(write[2] == "0" and write[5] == "1" and not int(write[4],16) & 1 and write[6], "broken selector write")
    selector = int(write[6], 16)
    require(selector == reg, "regmap and I2C register selector differ")
    require(read[2] == "1" and int(read[4],16) & 1 and not read[6] and
            read.groups()[:5] == reply.groups()[:5] and reply[6], "unpaired data read")
    data = bytes.fromhex(reply[6].replace("-", " "))
    require(len(data) == int(read[5]), "truncated data reply")
    result = RESULT.fullmatch(rows[6].detail)
    require(result and (int(result[1]),result[2],result[3]) == (bus,"2","2"), "incomplete I2C read")
    return {"shape":[reg,selector,len(data)], "bytes":data.hex(), "events":rows}


def features(record, meta):
    begin, end = one(record,"driver_enter"), one(record,"driver_exit")
    require(all(re.search(r"\b" + re.escape(meta["driver_symbol"]) + r"\b", e.detail) for e in (begin,end)),
            "native driver probe did not bind to the declared callback")
    accepted = [e for e in record if e.name in BUS]
    require(accepted and len(accepted) % len(BUS) == 0 and begin.line < accepted[0].line < accepted[-1].line < end.line,
            "missing native driver or transfer")
    tx = [transaction(accepted[i:i+len(BUS)],meta) for i in range(0,len(accepted),len(BUS))]
    for t in tx:
        require(all(re.search(r"\bboard_xfer\b", t["events"][i].detail) for i in (3,4)),
                "target I2C adapter callback mismatch")
    last = one(record,"END")
    return {"shape":[t["shape"] for t in tx], "bytes":[t["bytes"] for t in tx],
            "value":int(MARK.fullmatch(last.detail)[6]), "transfers":tx,
            "tid":begin.tid, "start":one(record,"BEGIN"), "end":last, "driver_enter":begin,
            "driver_exit":end, "core_enter":next((e for e in record if e.name == "core_enter"),None)}


def decode(features, rules):
    # Only register selectors and transfer widths participate in identification.
    labels = [ch for ch in ("A","B") if rules["paths"][ch] == features["shape"]]
    require(len(labels) == 1, "ambiguous or unregistered transfer path")
    return labels[0]


def compare_pair(pair,rules,expected_order=None):
    for ch, info in pair.items():
        require(decode(info,rules) == ch, "mid-path signature disagrees with issued operation")
        require([info["bytes"],info["value"]] == rules["outputs"][ch], "data or sysfs result differs")
    require(pair["A"]["tid"] != pair["B"]["tid"], "two reads share a thread")
    if expected_order:
        a,b = (pair[ch] for ch in expected_order)
        require(a["end"].line < b["start"].line and a["end"].ns <= b["start"].ns, "wrong complete operation order")


def matching_window(owner,peer,level="driver_enter"):
    arrival = peer[level]
    if not arrival:
        return None
    for t in owner["transfers"]:
        evs=t["events"]
        critical=[evs[2],evs[3],arrival,evs[4],evs[5]]
        if all(a.line < b.line and a.ns < b.ns for a,b in zip(critical,critical[1:])):
            return critical
    return None


def board_receipt(cap,owner,info):
    lines=(cap/"control.txt").read_text().splitlines()
    phases = {}
    for row in lines:
        step,*fields=row.split()
        require(step not in phases, "duplicate board receipt")
        phases[step] = dict(word.split("=",1) for word in fields)
    require(list(phases) == ["before","armed","seen","after"] and
            [p["phase"] for p in phases.values()] == ["idle","armed","pending","done"], "control phase mismatch")
    seen,after = phases["seen"],phases["after"]
    require(int(seen["tid"]) == info["tid"] and int(seen["reg"]) in {s[1] for s in info["shape"]} and
            int(seen["seq"]) == 1 and int(seen["end_ns"]) == 0 and int(seen["delay_ms"]) > 0 and
            int(after["end_ns"]) > int(seen["start_ns"]) > 0, "bad waiting thread/transaction")
    for k in ("tid","reg","seq","delay_ms","start_ns"):
        require(seen[k] == after[k], "pending/completion are different transactions")
    return phases


def identity(meta,pkg):
    return {k:meta[k] for k in ("kernel_sha256","kernel_build_id","config_sha256","vmlinux_sha256","hwmon_name",
                                "bound_driver","channel_a","channel_b")} | {"driver_sha256":pkg.get("driver_sha256")}


def check(mode,cap,pkg,rules_file=None,owner=None):
    meta,manifest=inputs(cap,pkg,mode)
    require(meta["mode"] == ("active-"+owner if mode=="active" else mode), "wrong guest mode")
    active=mode=="active"
    require(meta["control"] == ("adapter" if active else "none") and ("control.txt" in manifest)==active, "wrong control mode")
    groups=COUNTS[mode]
    records=read_trace(cap,groups)
    pairs=[{c:features(records[g,c],meta) for c in ("A","B")} for g in range(1,groups+1)]
    require(all(max(p[c]["end"].line for c in p) < min(q[c]["start"].line for c in q)
                for p,q in zip(pairs,pairs[1:])), "separate groups overlap")
    base={"valid":True,"boot_id":meta["boot_id"],"groups":groups,"capture_sha256":digest(cap/"capture.sha256"),
          "build_identity":identity(meta,pkg),"board_build_id":meta["board_build_id"]}
    if mode=="train":
        paths,outputs={},{}
        for pair in pairs:
            for ch,info in pair.items():
                require(paths.setdefault(ch,info["shape"])==info["shape"],"unstable training path")
                ret=[info["bytes"],info["value"]]
                require(outputs.setdefault(ch,ret)==ret,"unstable synthetic sensor")
        require(paths["A"] != paths["B"], "no distinguishing bus signature")
        rules=base | {"paths":paths,"outputs":outputs,"support_per_channel":groups,
                      "features":["regmap_register","i2c_selector","transfer_bytes"], "matched":True}
        for i, pair in enumerate(pairs):
            compare_pair(pair,rules,("AB","BA")[i%2])
        return rules | {"seal":seal(rules)}
    rules=json.loads(rules_file.read_bytes())
    stored=rules.pop("seal")
    require(stored==seal(rules) and rules["build_identity"]==base["build_identity"] and
            rules["boot_id"]!=base["boot_id"],"frozen training/build mismatch")
    out=base | {"rules_sha256":digest(rules_file),"hits":[],"core_hits":[],"orders":[],"ordered":{},"negative":[]}
    for n,pair in enumerate(pairs,1):
        order=("AB","BA")[n-1] if mode=="ordered" else None
        compare_pair(pair,rules,order)
        if order:
            a,b=(pair[ch] for ch in order)
            out["ordered"][order]=True
            out["orders"].append({"group":n,"order":order,"first_tid":a["tid"],"second_tid":b["tid"],
                                  "first_end":asdict(a["end"]),"second_begin":asdict(b["start"])})
            for ch in "AB":
                changed={k:v.copy() for k,v in pair.items()}
                other="B" if ch=="A" else "A"
                changed[ch]["shape"]=changed[other]["shape"]
                try:
                    compare_pair(changed,rules,order)
                except ValueError as e:
                    out["negative"].append({"kind":"wrong_signature","group":n,"channel":ch,"error":str(e)})
                else:
                    raise ValueError("same-return swapped path was accepted")
            try:
                compare_pair(pair,rules,order[::-1])
            except ValueError as e:
                out["negative"].append({"kind":"reversed_order","group":n,"error":str(e)})
            else:
                raise ValueError("same-return reversed reference was accepted")
        else:
            for ch,other in (("A","B"),("B","A")):
                if owner and ch!=owner:
                    continue
                a,b=pair[ch],pair[other]
                if active:
                    require(meta["owner"]==owner,"wrong board owner")
                    out["control"]=board_receipt(cap,owner,a)
                for level,key in (("driver_enter","hits"),("core_enter","core_hits")):
                    events=matching_window(a,b,level)
                    if not events:
                        continue
                    out[key].append({"group":n,"owner":ch,"peer":other,"owner_tid":a["tid"],"peer_tid":b["tid"],
                                     "events":[asdict(e) for e in events]})
                    if level=="driver_enter":
                        late=b.copy()
                        reply=events[-1]
                        late[level]=replace(b[level],line=reply.line+1,ns=reply.ns+1)
                        require(matching_window(a,late) is None, "wrong driver window accepted")
                        out["negative"].append({"kind":"late_driver_entry","group":n,"rejected":True,
                                                "values":[a["value"],b["value"]]})
    for key in ("hits","core_hits"):
        out[key].sort(key=lambda x:x["events"][2]["line"])
    out["matched"]=all(out["ordered"].values()) if mode=="ordered" else bool(out["hits"])
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=COUNTS)
    for name in ("capture","package","out"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--rules",type=Path)
    p.add_argument("--owner",choices=("A","B"))
    a=p.parse_args()
    if (a.mode=="train") != (a.rules is None) or (a.mode=="active") != bool(a.owner):
        p.error("provide --rules for verification, --owner for active only")
    try:
        result=check(a.mode,a.capture,json.loads(a.package.read_bytes()),a.rules,a.owner)
    except (ValueError,OSError,TypeError,KeyError,IndexError) as err:
        result={"valid":False,"matched":False,"error":str(err)}
    with a.out.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2)
        f.write("\n")
    return 0 if result["valid"] and (a.mode=="natural" or result["matched"]) else 1


if __name__=="__main__":
    sys.exit(main())

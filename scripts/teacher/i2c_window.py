"""Join a private adapter's transaction receipt to two native reads on ftrace global."""
import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TOOLS = ROOT.parent
PROFILES = {
    "bma": ("iio-i2c-overlap", "X", "Y", "IIO", "bma_enter", 4),
    "ads": ("hwmon-i2c", "B", "A", "HWMON", "driver_enter", 204),
}
CONTROL = re.compile(r"KCONC_I2C_CTRL phase=(pending|done) seq=(\d+) reg=(\d+) tid=(\d+)")
ROW = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*\d+\]\s+\S+\s+(\d+)\.(\d{1,9}):\s+(\w+):\s*(.*)")


def require(ok, message):
    if not ok:
        raise ValueError(message)


@dataclass(frozen=True)
class Event:
    line: int
    ns: int
    tid: int
    name: str
    detail: str


def events(lines):
    parsed = []
    for line, raw in enumerate(lines, 1):
        match = ROW.search(raw)
        if match:
            tid, sec, frac, name, detail = match.groups()
            parsed.append(Event(line, int(sec) * 10**9 + int(frac.ljust(9, "0")), int(tid), name, detail))
        elif "KCONC_I2C_CTRL" in raw:
            raise ValueError("unparsed adapter receipt")
    return parsed


def one(records, predicate, label):
    hits = [e for e in records if predicate(e)]
    require(len(hits) == 1, f"{label}: expected one event, found {len(hits)}")
    return hits[0]


def operation(records, prefix, role, driver):
    tag = f"key=g001{role.lower()} "
    def boundary(edge):
        return one(records, lambda e: e.name in ("tracing_mark_write", "trace_marker")
                   and e.detail.startswith(f"{prefix}_{edge} {tag}"), role + " " + edge)
    begin, end = boundary("BEGIN"), boundary("END")
    require(begin.tid == end.tid and begin.line < end.line, "wrong operation endpoints")
    op = [e for e in records if e.tid == begin.tid and begin.line < e.line < end.line]
    result = {name: one(op, lambda e: e.name == name, role + " " + name)
              for name in (driver, "i2c_write", "i2c_read", "board_enter", "board_exit", "i2c_reply", "i2c_result")}
    result.update(begin=begin, end=end)
    return result


def identify_control(records, seq, reg, tid):
    phases = {}
    for event in records:
        if "KCONC_I2C_CTRL" not in event.detail:
            continue
        match = CONTROL.fullmatch(event.detail)
        require(match and event.name == "defer_selected_reply", "invalid adapter receipt producer or format")
        phase, s, r, t = match.groups()
        require((int(s), int(r), int(t), event.tid) == (seq, reg, tid, tid), "wrong adapter request or task")
        require(phase not in phases, "duplicate " + phase)
        phases[phase] = event
    require("pending" in phases, "missing pending")
    require("done" in phases, "missing done")
    return phases


def strict(records, owner, peer, driver, receipt):
    seq, reg, tid = (int(receipt[k]) for k in ("seq", "reg", "tid"))
    require(tid == owner[driver].tid and peer[driver].tid != tid, "owner or peer TID mismatch")
    phases = identify_control(records, seq, reg, tid)
    chain = [owner[driver], owner["i2c_read"], owner["board_enter"], phases["pending"],
             peer[driver], phases["done"], owner["board_exit"], owner["i2c_reply"]]
    for left, right in zip(chain, chain[1:]):
        require(left.line < right.line and left.ns < right.ns, "wrong same-clock order: " + left.detail + " -> " + right.detail)
    require(owner["i2c_result"].line < peer["i2c_write"].line and
            owner["i2c_result"].ns <= peer["i2c_write"].ns, "peer issued I2C before owner transfer completed")
    return {"clock":"global", "seq":seq, "reg":reg, "owner_tid":tid, "peer_tid":peer[driver].tid,
            "events":[asdict(e) for e in chain], "pending_to_done_ns":phases["done"].ns - phases["pending"].ns,
            "owner_end":asdict(owner["end"]), "peer_bus":asdict(peer["i2c_write"]), "peer_end":asdict(peer["end"])}


def rejected(check, expected):
    try:
        check()
    except ValueError as exc:
        return expected in str(exc), str(exc)
    return False, "copy unexpectedly accepted"


def load_legacy(folder):
    spec = importlib.util.spec_from_file_location("legacy_i2c_judge", TOOLS / folder / "judge.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def grade(device, cap, pkg_file, result, rules=None):
    folder, first, second, prefix, driver, register = PROFILES[device]
    package = json.loads(pkg_file.read_bytes())
    legacy = load_legacy(folder)
    meta = json.loads((cap / "build.json").read_bytes())
    result["boot_id"] = meta["boot_id"]
    require(meta["mode"] == "active-" + first and meta["trace_clock"] == "global", "wrong guest schedule or clock")
    require(meta["board_module"] == {"bma":"bma400_i2c_board","ads":"ads7828_i2c_board"}[device], "wrong board")
    require(package["same_clock_events"] == ["pending","done"] and package["phase"] == "active", "wrong package capability")
    if device == "bma":
        base = legacy.judge(cap, package, 1, first)
        receipt = base["checks"]["board_control"]["seen"]
    else:
        require((cap / "driver.notes").is_file(), "missing sensor module notes")
        base = legacy.check("active", cap, package, rules, first)
        receipt = base["control"]["seen"]
    require(int(receipt["seq"]) == 1 and int(receipt["reg"]) == register, "wrong selected transaction")
    result["original_window_matched"] = base["matched"]
    result["kernel_build_id"] = meta["kernel_build_id"]
    result["board_build_id"] = meta["board_build_id"]
    result["capture_seal"] = hashlib.sha256((cap / "capture.sha256").read_bytes()).hexdigest()
    records = events((cap / "trace.txt").read_text().splitlines())
    owner = operation(records, prefix, first, driver)
    peer = operation(records, prefix, second, driver)
    try:
        result["witness"] = strict(records, owner, peer, driver, receipt)
        result["matched"] = base["matched"]
    except ValueError as exc:
        result["error"] = str(exc)
    # Change just the peer driver entry; both actual read returns and TIDs are kept.
    reply = owner["i2c_reply"]
    changed = dict(peer)
    changed[driver] = replace(peer[driver], line=reply.line + 1, ns=reply.ns + 1)
    negative = result["negative"]
    negative["wrong_order_rejected"], negative["wrong_order_reason"] = rejected(
        lambda: strict(records, owner, changed, driver, receipt), "wrong same-clock order")
    negative["changed_driver_entry"] = asdict(changed[driver])
    negative["unchanged_returns"] = [asdict(e["end"]) for e in (owner, peer)]
    for phase in ("pending", "done"):
        kept = [e for e in records if not e.detail.startswith("KCONC_I2C_CTRL phase=" + phase + " ")]
        # A negative counts only if it excised exactly one real event.
        hit, reason = rejected(lambda: strict(kept, owner, peer, driver, receipt), "missing " + phase)
        negative["missing_" + phase + "_rejected"] = hit and len(kept) + 1 == len(records)
        negative["missing_" + phase + "_reason"] = reason
    negative["missing_receipt_rejected"] = negative["missing_pending_rejected"] and negative["missing_done_rejected"]

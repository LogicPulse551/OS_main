"""Check a functional boot against the protocol registered before both builds ran."""

import argparse
import hashlib
import json
from pathlib import Path
import re


RESULT_FILES = {
    "fixture": "/sys/kernel/debug/kconc-bma400/results",
    "observer": "/sys/kernel/debug/kconc-c06-observer/results",
}


def verify_slot(plan, slot_id, col):
    slot, = [entry for entry in plan["slots"] if entry["id"] == slot_id]
    mode = slot["mode"]
    violations = []

    def equal(label, actual, expected):
        if type(actual) is not type(expected) or actual != expected:
            violations.append(f"{label}: expected {expected!r}, observed {actual!r}")

    def fields(label, obj, expected):
        if not isinstance(obj, dict):
            violations.append(f"{label}: missing object")
            return
        for key, value in expected.items():
            equal(f"{label}.{key}", obj.get(key), value)

    def rows(label, actual, expected):
        if not isinstance(actual, list):
            violations.append(f"{label}: missing array")
            return
        equal(label + ".count", len(actual), len(expected))
        for i, (obs, exp) in enumerate(zip(actual, expected)):
            fields(f"{label}[{i}]", obs, exp)

    if not isinstance(col, dict):
        return {"slot": slot_id, "passed": False, "violations": ["missing collection"]}
    fields("guest", col, {"schema": 1, "online": "0-3"})
    cmdline = col.get("cmdline")
    flags = sorted(arg for arg in str(cmdline).split() if arg.startswith("kconc_bma400."))
    parameters = dict(plan["command_parameters"])
    if not slot["off_mode_omitted"]:
        parameters["mode"] = mode
    equal("cmdline.fixture", flags, sorted(f"kconc_bma400.{key}={v}" for key, v in parameters.items()))

    raw_files = col.get("debugfs")
    present = slot["fixture"] != "absent"
    for key, path in RESULT_FILES.items():
        entry = raw_files.get(path) if isinstance(raw_files, dict) else None
        exists = key == "observer" or present
        fields(path, entry, {"exists": exists})
        if key + "_error" in col or key not in col:
            violations.append(f"{key}: missing or malformed collector result")
        if not isinstance(entry, dict):
            continue
        if not exists:
            fields(path, entry, {"text": None})
            equal(key, col.get(key), None)
        else:
            try:
                original = json.loads(entry["text"])
                equal(key + ".raw", original, col.get(key))
            except (ValueError, KeyError, TypeError) as error:
                violations.append(f"{path}: unreadable JSON ({error})")

    fixture = col.get("fixture")
    if present:
        fields("fixture", fixture, {"schema": 1, "mode": mode, **plan["command_parameters"]})
        body = fixture if isinstance(fixture, dict) else {}
        checks = slot["fixture"] == "checks"
        rows("checks", body.get("checks"), plan["expected_checks"] if checks else [])
        single = {"sample": 0, "warmup": 0, "cycles": 1, "bus_reads": 3, "result": 0}
        rows("batch", body.get("rows"), [] if checks else [single])

    observer = col.get("observer")
    fields("observer", observer, {"schema": 1, "errors": 0})
    expected_maps = []
    for mapping in slot["maps"]:
        n = mapping["raw_starts"]
        private = mapping["path"] == "private"
        visible = int(mapping["target_node"] == "present")
        expected_maps.append({
            "width": mapping["bits"], "hidden": 1 - visible, "target_live_visible": visible,
            "raw_starts": n, "private_hits": n if private else 0, "public_hits": 0 if private else n,
            "unresolved": 0, "bulk_success": 1, "reader_rc": 0, "control_ready": 1,
            "overlap": 1, "control_ok": 1, "control_joined": 1, "control_bus_reads": 1,
            "control_live_visible": 1, "target_removed": 1, "control_removed": 1,
        })
    rows("maps", observer.get("maps") if isinstance(observer, dict) else None, expected_maps)

    entries = col.get("final_regmap_entries")
    if not isinstance(entries, list) or any(not isinstance(name, str) for name in entries):
        violations.append("final_regmap_entries: missing directory listing")
    elif {"dummy-c02-bulk", "dummy-c06-control"}.intersection(entries):
        violations.append("test map still visible after teardown")
    log = col.get("dmesg")
    if not isinstance(log, str) or not log.strip():
        violations.append("missing kernel log")
    else:
        for line in log.splitlines():
            if re.search(r"\b(?:BUG:|Oops:|Kernel panic|kernel BUG at|WARNING: CPU:)", line):
                violations.append("kernel diagnostic: " + line)
    return {"slot": slot_id, "passed": not violations, "violations": violations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, help="externally registered matrix (default: bundled functional matrix)")
    parser.add_argument("--protocol-sha256", help="required digest when using an external protocol")
    parser.add_argument("--slot", required=True)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if bool(args.protocol) != bool(args.protocol_sha256):
        parser.error("supply both --protocol and --protocol-sha256")
    default = Path(__file__).resolve().parents[1] / "configs/optimization/bma400-functional.json"
    raw = (args.protocol or default).read_bytes()
    if args.protocol and hashlib.sha256(raw).hexdigest() != args.protocol_sha256:
        parser.error("protocol digest mismatch")
    result = verify_slot(json.loads(raw), args.slot, json.loads(args.collection.read_bytes()))
    content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as dest:
            dest.write(content)
    else:
        print(content, end="")
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())

"""Verify a normal X read whose submitted SPI message spans both other driver entries."""
import argparse
import csv
from dataclasses import replace
from pathlib import Path
import json

import inspect_overlap as obs


AXES = ("X", "Y", "Z")
GROUPS = tuple(f"{n:02d}" for n in range(1, 13))


def checked_capture(args):
    pkg, cert = obs.js(args.package), obs.js(args.reference)
    meta = obs.load_ids(args.capture, pkg, cert)
    obs.check(set(cert["signature"]) == set(AXES), "registered axes differ")
    ref_hash = obs.sha(args.reference)
    obs.check(pkg["observation"]["registry_sha256"] == ref_hash, "different axis reference")
    symbol = obs.once(pkg["observation"]["source_verification"], "registered read_raw")["symbol"]
    obs.check(any(name.endswith("::" + symbol) for name in cert["common_driver_functions"]),
              "entry symbol outside learned driver path")
    plan = obs.js(args.capture / "plan.json")
    obs.check(plan["package_sha256"] == obs.sha(args.package), "package differs from launch plan")
    argv = plan["argv"]
    cmdline = argv[argv.index("-append") + 1].split()
    obs.check("iio.mode=" + meta["mode"] in cmdline and meta["mode"] == plan["mode"],
              "capture mode differs from boot plan")
    expected = {Path(k).name: v for k, v in pkg["guest"].items() if k.startswith("payload/")}
    payload = {Path(p).name: h for h, p in
               (line.split() for line in (args.capture / "guest-payload.sha256").read_text().splitlines())}
    obs.check(expected == payload and expected["board.ko"] == pkg["board_sha256"],
              "unexpected reader, observer or board")
    # Capture checks the transfer from the private evidence disk. Recheck the guest's
    # manifest here too when the verifier is run independently on retained files.
    manifest = args.capture / "capture.sha256"
    serial = (args.capture / "serial.log").read_text().splitlines()
    obs.check(serial.count("CAPTURE " + obs.sha(manifest) + "  capture.sha256") == 1,
              "guest serial does not commit the capture manifest")
    members = {line.split()[1] for line in manifest.read_text().splitlines()}
    obs.check({"guest-payload.sha256", "probe-stats.txt"} <= members, "missing evidence binding")
    events = obs.load_events(args.capture)
    ops = obs.axis_reads(args.capture, events, cert, symbol, AXES)
    obs.check(all(key + ".words" in members for key in ops), "unbound worker trace")
    common = {"boot_id": meta["boot_id"], "kernel_build_id": meta["kernel_build_id"],
              "board_build_id": meta["board_build_id"], "driver_symbol": symbol,
              "package_sha256": plan["package_sha256"], "reference_sha256": ref_hash,
              "trace_sha256": obs.sha(args.capture / "trace.txt"),
              "capture_sha256": obs.sha(manifest)}
    return meta, pkg, cert, ops, common, members


def assess_window(operations):
    xmsg = operations["X"]["spi"]
    flags = {axis: obs.strictly(xmsg["submit"], operations[axis]["entry"], xmsg["start"], xmsg["done"])
             for axis in ("Y", "Z")}
    return {"per_peer": flags, "strict_window": all(flags.values())}


def group(ops, keys):
    found = {axis: ops[key] for axis, key in zip(AXES, keys)}
    obs.check(all(found[a]["axis"] == a for a in AXES), "read label differs from recognized axis")
    obs.check(len({op["tid"] for op in found.values()}) == 3, "three independent reader TIDs required")
    obs.check(len({op["spi"]["dev"] for op in found.values()}) == 1, "different SPI devices")
    return found


def passive(args):
    meta, pkg, cert, ops, result, members = checked_capture(args)
    obs.check(meta["mode"] == "natural3" and "control.tsv" not in members and "triple" not in pkg,
              "passive capture contains a control plan")
    obs.check(all(meta[k] == cert["identity"][k] for k in ("board_sha256", "board_build_id")),
              "passive board differs from the training board")
    expected = {"n" + a.lower() + n for n in GROUPS for a in AXES}
    obs.check(set(ops) == expected, "incomplete natural round")
    pairs = []
    for n in GROUPS:
        group_ops = group(ops, ("n" + a.lower() + n for a in AXES))
        pairs.append({"pair": n, **assess_window(group_ops),
                      "rows": {a: obs.compact(group_ops[a]) for a in AXES}})
    hits = [row["pair"] for row in pairs if row["strict_window"]]
    result.update(phase="passive", passed=True, pairs=pairs, examined=len(pairs),
                  first_match=hits[0] if hits else None, strict_matches=len(hits),
                  per_peer_matches={a: sum(r["per_peer"][a] for r in pairs) for a in ("Y", "Z")},
                  active_attempts=0)
    return result


def receipt_matches(control, ops):
    expected = {"state_before": 0, "state_armed": 1, "state_observed": 2, "state_after": 3,
                "y_state": 2, "z_state": 2, "callback_tid": ops["X"]["spi"]["submit"].tid}
    for axis in AXES:
        prefix = axis.lower()
        expected.update({prefix + "_key": prefix + "3", prefix + "_tid": ops[axis]["tid"],
                         prefix + "_exit": 0})
    if not all(control.get(k) == str(v) for k, v in expected.items()):
        return False
    for field in ("y_started_ns", "z_started_ns"):
        times = [int(control[k]) for k in ("arm_ns", "warming_seen_ns", field, "joined_ns")]
        if not 0 < times[0] < times[1] < times[2] < times[3]:
            return False
    return True


def equivalent(actual, expected):
    return (all(actual[k] == expected[k] for k in ("axis", "regmap", "size", "rc", "value", "payload"))
            and actual["spi"]["length"] == expected["spi"]["length"])


def assess(ops, control, cold):
    window = assess_window(ops)
    receipt = receipt_matches(control, ops)
    readouts = {a: equivalent(ops[a], cold[a]) for a in AXES}
    return {**window, "controller_matched": receipt, "readouts_matched": readouts,
            "passed": window["strict_window"] and receipt and all(readouts.values())}


def negative_controls(ops, control, cold):
    negative = {}
    for axis in ("Y", "Z"):
        peer = ops[axis]
        at_start = replace(peer["entry"], ns=ops["X"]["spi"]["start"].ns)
        changed = {**ops, axis: {**peer, "entry": at_start}}
        negative[axis.lower() + "_outside_window"] = assess(changed, control, cold)
    assigned = dict(control, z_tid=control["y_tid"])
    negative["wrong_z_thread"] = assess(ops, assigned, cold)
    negative["wrong_ready_state"] = assess(ops, dict(control, state_observed="1"), cold)
    negative["wrong_board_owner"] = assess(ops, dict(control, callback_tid=control["y_tid"]), cold)
    return negative


def active(args):
    meta, pkg, cert, ops, result, members = checked_capture(args)
    plan = pkg["triple"]
    obs.check(plan["axis_owner"] == "X" and plan["peer_axes"] == ["Y", "Z"] and plan["initrd_plan"] is True,
              "wrong actors in guest plan")
    obs.check(meta["mode"] == plan["guest_mode"] == "natural" and meta["reader_exit"] == "0"
              and meta["board_read_order"] == "X{Y,Z}", "guest did not complete registered plan")
    obs.check(meta["board_build_id"] != cert["identity"]["board_build_id"], "passive board loaded")
    ref = obs.js(args.natural)
    obs.check(ref["phase"] == "passive" and ref["passed"] and ref["active_attempts"] == 0
              and ref["kernel_build_id"] == meta["kernel_build_id"]
              and ref["board_build_id"] == cert["identity"]["board_build_id"]
              and ref["reference_sha256"] == result["reference_sha256"]
              and ref["driver_symbol"] == result["driver_symbol"]
              and ref["boot_id"] != meta["boot_id"], "different or non-independent natural reference")
    obs.check([row["pair"] for row in ref["pairs"]] == list(GROUPS), "incomplete reference")
    hits = [row["pair"] for row in ref["pairs"] if row["strict_window"]]
    obs.check(hits and hits[0] == args.pair == ref["first_match"], "expected first naturally matched triple")
    cold = ref["pairs"][0]["rows"]
    obs.check(set(ops) == {"x3", "y3", "z3"} and "control.tsv" in members,
              "missing normal operation or controller receipt")
    current = group(ops, ("x3", "y3", "z3"))
    with (args.capture / "control.tsv").open() as stream:
        control = obs.once(list(csv.DictReader(stream, delimiter="\t")), "board receipt")
    signal = assess(current, control, cold)
    result.update(phase="active", **signal, natural_boot_id=ref["boot_id"], frozen_pair=args.pair,
                  natural_sha256=obs.sha(args.natural), control=control,
                  rows={a: obs.compact(current[a]) for a in AXES})
    if signal["passed"]:
        negative = negative_controls(current, control, cold)
        result["negative"] = negative
        result["passed"] = all(not r["passed"] and all(r["readouts_matched"].values())
                               for r in negative.values())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("passive", "active"):
        action = modes.add_parser(mode)
        for name in ("capture", "package", "reference", "out"):
            action.add_argument("--" + name, type=Path, required=True)
        if mode == "active":
            action.add_argument("--natural", type=Path, required=True)
            action.add_argument("--pair", required=True)
    args = parser.parse_args()
    try:
        result = (active if args.mode == "active" else passive)(args)
    except (KeyError, ValueError, OSError, TypeError, IndexError, StopIteration) as e:
        result = {"phase": args.mode, "passed": False, "diagnostic": str(e)}
    obs.output(args.out, result)
    print(json.dumps({k: v for k, v in result.items()
                      if k in ("phase", "passed", "boot_id", "first_match", "strict_matches", "diagnostic")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

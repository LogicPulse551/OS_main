"""Validate the original backend's grant and wake for the private RAM update.

Physical slot A always holds the instrumented update. Its logical callback
comes from the requested AB/BA mapping and the actual worker TIDs.
"""

import hashlib
import json
import re
from pathlib import Path

from .artifacts import notes_id
from .lifecycle import load

_REPO = Path(__file__).resolve().parents[2]
k08 = load("kconc_prelock_k08_analysis", _REPO / "adapters/maccconc/k08_analysis.py")
k03 = k08.k03


def guest_id(path):
    return notes_id(path.read_bytes())


# nm -S of this experiment's vmlinux. These ranges apply only to this build.
BUILD_ID = "3f8e2263798cf38787636c757001b7454df7139a"
PLAN_SHA256 = "302a672890bab4990db2f91367de7ed643513f3848e8b1317221aa713cae2a92"
SYMBOLS = {
    "update": (0xFFFFFFFF825BEB10, 0x122),  # regmap_update_bits_base
    "prelock": (0xFFFFFFFF825CDCF0, 0x1D6),  # kconc_regmap_prelock
    "marker": (0xFFFFFFFF825CDEE0, 0xC3),  # kconc_regmap_checkpoint
    "lock": (0xFFFFFFFF825B97C0, 0x3A),  # regmap_lock_spinlock
}


class PositionError(ValueError):
    """The recorded execution cannot establish the required handoff."""


def require(condition, reason):
    if not condition:
        raise PositionError(reason)


def in_symbol(ip, symbol):
    start, size = SYMBOLS[symbol]
    return start <= int(ip, 16) < start + size


def only(indices, description):
    require(len(indices) == 1, f"expected one {description}, found {len(indices)}")
    return indices[0]


def read(p):
    return json.loads(Path(p).read_text(encoding="utf-8-sig"))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_plan(path):
    p = Path(path)
    tokens = p.read_text(encoding="ascii").split()
    assert (
        tokens[0] == "MACCCONC_K03_PLAN_V1"
        and tokens[1] == "spin_limit"
        and tokens[3:6] == ["role", "A", "count"]
    )
    count = int(tokens[6])
    assert len(tokens) == 7 + 2 * count
    stack = [
        {
            "ip": f"0x{int(tokens[7 + i * 2], 16):016x}",
            "parent_idx": int(tokens[8 + i * 2]),
        }
        for i in range(count)
    ]
    return {
        "path": str(p),
        "sha256": sha(p),
        "stack": stack,
        "count": count,
        "spin_limit": int(tokens[2]),
    }


def phases(run):
    result = {}
    for line in (run / "raw/native/testcase.stdout.txt").read_text().splitlines():
        if line.startswith("KCONC_PHASE "):
            value = json.loads(line[len("KCONC_PHASE ") :])
            result[value["phase"]] = value
    return result


def trace_rows(run):
    rows = []
    pattern = re.compile(
        r"^(.+)-(\d+)\s+\[[^\]]+\]\s+\S+\s+([0-9]+\.[0-9]+):\s+(\w+):\s*(.*)$"
    )
    for number, line in enumerate(
        (run / "raw/system.trace").read_text().splitlines(), 1
    ):
        m = pattern.match(line.strip())
        if not m:
            continue
        tid = int(m.group(2))
        ns = float(m.group(3))
        event = m.group(4)
        detail = m.group(5)
        row = {"line": number, "tid": tid, "ns": ns, "event": event, "detail": detail}
        if event.startswith("regmap_reg_"):
            q = re.search(r"reg=(\d+) val=(\d+)", detail)
            if q:
                row.update(reg=int(q.group(1)), val=int(q.group(2)))
        rows.append(row)
    return rows


def check_handoff(run, expected_plan, derived, metadata, slot_roles):
    actual_build = guest_id(run / "raw/kernel.notes")
    require(
        actual_build == derived["kernel_build_id"] == BUILD_ID,
        "incorrect guest build for the lock symbols",
    )
    native = run / "raw/native"
    require(
        sha(native / "plan.txt") == expected_plan["sha256"] == PLAN_SHA256,
        "unexpected executed plan",
    )
    events = {role: k03.read_events(native, role) for role in ("A", "B")}
    a = events["A"]

    def boundary(kind, symbol):
        return only(
            [
                i
                for i, e in enumerate(a)
                if e["kind"] == kind and in_symbol(e["ip"], symbol)
            ],
            f"A {symbol} {kind}",
        )

    entry, end = boundary("ENTRY", "update"), boundary("EXIT", "update")
    inside = [i for i in range(entry + 1, end) if a[i]["kind"] == "ENTRY"]

    def inner(symbol):
        index = only(
            [i for i in inside if in_symbol(a[i]["ip"], symbol)],
            f"A {symbol} call in this update",
        )
        require(
            in_symbol(a[index]["caller_ip"], "update"), f"incorrect caller of {symbol}"
        )
        return index

    callback, lock = inner("prelock"), inner("lock")
    controls = [i for i, e in enumerate(a) if e["kind"] in ("WAKE", "WAIT")]
    require(len(controls) == 2, "expected exactly one grant and one wait in A")
    grant, wait = controls
    require(
        [(a[i]["kind"], a[i]["flagidx"], a[i]["timed_out"]) for i in controls]
        == [("WAKE", 0, False), ("WAIT", 1, False)],
        "incorrect permit or completion-wait receipt",
    )
    outer, peer = slot_roles["A"], slot_roles["B"]
    require(grant > entry, f"{peer} permitted before {outer} entered regmap_update_bits_base")
    require(wait < lock, "handoff outside the pre-lock window of the original A call")
    require(callback < grant, f"{peer} permitted before {outer} reached the interior checkpoint")
    target = only(
        [
            i
            for i, e in enumerate(a)
            if e["kind"] == "MEMORY" and e["stack"] == expected_plan["stack"]
        ],
        "A access with the frozen interior stack",
    )
    require(
        grant + 1 == wait
        and wait + 1 == target
        and target < lock
        and in_symbol(a[target]["ip"], "marker"),
        "grant and wait must immediately precede the planned marker before the default lock",
    )
    require(
        not any(e["kind"] in ("WAIT", "WAKE") for e in events["B"]),
        "unexpected in-callback control on B",
    )

    # Compare with the actual words, including the function boundaries. The
    # B-side gate and completion are executor receipts outside the B callback.
    words = [
        int(w, 16)
        for w in (native / "A.words").read_text(encoding="ascii").splitlines()
    ]
    tags = {"ENTRY": 0, "EXIT": 1, "MEMORY": 3}
    for index in (entry, callback, target, lock, end):
        e = a[index]
        offset = e["word_index"]
        expected = (tags[e["kind"]] << 60) | (int(e["ip"], 16) & 0x00FFFFFFFFFFFFFF)
        require(
            offset < len(words) and words[offset] == expected,
            "raw word differs from recorded boundary or target",
        )
        if e["kind"] == "ENTRY":
            require(
                words[offset + 1 : offset + 2] == [int(e["caller_ip"], 16)],
                "raw caller differs from decoded event",
            )
    start = a[grant]["word_index"]
    require(
        a[wait]["word_index"] == start + 1
        and a[target]["word_index"] == start + 2
        and words[start : start + 2] == [0x5000000000000000, 0x4000000000000001],
        "raw handoff words disagree",
    )
    checks = k03._control_checks(metadata, events, expected_plan)
    # K03 assumes identity mapping. The K08/K09 contract identifies the
    # actually loaded callbacks in physical-slot order for both directions.
    checks["roles"] = metadata["roles"] == {
        slot: k08.CALLBACKS[role] for slot, role in slot_roles.items()
    }
    failed = [name for name, ok in checks.items() if not ok]
    require(not failed, "backend receipt checks failed: " + ", ".join(failed))
    require(
        metadata["a_completed_wake0"]["called"] is False,
        "B could have been released after A completed",
    )
    return {
        "update_enter": entry + 1,
        "callback_enter": callback + 1,
        f"permit_{peer}": grant + 1,
        f"wait_for_{peer}": wait + 1,
        "marker": target + 1,
        "default_lock_enter": lock + 1,
        "update_exit": end + 1,
        "permit_word_line": start + 1,
    }


def verify(run, expected_plan, derived, reference=None, direction="ab"):
    require(__debug__, "normal Python mode is required for the legacy assertions")
    run_json = read(run / "raw/native/run.json")
    ph = phases(run)
    require(direction in k08.ORDERS, "unsupported direction")
    ordered_phases = [ph[name] for name in ("setup", "initial_state", "operations", "property", "teardown")]
    contract, slot_roles = k08._sample_contract(run_json, ordered_phases, direction)
    contract["sampling_only"] = run_json["sampling_only"] is False
    outer, peer = k08.ORDERS[direction]
    contract["controlled_candidate"] = (
        run_json["k09_schema_version"] == 1
        and run_json["candidate_execution_requested"] is True
        and run_json["requested_candidate_executions"] == 1
        and run_json["candidate_pattern"] == f"{outer}-{peer}-{outer}"
    )
    failed = [name for name, passed in contract.items() if not passed]
    require(not failed, "role/plan binding failed: " + ", ".join(failed))
    ops = ph["operations"]["results"]
    prop = ph["property"]
    teardown = ph["teardown"]
    tids = {"A": ops[0]["caller_tid"], "B": ops[1]["caller_tid"]}
    expected_ops = [{"role": i, "reg": 0, "mask": 1 << i, "value": 1 << i} for i in range(2)]
    require(ph["setup"]["operations"] == expected_ops and ph["setup"]["case_id"] == "disjoint-bits"
            and ph["setup"]["mode"] == "update-bits" and ph["setup"]["fault"] == "none"
            and ph["initial_state"]["values"] == [0, 0, 0, 0], "wrong RAM fixture or initial values")
    require(all(all(actual[key] == value for key, value in expected.items())
                for actual, expected in zip(ops, expected_ops)), "logical update mask or register mismatch")
    require(
        tids["A"] != tids["B"]
        and ops[0]["kernel_pid"] == tids["A"]
        and ops[1]["kernel_pid"] == tids["B"]
        and ph["operations"]["a_calls"] == ph["operations"]["b_calls"] == 1,
        "expected one native update per worker",
    )
    assert all(
        x["status"] == 0 and x["rc"] == 0 and x["checkpoint"] == 1 for x in ops
    ), "operation status"
    assert (
        prop["values"] == [3, 0, 0, 0]
        and prop["passed"] is True
        and teardown["passed"] is True
    ), "final/teardown"
    assert run_json["plan_loaded_from_file"] is True, "plan not loaded"
    assert (
        run_json["A"]["target_matches"] == 1
        and run_json["A"]["wait1"] == 1
        and run_json["A"]["wake0"] == 1
    ), "A target/DI stats"
    assert (
        run_json["A"]["waits"] == 1
        and run_json["A"]["wakes"] == 1
        and run_json["A"]["timeouts"] == 0
    ), "A wait/wake"
    assert run_json["B"]["timeouts"] == 0 and run_json["B"]["target_matches"] == 0, (
        "B control stats"
    )
    assert run_json["gate0"]["called"] is True and run_json["gate0"]["rc"] == 0, "gate0"
    assert (
        run_json["b_completed_wake1"]["called"] is True
        and run_json["b_completed_wake1"]["rc"] == 0
    ), "B wake1"
    assert (
        run_json["a_done"]
        and run_json["b_done"]
        and run_json["child_ok"]
        and run_json["control_valid"]
    ), "run completion"
    plan = load_plan(expected_plan)
    position = check_handoff(run, plan, derived, run_json, slot_roles)
    rows = trace_rows(run)
    calls = [r for r in rows if r["event"] in ("call_enter", "call_exit")]
    require([(r["event"], r["tid"]) for r in calls] ==
            [("call_enter", tids[outer]), ("call_enter", tids[peer]),
             ("call_exit", tids[peer]), ("call_exit", tids[outer])]
            and all("regmap_update_bits_base" in r["detail"] for r in calls),
            "unexpected extra or disjoint native calls")
    outer_enter, peer_enter, peer_exit, outer_exit = calls
    require(outer_enter["ns"] < peer_enter["ns"] < peer_exit["ns"] < outer_exit["ns"], "call interval order")
    upd = [r for r in rows if outer_enter["line"] < r["line"] < outer_exit["line"]
           and r["tid"] in tids.values() and r["event"].startswith("regmap_reg_")]
    seq = [
        (
            ("A" if r["tid"] == tids["A"] else "B"),
            r["event"],
            r.get("reg"),
            r.get("val"),
        )
        for r in upd
    ]
    first_value = 1 if peer == "A" else 2
    expected = [(peer, "regmap_reg_read", 0, 0), (peer, "regmap_reg_write", 0, first_value),
                (outer, "regmap_reg_read", 0, first_value), (outer, "regmap_reg_write", 0, 3)]
    require(seq == expected, f"update access sequence {seq}")
    require(peer_enter["line"] < upd[0]["line"] < upd[1]["line"] < peer_exit["line"] < upd[2]["line"],
            "peer read/write not enclosed in its update or outer resumed too early")
    final = [
        r
        for r in rows
        if r["line"] > outer_exit["line"]
        and r["event"] == "regmap_reg_read"
        and r["tid"] == tids[outer]
    ]
    require([(r.get("reg"),r.get("val")) for r in final] == [(0,3),(1,0),(2,0),(3,0)],
            "expected independent four-register readback by the original slot A after return")
    info = {
        "run": str(run),
        "boot_id": gen_boot(run),
        "kernel_build_id": derived["kernel_build_id"],
        "component_sha256": derived["component_sha256"],
        "executor_sha256": derived["executor_sha256"],
        "plan_sha256": plan["sha256"],
        "target_sha256": sha(expected_plan),
        "tids": tids,
        "target_count": 1,
        "target_stack": plan["stack"],
        "handoff_lines": position,
        "update_sequence": seq,
        "final_read": [(r["reg"], r["val"]) for r in final],
        "call_lines": {
            f"{outer}_enter": outer_enter["line"],
            f"{peer}_enter": peer_enter["line"],
            f"{peer}_exit": peer_exit["line"],
            f"{outer}_exit": outer_exit["line"],
        },
        "run_json": run_json,
    }
    if reference is not None:
        assert info["boot_id"] != reference["boot_id"], "cold replay reused boot"
        assert (
            info["plan_sha256"] == reference["plan_sha256"]
            and info["target_stack"] == reference["target_stack"]
        ), "plan/target differs"
        assert info["update_sequence"] == reference["update_sequence"], (
            "cold update sequence differs"
        )
        assert [x for x in info["final_read"]] == [
            x for x in reference["final_read"]
        ], "cold final differs"
    return info


def gen_boot(run):
    # The guest boot ID is in the serial; the K09 run does not repeat it.
    m = re.search(r"^BOOT ([0-9a-f-]{36})$", (run / "serial.log").read_text(), re.M)
    assert m, "missing boot id"
    return m.group(1)


_COMPONENT_SHA256 = "923c28b1a35cf36141c761a494f355780d078108537b3de00f19b87b755a57ce"
_EXECUTOR_SHA256 = "154fae21ac3203c5a6ce90dca44369facba4b06d87491c983c87889c00dd61ee"


def check_slot(run_dir, frozen_plan_path, direction="ab"):
    """Check one capture against the frozen build and plan.

    The launcher binds the executor and component binaries to these digests.
    The trace checker reads the boot ID, build ID, backend and thread events
    directly from this slot.
    """
    pinned = {
        "kernel_build_id": BUILD_ID,
        "component_sha256": _COMPONENT_SHA256,
        "executor_sha256": _EXECUTOR_SHA256,
    }
    try:
        result = verify(Path(run_dir), Path(frozen_plan_path), pinned, direction=direction)
    except PositionError:
        raise
    except (
        AssertionError,
        OSError,
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        StopIteration,
    ) as exc:
        raise PositionError(
            f"invalid pre-lock capture: {exc or type(exc).__name__}"
        ) from exc

    # Preserve comparable types across an on-disk reference and a fresh capture.
    for field in ("update_sequence", "final_read"):
        result[field] = [list(row) for row in result[field]]
    return result

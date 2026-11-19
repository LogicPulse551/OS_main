"""Pure analysis of the fixed K03 MAccConc dup/close sample evidence.

This module neither runs a guest nor infers a global memory order from clocks.
Its match is the saved A-B-A control point, the observed per-thread fs/file.c
memory-event path, and the dup outcome. It is not a whole-machine replay proof.
Build identity and the one-call test_thread1/test_thread2 source contract are
bound by the caller's evidence manifest, not inferred from these trace files.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


class EvidenceError(ValueError):
    """An evidence file does not satisfy the recorded format."""


_IP = re.compile(r"0x[0-9a-f]{16}\Z")
_WORD = re.compile(r"[0-9a-f]{16}\Z")
_CANDIDATE = re.compile(r"candidate-([0-9]+)\Z")
_DUP = re.compile(r"^dup\(([0-9]+)\)\s*=\s*(-?[0-9]+)\s*\(([^\r\n]*)\)\s*$", re.MULTILINE)
_WIDTH = {"MEMORY": 5, "ENTRY": 2, "EXIT": 1, "NORMAL": 1,
          "EESUM": 1, "WAIT": 1, "WAKE": 1}
_ROLES = {"A": "test_thread1", "B": "test_thread2"}


def _integer(value: Any, name: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise EvidenceError(f"{name}: expected nonnegative integer <= {maximum}")
    return value


def _ip(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IP.fullmatch(value):
        raise EvidenceError(f"{name}: expected canonical 0x + 16 lower-case hex digits")
    return value


def _stack(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise EvidenceError(f"{name}: expected nonempty stack")
    for index, element in enumerate(value):
        if not isinstance(element, dict):
            raise EvidenceError(f"{name}[{index}]: expected object")
        _ip(element.get("ip"), f"{name}[{index}].ip")
        _integer(element.get("parent_idx"), f"{name}[{index}].parent_idx")
    return value


def _stack_key(stack: list[dict[str, Any]]) -> tuple[tuple[str, int], ...]:
    return tuple((entry["ip"], entry["parent_idx"]) for entry in stack)


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: expected JSON object")
    return value


def read_plan(path: str | Path) -> dict[str, Any]:
    """Read the upstream-compatible text plan, including its exact byte hash."""
    data = Path(path).read_bytes()
    tokens = data.decode("ascii").split()
    if len(tokens) < 7 or tokens[0] != "MACCCONC_K03_PLAN_V1" or tokens[1] != "spin_limit" or tokens[3:6] != ["role", "A", "count"]:
        raise EvidenceError("invalid K03 plan header")
    try:
        if not re.fullmatch(r"[0-9]+", tokens[2]) or not re.fullmatch(r"[0-9]+", tokens[6]):
            raise EvidenceError("plan limit/count must use unsigned decimal digits")
        spin_limit, count = int(tokens[2]), int(tokens[6])
        if not 1 <= spin_limit <= 1_000_000_000 or not 2 <= count <= 32 or len(tokens) != 7 + 2 * count:
            raise EvidenceError("invalid plan limit/count or trailing data")
        stack = []
        for index in range(count):
            if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", tokens[7 + 2 * index]) or not re.fullmatch(r"[0-9]+", tokens[8 + 2 * index]):
                raise EvidenceError("invalid stack token syntax")
            raw_ip = int(tokens[7 + 2 * index], 16)
            parent = int(tokens[8 + 2 * index], 10)
            if not 0xFFFFFFFF80000000 <= raw_ip <= 0xFFFFFFFFFFFFFFFF:
                raise EvidenceError("plan IP is outside the fixed x86_64 kernel range")
            _integer(parent, "plan parent_idx")
            stack.append({"ip": f"0x{raw_ip:016x}", "parent_idx": parent})
    except ValueError as exc:
        raise EvidenceError(f"invalid K03 plan: {exc}") from exc
    return {"schema_version": 1, "role": "A", "spin_limit": spin_limit,
            "count": count, "stack": stack, "sha256": hashlib.sha256(data).hexdigest()}


def read_events(run_dir: str | Path, thread: str) -> list[dict[str, Any]]:
    """Read exported events, checking their shape and raw-word offsets.

    The adapter uses the pinned upstream iterator to decode KCOV. This reader
    validates its exported representation; it is not another KCOV decoder.
    """
    if thread not in _ROLES:
        raise EvidenceError("thread must be A or B")
    path = Path(run_dir) / f"{thread}.events.jsonl"
    events: list[dict[str, Any]] = []
    expected_offset = 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("thread") != thread:
                raise EvidenceError("wrong event object/thread")
            kind = event.get("kind")
            if kind not in _WIDTH:
                raise EvidenceError("unknown event kind")
            if _integer(event.get("word_index"), "word_index") != expected_offset:
                raise EvidenceError(f"non-contiguous word_index: expected {expected_offset}")
            expected_offset += _WIDTH[kind]
            _ip(event.get("record_type"), "record_type")
            if kind in ("WAIT", "WAKE"):
                _integer(event.get("flagidx"), "flagidx", 63)
                if type(event.get("timed_out")) is not bool:
                    raise EvidenceError("timed_out must be bool")
                if kind == "WAKE" and event["timed_out"]:
                    raise EvidenceError("WAKE cannot time out")
            elif kind == "EESUM":
                for key in ("delta", "minimum_delta"):
                    if type(event.get(key)) is not int:
                        raise EvidenceError(f"{key} must be int")
            else:
                _ip(event.get("ip"), "ip")
                if kind == "ENTRY":
                    _ip(event.get("caller_ip"), "caller_ip")
                elif kind == "MEMORY":
                    for key in ("address", "value", "timestamp"):
                        _ip(event.get(key), key)
                    if _integer(event.get("size"), "size", (1 << 32) - 1) == 0:
                        raise EvidenceError("zero-sized memory access")
                    _integer(event.get("flags"), "flags", (1 << 32) - 1)
                    _stack(event.get("stack"), "stack")
                    if event["stack"][-1]["ip"] != event["ip"]:
                        raise EvidenceError("memory IP differs from the final stack element")
            events.append(event)
        except (ValueError, KeyError, TypeError) as exc:
            raise EvidenceError(f"{path}:{number}: {exc}") from exc
    return events


def _dup_outcome(run_dir: Path) -> dict[str, Any]:
    output = (run_dir / "testcase.stdout.txt").read_text(encoding="utf-8")
    matches = list(_DUP.finditer(output))
    if len(matches) != 1:
        raise EvidenceError(f"expected exactly one dup outcome, found {len(matches)}")
    match = matches[0]
    fd, result = int(match[1]), int(match[2])
    return {"fd": fd, "result": result, "message": match[3],
            "success": result >= 0, "returned_original_fd": result == fd,
            "matched_line": match[0].strip()}


def _stats(events: list[dict[str, Any]], target: list[dict[str, Any]] | None) -> dict[str, int]:
    result = dict.fromkeys(("events", "memory_records", "waits", "wakes", "wait1",
                           "wake0", "timeouts", "target_matches", "adjacent_target_hits"), 0)
    result["events"] = len(events)
    key = _stack_key(target) if target else None
    for index, event in enumerate(events):
        kind = event["kind"]
        if kind == "MEMORY":
            result["memory_records"] += 1
            if key is not None and _stack_key(event["stack"]) == key:
                result["target_matches"] += 1
                preceding = events[max(0, index - 2):index]
                if len(preceding) == 2 and preceding[0]["kind"] == "WAKE" and preceding[0]["flagidx"] == 0 and preceding[1]["kind"] == "WAIT" and preceding[1]["flagidx"] == 1 and not preceding[1]["timed_out"]:
                    result["adjacent_target_hits"] += 1
        elif kind == "WAIT":
            result["waits"] += 1
            result["wait1"] += event["flagidx"] == 1
            result["timeouts"] += event["timed_out"]
        elif kind == "WAKE":
            result["wakes"] += 1
            result["wake0"] += event["flagidx"] == 0
    return result


def _call_ok(metadata: dict[str, Any], key: str) -> bool:
    call = metadata.get(key)
    return isinstance(call, dict) and call.get("called") is True and type(call.get("rc")) is int and call["rc"] == 0 and type(call.get("errno")) is int and call["errno"] == 0


def _control_checks(metadata: dict[str, Any], events: dict[str, list], plan: dict) -> dict[str, bool]:
    a, b = _stats(events["A"], plan["stack"]), _stats(events["B"], None)
    return {
        "schema": type(metadata.get("schema_version")) is int and metadata["schema_version"] == 1,
        "roles": metadata.get("roles") == _ROLES,
        "controlled_not_sequential": metadata.get("sequential_A_B") is False,
        "declared_control_valid": metadata.get("control_valid") is True,
        "safe_to_continue": metadata.get("safe_to_continue") is True,
        "child_exited_zero": metadata.get("child_ok") is True and type(metadata.get("child_status")) is int and metadata["child_status"] == 0,
        "both_operations_completed": metadata.get("a_done") is True and metadata.get("b_done") is True,
        "reset_succeeded": _call_ok(metadata, "reset"),
        "b_gate0_succeeded": _call_ok(metadata, "gate0"),
        "b_completion_wake1_succeeded": _call_ok(metadata, "b_completed_wake1"),
        "not_overflowed": metadata.get("overflow") is False,
        "declared_raw_well_formed": metadata.get("raw_words_well_formed") is True,
        "spin_limit_matches_plan": type(metadata.get("spin_limit")) is int and metadata["spin_limit"] == plan["spin_limit"],
        "both_memory_traces_nonempty": a["memory_records"] > 0 and b["memory_records"] > 0,
        "a_exactly_one_target": a["target_matches"] == 1,
        "a_exactly_one_adjacent_wake0_wait1_target": a["adjacent_target_hits"] == 1,
        "a_exactly_one_wait1_and_wake0": a["waits"] == a["wait1"] == a["wakes"] == a["wake0"] == 1,
        "neither_trace_timed_out": a["timeouts"] == b["timeouts"] == 0,
        "a_reported_stats_match_events": metadata.get("A") == a,
        "b_reported_stats_match_events": metadata.get("B") == b,
    }


def classify_candidates(record_dir: str | Path) -> list[dict[str, Any]]:
    """Keep every candidate, including partial/failed ones, in numeric order."""
    directories = [(int(match[1]), path) for path in Path(record_dir).iterdir()
                   if path.is_dir() and (match := _CANDIDATE.fullmatch(path.name))]
    candidates = []
    for number, path in sorted(directories, key=lambda item: (item[0], item[1].name)):
        item: dict[str, Any] = {"candidate": number, "dir": str(path), "control_valid": False,
                                "timeout": None, "child_status": None, "child_ok": None,
                                "dup_outcome": None, "errors": []}
        metadata = None
        try:
            metadata = _object(path / "run.json")
        except (OSError, ValueError) as exc:
            item["errors"].append(str(exc))
            try:
                metadata = _object(path / "run.partial.json")
            except (OSError, ValueError) as partial_exc:
                item["errors"].append(str(partial_exc))
        if metadata is not None:
            item["child_status"], item["child_ok"] = metadata.get("child_status"), metadata.get("child_ok")
            item["declared_control_valid"] = metadata.get("control_valid") is True
        try:
            events = {thread: read_events(path, thread) for thread in _ROLES}
            item["timeout"] = any(event["kind"] == "WAIT" and event["timed_out"] for rows in events.values() for event in rows)
            checks = _control_checks(metadata or {}, events, read_plan(path / "plan.txt"))
            item["control_valid"] = all(checks.values())
            item["failed_control_checks"] = [key for key, value in checks.items() if not value]
        except (OSError, ValueError) as exc:
            item["errors"].append(str(exc))
        try:
            item["dup_outcome"] = _dup_outcome(path)
        except (OSError, ValueError) as exc:
            item["errors"].append(str(exc))
        candidates.append(item)
    return candidates


def _raw_consistency(run_dir: Path, thread: str, events: list[dict], metadata: dict) -> dict[str, Any]:
    data = (run_dir / f"{thread}.words").read_bytes()
    words = data.decode("ascii").splitlines()
    valid = all(_WORD.fullmatch(word) for word in words)
    expected_count = sum(_WIDTH[event["kind"]] for event in events)
    recorded_count = metadata.get(f"{thread}_words")
    buffer_words = metadata.get("buffer_words")
    return {"valid": valid and len(words) == expected_count and type(recorded_count) is int and len(words) == recorded_count and type(buffer_words) is int and 0 < recorded_count < buffer_words - 6,
            "raw_count": len(words), "event_word_count": expected_count,
            "reported_count": recorded_count, "sha256": hashlib.sha256(data).hexdigest()}


def _mapping(ip: str, source_map: dict) -> dict[str, Any]:
    mapping = source_map.get(ip)
    if not isinstance(mapping, dict) or mapping.get("found") is not True or not isinstance(mapping.get("file"), str) or not mapping["file"] or type(mapping.get("line")) is not int or mapping["line"] < 0 or not isinstance(mapping.get("symbol"), str) or not mapping["symbol"]:
        raise EvidenceError(f"missing or invalid source mapping for {ip}")
    # Optimized DWARF can identify the containing function/file while explicitly
    # recording line 0. Preserve these events in the path, without inventing a
    # source line. Such a mapping is insufficient for the chosen control target.
    exact = mapping["line"] > 0
    if mapping.get("exact_line") is not exact or mapping.get("mapping_kind") != ("exact_line" if exact else "function_only"):
        raise EvidenceError(f"inconsistent source mapping precision for {ip}")
    return mapping


def _project(events: list[dict], source_map: dict) -> list[dict[str, Any]]:
    projection = []
    for event in events:
        if event["kind"] != "MEMORY":
            continue
        mapping = _mapping(event["ip"], source_map)
        if mapping["file"].replace("\\", "/").endswith("/fs/file.c"):
            # Keep snapshots and dynamic fields for audit; equality below excludes them.
            projection.append({**event, "source": mapping,
                               "value_snapshot_valid": bool(event["flags"] & 0x100)})
    return projection


def _event_identity(event: dict) -> tuple:
    return (event["ip"], event["size"], event["flags"], _stack_key(event["stack"]))


def compare_runs(reference_dir: str | Path, actual_dir: str | Path,
                 plan_path: str | Path, source_map: dict[str, dict]) -> dict[str, Any]:
    """Compare one saved candidate with one real reexecution, failing closed.

    Callers must retain all attempted reexecutions, even when this returns false.
    A successful result applies only to this fixed-sample observed projection.
    """
    result: dict[str, Any] = {
        "schema_version": 1, "passed": False, "checks": {}, "errors": [],
        "differences": [], "counts": {}, "outcomes": {}, "projection": {},
        "scope": "fixed upstream demo-dup-vs-close; saved A-B-A target and ordered per-thread fs/file.c memory-event projection",
        "operation_count_basis": "the externally bound fixed upstream runner calls test_thread1 and test_thread2 once each; roles/completion and one dup stdout line checked here",
        "excluded_from_cross_process_equality": ["address", "timestamp", "value"],
        "value_semantics": "raw snapshots, valid only when flags & 0x100; not write-after values or exact reads-from",
        "ordering_basis": "per-thread event order and checked WAKE0/WAIT1 with successful B gate/completion; no timestamp-derived global order",
    }
    checks = result["checks"]
    try:
        plan = read_plan(plan_path)
        plan_bytes = Path(plan_path).read_bytes()
        result["plan"] = plan
        checks["plan_parsed"] = True
    except (OSError, ValueError) as exc:
        checks["plan_parsed"] = False
        result["errors"].append(str(exc))
        return result
    projections = {}
    for label, directory in (("reference", Path(reference_dir)), ("actual", Path(actual_dir))):
        try:
            metadata = _object(directory / "run.json")
            events = {thread: read_events(directory, thread) for thread in _ROLES}
            checks[f"{label}.evidence_parsed"] = True
            checks.update({f"{label}.{name}": value for name, value in _control_checks(metadata, events, plan).items()})
            checks[f"{label}.plan_bytes_identical"] = (directory / "plan.txt").read_bytes() == plan_bytes
            if label == "actual":
                checks["actual.plan_loaded_from_file"] = metadata.get("plan_loaded_from_file") is True
            result["outcomes"][label] = _dup_outcome(directory)
            result["projection"][label] = {}
            projections[label] = {}
            result["counts"][label] = {}
            for thread in _ROLES:
                raw = _raw_consistency(directory, thread, events[thread], metadata)
                checks[f"{label}.{thread}.raw_count_and_format"] = raw["valid"]
                result["counts"][label][thread] = {**raw, "events": len(events[thread]),
                                                    "memory_records": sum(row["kind"] == "MEMORY" for row in events[thread])}
                projection = _project(events[thread], source_map)
                checks[f"{label}.{thread}.all_memory_sources_resolved"] = True
                checks[f"{label}.{thread}.fs_file_projection_nonempty"] = bool(projection)
                result["counts"][label][thread]["fs_file_memory_records"] = len(projection)
                result["projection"][label][thread] = projection
                projections[label][thread] = projection
            target = [row for row in events["A"] if row["kind"] == "MEMORY" and _stack_key(row["stack"]) == _stack_key(plan["stack"])]
            checks[f"{label}.target_has_exact_source_line"] = len(target) == 1 and _mapping(target[0]["ip"], source_map)["exact_line"] is True and _mapping(target[0]["ip"], source_map)["line"] > 0
        except (OSError, ValueError, KeyError, TypeError) as exc:
            checks[f"{label}.evidence_complete"] = False
            result["errors"].append(f"{label}: {exc}")
    reference, actual = result["outcomes"].get("reference"), result["outcomes"].get("actual")
    checks["reference.successful_original_fd_return"] = bool(reference and reference["success"] and reference["returned_original_fd"] and reference["message"] == "success")
    checks["dup_outcome_matches"] = bool(reference and actual and all(reference[key] == actual[key] for key in ("fd", "result", "message")))
    for thread in _ROLES:
        left, right = projections.get("reference", {}).get(thread), projections.get("actual", {}).get(thread)
        if left is None or right is None:
            checks[f"{thread}.ordered_fs_file_memory_path_matches"] = False
            continue
        differences = []
        for index in range(max(len(left), len(right))):
            before = left[index] if index < len(left) else None
            after = right[index] if index < len(right) else None
            if before is None or after is None or _event_identity(before) != _event_identity(after):
                differences.append({"thread": thread, "projection_index": index,
                                    "reference": before, "actual": after})
        checks[f"{thread}.ordered_fs_file_memory_path_matches"] = not differences
        result["differences"].extend(differences)
    result["counts"]["differences"] = len(result["differences"])
    result["passed"] = bool(checks) and all(checks.values()) and not result["errors"]
    return result

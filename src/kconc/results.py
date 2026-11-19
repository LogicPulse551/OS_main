"""Keep result inspection independent of execution so archived runs stay inspectable."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

MAX_RESULT_BYTES = 8 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACTIONS = {"build", "record", "bind", "replay", "child-exit", "view"}
_STATUSES = {"passed", "failed", "invalid", "unsupported", "interrupted", "read"}


class ResultError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _require(condition: bool, message: str, code: str = "invalid_result") -> None:
    if not condition:
        raise ResultError(code, message)


def _integer(value: Any, name: str, *, minimum: int | None = None) -> int:
    _require(type(value) is int, f"{name} must be an integer, not a boolean")
    _require(minimum is None or value >= minimum, f"{name} is below its minimum")
    return value


def _text(value: Any, name: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{name} must be a nonempty string")
    return value


def _object(value: Any, name: str) -> dict:
    _require(isinstance(value, dict), f"{name} must be an object")
    return value


def _boolean(value: Any, name: str) -> bool:
    _require(type(value) is bool, f"{name} must be a boolean")
    return value


def _hash(value: Any, name: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None,
             f"{name} must be a lower-case SHA256")
    return value


def _checks(value: Any, name: str, passed: bool) -> dict:
    checks = _object(value, name)
    _require(all(type(item) is bool for item in checks.values()), f"{name} values must be booleans")
    if passed:
        _require(bool(checks) and all(checks.values()), f"{name} contradicts passed=true", "inconsistent_result")
    return checks


def _bounded(value: Any, depth: int = 0) -> Any:
    """Keep terminal summaries small even when a record embeds full projections."""
    if isinstance(value, str):
        return value if len(value) <= 2048 else value[:2048] + " [truncated]"
    if isinstance(value, (dict, list)) and depth >= 4:
        return {"omitted_items": len(value)}
    if isinstance(value, dict):
        items = [(key, item) for key, item in value.items()
                 if key not in {"projection", "events", "raw_words"}]
        output = {key: _bounded(item, depth + 1) for key, item in items[:32]}
        if len(items) > 32:
            output["omitted_keys"] = len(items) - 32
        return output
    if isinstance(value, list):
        output = [_bounded(item, depth + 1) for item in value[:32]]
        if len(value) > 32:
            output.append({"omitted_items": len(value) - 32})
        return output
    return value


def _exit_consistent(record: dict, passed: bool, *, required: bool = False) -> None:
    if required or "exit_code" in record:
        code = _integer(record.get("exit_code"), "exit_code")
        _require(not passed or code == 0, "exit_code contradicts passed=true", "inconsistent_result")


def _k02(record: dict, passed: bool) -> tuple[str, str, dict]:
    mode = record.get("mode")
    _require(isinstance(mode, str) and mode in {"full", "transport-only"}, "Unsupported K02 runtime mode", "unsupported_result")
    checks = _checks(record.get("checks"), "checks", passed)
    errors = record.get("errors")
    _require(isinstance(errors, list), "errors must be a list")
    _require(not passed or not errors, "errors contradict passed=true", "inconsistent_result")
    _exit_consistent(record, passed, required=True)
    return "maccconc.k02.runtime", "Recorded K02 runtime check; current environment and referenced artifacts were not revalidated", {
        "mode": mode, "exit_code": record["exit_code"], "check_count": len(checks),
        "failed_checks": [key for key, value in checks.items() if not value], "errors": errors,
        "kernel_release": record.get("expected_kernel_release"),
        "recorded_evidence_directory": record.get("evidence_directory"),
        "k03_scenario_run": record.get("k03_scenario_run"),
    }


def _k03(record: dict, passed: bool) -> tuple[str, str, dict]:
    action = record.get("action")
    _require(isinstance(action, str) and action in _ACTIONS, "Unsupported K03 action", "unsupported_result")
    _exit_consistent(record, passed)
    error = record.get("error")
    if error is not None:
        _object(error, "error")
        _require(not passed, "error contradicts passed=true", "inconsistent_result")
        return f"maccconc.k03.{action}", "Recorded K03 action failure; no execution or environment was revalidated", {"action": action, "error": error}
    scope = "Recorded fixed upstream K03 sample; not kernel bug detection, whole-VM determinism, or a new replay"
    summary: dict = {"action": action}
    if action == "build":
        _exit_consistent(record, passed, required=True)
        summary.update(guest_build=_text(record.get("guest_build"), "guest_build"), exit_code=record["exit_code"])
        scope = "Recorded native K03 adapter build; compilation does not establish controlled execution"
    elif action == "record":
        data = _object(record.get("summary"), "summary")
        names = ("candidate_count", "upstream_injection_failed", "upstream_wait_timeout", "upstream_reordered", "evidence_control_valid")
        counts = {name: _integer(data.get(name), f"summary.{name}", minimum=0) for name in names}
        _require(sum(counts[name] for name in names[1:4]) == counts["candidate_count"],
                 "Candidate totals are inconsistent", "inconsistent_result")
        _require(counts["evidence_control_valid"] <= counts["upstream_reordered"],
                 "Strict control count exceeds reordered count", "inconsistent_result")
        _require(not passed or counts["evidence_control_valid"] > 0,
                 "No strict control success despite passed=true", "inconsistent_result")
        summary.update(counts)
    elif action == "bind":
        binding = _object(record.get("binding"), "binding")
        candidate = _text(record.get("candidate"), "candidate")
        _require(candidate == binding.get("candidate"), "Candidate differs from binding", "inconsistent_result")
        _object(binding.get("identity"), "binding.identity")
        summary.update(candidate=candidate, plan_sha256=_hash(binding.get("plan_sha256"), "binding.plan_sha256"),
                       recorded_identity=binding["identity"], selection=binding.get("selection"))
        scope = "Recorded control-plan binding; saved hashes and current artifacts were not revalidated"
    elif action == "replay":
        comparison = _object(record.get("comparison"), "comparison")
        matched = _boolean(comparison.get("passed"), "comparison.passed")
        checks = _checks(comparison.get("checks"), "comparison.checks", matched)
        errors, differences = comparison.get("errors"), comparison.get("differences")
        _require(isinstance(errors, list) and isinstance(differences, list), "comparison errors/differences must be lists")
        _require(not matched or not errors and not differences,
                 "Comparison errors/differences contradict passed=true", "inconsistent_result")
        _require(not passed or matched, "Comparison contradicts outer passed=true", "inconsistent_result")
        counts = _object(comparison.get("counts"), "comparison.counts")
        summary.update(comparison_passed=matched, check_count=len(checks),
                       failed_checks=[key for key, value in checks.items() if not value],
                       errors=errors, difference_count=len(differences), counts=counts,
                       outcomes=comparison.get("outcomes"), recorded_scope=comparison.get("scope"))
    elif action == "child-exit":
        run = _object(record.get("run"), "run")
        child_ok = _boolean(run.get("child_ok"), "run.child_ok")
        control = _boolean(run.get("control_valid"), "run.control_valid")
        status = _integer(run.get("child_status"), "run.child_status")
        _require(not passed or not child_ok and not control and status == 7 << 8,
                 "Negative fixture outcome contradicts passed=true", "inconsistent_result")
        summary.update(child_status=status, child_ok=child_ok, control_valid=control,
                       negative_fixture_rejected=passed)
        scope = "Infrastructure negative test: passed means setup _exit(7) was rejected; not a kernel bug finding"
    else:
        _require(record.get("mode") == "archived-trace-view-only", "Unknown K03 view mode", "unsupported_result")
        _require(record.get("ui_verified") is False, "K03 view only confirms transport, not GUI verification", "inconsistent_result")
        summary.update(mode=record["mode"], frame_bytes=_integer(record.get("frame_bytes"), "frame_bytes", minimum=20),
                       frame_sha256=_hash(record.get("frame_sha256"), "frame_sha256"),
                       trace=_text(record.get("trace"), "trace"), ui_verified=False)
        scope = "Archived trace transmission only; no testcase execution, replay, or GUI inspection is established"
    return f"maccconc.k03.{action}", scope, summary


def _envelope(record: dict) -> tuple[bool | None, str, dict]:
    _require(type(record.get("schema_version")) is int and record["schema_version"] == 1, "Unsupported kconc.run schema version")
    status = record.get("status")
    _require(isinstance(status, str) and status in _STATUSES, "Unknown kconc.run status")
    _require("operation" in record, "operation must be present, even when an early failure leaves it null")
    operation = record["operation"]
    if operation is not None or status in {"passed", "read"}:
        operation = _text(operation, "operation")
    code = _integer(record.get("exit_code"), "exit_code")
    error = record.get("error")
    _require("error" in record and (error is None or isinstance(error, dict)), "error must be an object or null")
    data = _object(record.get("data"), "data")
    scope = _text(record.get("result_scope"), "result_scope")
    if status in {"passed", "read"}:
        _require(code == 0 and error is None, "Successful kconc.run status contradicts exit_code/error", "inconsistent_result")
    else:
        _require(code != 0, "Unsuccessful kconc.run status has exit_code zero", "inconsistent_result")
    return None if status == "read" else status == "passed", scope, {
        "operation": operation, "status": status, "exit_code": code, "error": error, "data": data,
        "read_status_meaning": "Successfully read historical evidence, not a new verification" if status == "read" else None,
    }


def _lifecycle(record: dict) -> tuple[bool, str, dict]:
    """Read the recorded classification without rerunning its classifier or guest."""
    _require(type(record.get("schema_version")) is int and record["schema_version"] == 1,
             "Unsupported lifecycle result schema version")
    passed = _boolean(record.get("passed"), "passed")
    _text(record.get("scope"), "scope")
    _exit_consistent(record, passed)
    if record.get("error") is not None:
        _object(record["error"], "error")
        _require(not passed, "error contradicts passed=true", "inconsistent_result")
    if record["kind"] == "kconc.runtime":
        _text(record.get("operation"), "operation")
        scope = "Recorded lifecycle operation; current runtime readiness and recovery were not revalidated"
    else:
        classification = _object(record.get("classification"), "classification")
        classified_passed = _boolean(classification.get("passed"), "classification.passed")
        needs_recovery = _boolean(classification.get("recovery_required"), "classification.recovery_required")
        axes = {
            "execution": {"controlled_completed", "timeout", "cancelled", "failed"},
            "control": {"hit", "wait_timeout", "not_hit", "unknown"},
            "property": {"holds", "violated", "not_evaluated"},
            "trace": {"valid", "overflow", "invalid", "missing"},
            "cleanup": {"clean", "failed", "unconfirmed"},
        }
        for axis, choices in axes.items():
            value = classification.get(axis)
            _require(isinstance(value, str) and value in choices, "Unknown classification." + axis)
        _require(needs_recovery == (classification["cleanup"] != "clean"),
                 "Recovery requirement contradicts cleanup classification", "inconsistent_result")
        if classified_passed:
            expected = {"execution": "controlled_completed", "control": "hit", "property": "holds",
                        "trace": "valid", "cleanup": "clean"}
            _require(all(classification[key] == value for key, value in expected.items()) and not needs_recovery,
                     "Classification axes contradict passed=true", "inconsistent_result")
        _require(not passed or classified_passed, "Classification contradicts outer passed=true", "inconsistent_result")
        scope = "Recorded fixed dup/close lifecycle result; no new execution, recovery, or kernel bug finding is established"
    return passed, scope, {key: value for key, value in record.items() if key not in {"kind", "schema_version"}}


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    output = {}
    for key, value in pairs:
        _require(key not in output, f"Duplicate JSON key: {key}")
        output[key] = value
    return output


def _constant(value: str) -> None:
    raise ResultError("invalid_result", f"Non-finite JSON constant is not supported: {value}")


def _float(value: str) -> float:
    parsed = float(value)
    _require(math.isfinite(parsed), "Non-finite JSON number is not supported")
    return parsed


def read_result(path: Path, backend_exit_code: int | None = None) -> dict:
    """Summarize one known record. No referenced artifact or current VM is checked."""
    if backend_exit_code is not None:
        _integer(backend_exit_code, "backend_exit_code")
    try:
        source = Path(path).expanduser().resolve(strict=True)
        _require(source.is_file(), "Result path must identify a regular file", "result_io_error")
        with source.open("rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode), "Result path must identify a regular file", "result_io_error")
            _require(info.st_size <= MAX_RESULT_BYTES, "Result exceeds the 8 MiB input limit", "result_too_large")
            raw = stream.read(MAX_RESULT_BYTES + 1)
        _require(len(raw) <= MAX_RESULT_BYTES, "Result exceeds the 8 MiB input limit", "result_too_large")
    except OSError as error:
        raise ResultError("result_io_error", str(error)) from error
    try:
        record = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ResultError):
            raise
        raise ResultError("invalid_result", f"Cannot decode result JSON: {error}") from error
    _object(record, "result")
    if record.get("kind") == "kconc.run":
        passed, scope, summary = _envelope(record)
        kind = "kconc.run"
    elif record.get("kind") in ("kconc.scenario", "kconc.runtime"):
        passed, scope, summary = _lifecycle(record)
        kind = record["kind"]
    else:
        if record.get("task") == "K02" and "mode" in record:
            handler = _k02
        elif "action" in record:
            handler = _k03
        else:
            raise ResultError("unsupported_result", "Unrecognized result kind; build/identity/trace records are not passed results")
        passed = _boolean(record.get("passed"), "passed")
        kind, scope, summary = handler(record, passed)
    if backend_exit_code is not None:
        success_reported = passed or kind == "kconc.run" and record["status"] == "read"
        _require(not success_reported or backend_exit_code == 0,
                 "Backend exit code contradicts reported success", "inconsistent_result")
    return {"kind": kind, "reported_passed": passed, "scope": _bounded(scope),
            "summary": _bounded(summary),
            "source": {"path": str(source), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
            "revalidated": False}

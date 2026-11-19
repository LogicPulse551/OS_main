"""Classify one fixed K04 round without executing or repairing anything.

The lifecycle protocol is team code. Control and raw-trace validation remain in
the pinned K03 analyzer, called by the host adapter before this classifier.
Each axis retains its own evidence boundary: a timeout is not a kernel bug,
and a successful property check cannot establish that cleanup succeeded.
"""
from __future__ import annotations

from typing import Any


SCENARIO = {
    "id": "dup-close-v1",
    "roles": {"A": "dup(test_fd)", "B": "close(test_fd)"},
    "oracle": "legal-dup-close-result",
    "resources": "Child-process file descriptor set; explicit declared-FD cleanup and FD-set equality",
    "scope": "Lifecycle validation around the real upstream dup/close sample; not regmap or kernel bug discovery",
}
PHASES = ("setup", "initial_state", "operations", "property", "teardown")
FAULTS = frozenset({"none", "setup", "hang", "cleanup", "property"})
OUTCOMES = frozenset({"completed", "timeout", "cancelled", "execution_failed"})


def classify(guest: dict, run: dict | None, analysis: dict | None = None) -> dict:
    """Return separate execution, control, property, trace and cleanup verdicts.

    ``analysis`` is a host-normalized report with strict ``trace_valid`` and
    ``control_valid`` booleans plus ``errors: list[str]``. These come from the
    existing analyzer, not from trusting the guest's aggregate success flag.
    Missing or malformed inputs fail closed and remain reportable via issues.
    No cleanup, replay or proof is performed by reading these records.
    """
    issues: list[str] = []
    malformed: list[str] = []

    def invalid(message: str) -> None:
        malformed.append(message)
        issues.append("invalid_evidence: " + message)

    def flag(obj: dict, key: str, label: str) -> bool | None:
        value = obj.get(key)
        if type(value) is not bool:
            invalid(label + " must be a boolean")
            return None
        return value

    def integer(value: Any, label: str, minimum: int | None = None) -> int | None:
        if type(value) is not int or (minimum is not None and value < minimum):
            invalid(label + " must be an integer" + (f" >= {minimum}" if minimum is not None else ""))
            return None
        return value

    if not isinstance(guest, dict):
        invalid("guest must be an object")
        guest = {}
    if guest.get("kind") != "kconc.guest":
        invalid("guest.kind must be kconc.guest")
    if type(guest.get("schema_version")) is not int or guest.get("schema_version") != 1:
        invalid("guest.schema_version must be integer 1")
    outcome = guest.get("outcome")
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        invalid("guest.outcome is unknown")
        outcome = "execution_failed"
    exit_code = guest.get("exit_code")
    if exit_code is not None:
        exit_code = integer(exit_code, "guest.exit_code")
    elif outcome == "completed":
        invalid("completed guest requires exit_code")
    completed = outcome == "completed" and type(exit_code) is int and exit_code == 0
    if outcome == "completed" and not completed:
        issues.append("guest_completion_exit_mismatch")

    fault = guest.get("fault", "none")
    if not isinstance(fault, str) or fault not in FAULTS:
        invalid("guest.fault is unknown")
        fault = "unknown"
    infrastructure_fault = fault != "none"
    remaining = guest.get("remaining_pids")
    if not isinstance(remaining, list) or any(type(pid) is not int or pid <= 0 for pid in remaining):
        invalid("remaining_pids must be a list of positive integer PIDs")
        no_remaining = False
    else:
        no_remaining = not remaining
        if remaining:
            issues.append("remaining_guest_processes")
    local_cleanup = guest.get("local_cleanup")
    processes_confirmed = False
    if not isinstance(local_cleanup, dict):
        invalid("guest.local_cleanup must be an object")
    else:
        confirmed = flag(local_cleanup, "confirmed", "guest.local_cleanup.confirmed")
        errors = local_cleanup.get("errors")
        if not isinstance(errors, list) or any(not isinstance(item, str) for item in errors):
            invalid("guest.local_cleanup.errors must be a list of strings")
        else:
            processes_confirmed = confirmed is True and not errors and no_remaining
            if not processes_confirmed:
                issues.append("guest_process_cleanup_unconfirmed")
    phase_errors = guest.get("phase_errors")
    if not isinstance(phase_errors, list) or any(not isinstance(item, str) for item in phase_errors):
        invalid("phase_errors must be a list of strings")
        phase_errors = ["malformed phase_errors"]
    if phase_errors:
        issues.append("phase_parse_errors")

    rows = guest.get("phases")
    phase_map: dict[str, dict] = {}
    names: list[str] = []
    if not isinstance(rows, list):
        invalid("phases must be a list")
        rows = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("phase") not in PHASES:
            invalid(f"phase[{index}] is not a known phase object")
            continue
        name = row["phase"]
        if name in phase_map:
            invalid("duplicate phase: " + name)
            continue
        phase_map[name] = row
        names.append(name)
        flag(row, "passed", "phase." + name + ".passed")
        for marker in ("injected", "oracle_test_only"):
            if marker in row:
                value = flag(row, marker, "phase." + name + "." + marker)
                infrastructure_fault |= value is True
    if names != sorted(names, key=PHASES.index):
        invalid("lifecycle phases are out of order")
    phases_complete = tuple(names) == PHASES and len(rows) == len(PHASES)
    if not phases_complete:
        issues.append("incomplete_lifecycle")
    operations = phase_map.get("operations", {})
    operation_counts = False
    if operations:
        a = integer(operations.get("a_calls"), "operations.a_calls", 0)
        b = integer(operations.get("b_calls"), "operations.b_calls", 0)
        operation_counts = a == b == 1
        if not operation_counts:
            issues.append("logical_operation_count_mismatch")
    prop = phase_map.get("property", {})
    if prop and prop.get("oracle") != SCENARIO["oracle"]:
        invalid("property oracle does not match this scenario")

    run_present = isinstance(run, dict)
    run_flags: dict[str, bool | None] = {}
    reset_ok = False
    wait_timeout = False
    if run is not None and not run_present:
        invalid("run must be an object or null")
    if run_present:
        for key in ("control_valid", "overflow", "raw_words_well_formed", "child_ok",
                    "a_done", "b_done", "safe_to_continue"):
            run_flags[key] = flag(run, key, "run." + key)
        reset = run.get("reset")
        if not isinstance(reset, dict):
            invalid("run.reset must be an object")
        else:
            called = flag(reset, "called", "run.reset.called")
            rc = integer(reset.get("rc"), "run.reset.rc")
            reset_errno = integer(reset.get("errno"), "run.reset.errno", 0)
            reset_ok = called is True and rc == 0 and reset_errno == 0
        for role in ("A", "B"):
            stats = run.get(role)
            if not isinstance(stats, dict):
                invalid("run." + role + " must be an object")
                continue
            count = integer(stats.get("timeouts"), "run." + role + ".timeouts", 0)
            wait_timeout |= count is not None and count > 0
        if "gate0" in run:
            gate = run["gate0"]
            if not isinstance(gate, dict):
                invalid("run.gate0 must be an object")
            else:
                called = flag(gate, "called", "run.gate0.called")
                rc = integer(gate.get("rc"), "run.gate0.rc")
                gate_errno = integer(gate.get("errno"), "run.gate0.errno", 0)
                # The fixed Linux guest ABI uses ETIMEDOUT=110. This ioctl
                # may time out before an event enters either trace buffer.
                wait_timeout |= called is True and rc is not None and rc < 0 and gate_errno == 110
        if run_flags.get("control_valid") is True and (wait_timeout or run_flags.get("overflow") is True):
            invalid("control_valid contradicts wait timeout or trace overflow")
        if run_flags.get("safe_to_continue") is True and not (
                run_flags.get("child_ok") is True and run_flags.get("a_done") is True
                and run_flags.get("b_done") is True and reset_ok):
            invalid("safe_to_continue contradicts child/operation/reset evidence")

    analyzed_trace = analyzed_control = False
    analysis_errors: list[str] = []
    if analysis is None:
        issues.append("raw_analysis_missing")
    elif not isinstance(analysis, dict):
        invalid("analysis must be an object or null")
    else:
        analyzed_trace = flag(analysis, "trace_valid", "analysis.trace_valid") is True
        analyzed_control = flag(analysis, "control_valid", "analysis.control_valid") is True
        analysis_errors = analysis.get("errors")
        if not isinstance(analysis_errors, list) or any(not isinstance(item, str) for item in analysis_errors):
            invalid("analysis.errors must be a list of strings")
            analysis_errors = ["malformed analysis.errors"]
        if analysis_errors:
            issues.append("raw_analysis_errors")

    trace = "missing"
    if run_present:
        if run_flags.get("overflow") is True:
            trace = "overflow"
        elif run_flags.get("raw_words_well_formed") is True and analyzed_trace and not analysis_errors:
            trace = "valid"
        else:
            trace = "invalid"
    control = "unknown"
    if wait_timeout:
        control = "wait_timeout"
    elif run_present and trace == "valid":
        control = "hit" if run_flags.get("control_valid") is True and analyzed_control else "not_hit"
    if malformed:
        # Malformed evidence cannot establish either positive observation.
        if trace == "valid":
            trace = "invalid"
        if control == "hit":
            control = "unknown"

    both_done = run_flags.get("a_done") is True and run_flags.get("b_done") is True
    child_ok = run_flags.get("child_ok") is True
    if outcome == "cancelled":
        execution = "cancelled"
    elif outcome == "timeout" or wait_timeout:
        execution = "timeout"
    elif completed and child_ok and both_done and control == "hit" and not malformed:
        execution = "controlled_completed"
    else:
        execution = "failed"

    initialization_ok = all(phase_map.get(name, {}).get("passed") is True for name in ("setup", "initial_state"))
    operations_ok = operations.get("passed") is True and operation_counts
    lifecycle_valid = phases_complete and not phase_errors and not malformed
    property_status = "not_evaluated"
    if (lifecycle_valid and initialization_ok and operations_ok and execution == "controlled_completed"
            and trace == "valid" and type(prop.get("passed")) is bool):
        property_status = "holds" if prop["passed"] else "violated"

    teardown = phase_map.get("teardown", {})
    if teardown.get("passed") is False or (isinstance(remaining, list) and remaining):
        cleanup = "failed"
    elif (lifecycle_valid and completed and child_ok and both_done and initialization_ok and operations_ok
            and reset_ok and run_flags.get("safe_to_continue") is True and processes_confirmed
            and teardown.get("passed") is True):
        cleanup = "clean"
    else:
        cleanup = "unconfirmed"

    for axis, value, wanted in (("execution", execution, "controlled_completed"), ("control", control, "hit"),
                                ("trace", trace, "valid"), ("property", property_status, "holds"),
                                ("cleanup", cleanup, "clean")):
        if value != wanted:
            issues.append(axis + ":" + value)
    passed = (execution == "controlled_completed" and control == "hit" and trace == "valid"
              and property_status == "holds" and cleanup == "clean" and not issues)
    return {
        "schema_version": 1, "kind": "kconc.scenario-classification", "scenario_id": SCENARIO["id"],
        "execution": execution, "control": control, "property": property_status, "trace": trace,
        "cleanup": cleanup, "passed": passed, "recovery_required": cleanup != "clean",
        "infrastructure_fault": infrastructure_fault, "kernel_bug_claim": False,
        "phases_complete": phases_complete, "evidence_valid": not malformed,
        "guest_outcome": outcome, "issues": list(dict.fromkeys(issues)),
        "scope": SCENARIO["scope"],
    }

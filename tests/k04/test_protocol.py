"""Offline protocol fixtures; these tests do not run or certify a kernel."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kconc.scenario_protocol import PHASES, SCENARIO, classify


def evidence():
    guest = {"schema_version": 1, "kind": "kconc.guest", "outcome": "completed", "exit_code": 0,
             "remaining_pids": [], "local_cleanup": {"confirmed": True, "errors": []},
             "phase_errors": [], "fault": "none", "phases": [
                 {"phase": "setup", "passed": True},
                 {"phase": "initial_state", "passed": True},
                 {"phase": "operations", "passed": True, "a_calls": 1, "b_calls": 1},
                 {"phase": "property", "passed": True, "oracle": SCENARIO["oracle"]},
                 {"phase": "teardown", "passed": True}]}
    # Real K03 keys, but synthetic values: not a historical or actual execution.
    run = {"control_valid": True, "overflow": False, "raw_words_well_formed": True,
           "child_ok": True, "a_done": True, "b_done": True, "safe_to_continue": True,
           "reset": {"called": True, "rc": 0, "errno": 0},
           "A": {"timeouts": 0}, "B": {"timeouts": 0}}
    analysis = {"trace_valid": True, "control_valid": True, "errors": []}
    return guest, run, analysis


class ProtocolTests(unittest.TestCase):
    def test_complete_round_keeps_axes_separate(self):
        result = classify(*evidence())
        self.assertTrue(result["passed"])
        self.assertEqual([result[key] for key in ("execution", "control", "property", "trace", "cleanup")],
                         ["controlled_completed", "hit", "holds", "valid", "clean"])
        self.assertFalse(result["recovery_required"])
        self.assertFalse(result["kernel_bug_claim"])

    def test_property_failure_does_not_imply_cleanup_failure(self):
        guest, run, analysis = evidence()
        guest["phases"][3].update(passed=False, injected=True, oracle_test_only=True)
        guest["fault"] = "property"
        result = classify(guest, run, analysis)
        self.assertEqual((result["property"], result["cleanup"]), ("violated", "clean"))
        self.assertFalse(result["passed"])
        self.assertFalse(result["recovery_required"])
        self.assertTrue(result["infrastructure_fault"])
        self.assertFalse(result["kernel_bug_claim"])

    def test_trace_overflow_is_not_a_property_violation(self):
        guest, run, analysis = evidence()
        run.update(overflow=True, control_valid=False)
        analysis.update(trace_valid=False, control_valid=False)
        result = classify(guest, run, analysis)
        self.assertEqual(result["trace"], "overflow")
        self.assertEqual(result["property"], "not_evaluated")
        self.assertEqual(result["cleanup"], "clean")
        self.assertFalse(result["passed"])

    def test_control_wait_timeout_is_not_program_deadlock(self):
        guest, run, analysis = evidence()
        run["A"]["timeouts"] = 1
        run["control_valid"] = False
        analysis["control_valid"] = False
        result = classify(guest, run, analysis)
        self.assertEqual((result["execution"], result["control"], result["property"]),
                         ("timeout", "wait_timeout", "not_evaluated"))
        self.assertEqual(result["trace"], "valid")
        self.assertFalse(result["kernel_bug_claim"])

    def test_missed_control_is_different_from_bad_trace(self):
        guest, run, analysis = evidence()
        run["control_valid"] = analysis["control_valid"] = False
        result = classify(guest, run, analysis)
        self.assertEqual((result["control"], result["trace"]), ("not_hit", "valid"))
        self.assertFalse(result["passed"])

    def test_gate_ioctl_timeout_without_recorded_wait_is_classified_as_timeout(self):
        guest, run, analysis = evidence()
        guest.update(outcome="execution_failed", exit_code=1)
        run.update(control_valid=False, gate0={"called": True, "rc": -1, "errno": 110})
        analysis["control_valid"] = False
        self.assertEqual((run["A"]["timeouts"], run["B"]["timeouts"]), (0, 0))
        result = classify(guest, run, analysis)
        self.assertEqual((result["execution"], result["control"]), ("timeout", "wait_timeout"))
        self.assertEqual(result["trace"], "valid")
        self.assertEqual(result["property"], "not_evaluated")
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["recovery_required"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["kernel_bug_claim"])

    def test_gate_ioctl_fields_reject_boolean_integer_substitution(self):
        for field, value in (("called", 1), ("rc", False), ("errno", True)):
            guest, run, analysis = evidence()
            run["gate0"] = {"called": True, "rc": 0, "errno": 0}
            run["gate0"][field] = value
            with self.subTest(field=field):
                result = classify(guest, run, analysis)
                self.assertFalse(result["evidence_valid"])
                self.assertFalse(result["passed"])
                self.assertTrue(result["recovery_required"])

    def test_host_timeout_with_partial_lifecycle_requires_recovery(self):
        guest, _, _ = evidence()
        guest.update(outcome="timeout", exit_code=-15, phases=guest["phases"][:2], fault="hang")
        result = classify(guest, None)
        self.assertEqual((result["execution"], result["trace"], result["cleanup"]),
                         ("timeout", "missing", "unconfirmed"))
        self.assertTrue(result["recovery_required"])

    def test_cancelled_round_never_infers_cleanup_from_empty_process_list(self):
        guest, _, _ = evidence()
        guest.update(outcome="cancelled", exit_code=-9, phases=guest["phases"][:2])
        result = classify(guest, None)
        self.assertEqual(result["execution"], "cancelled")
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["recovery_required"])

    def test_cleanup_failure_survives_other_success(self):
        guest, run, analysis = evidence()
        guest["phases"][-1]["passed"] = False
        guest.update(outcome="execution_failed", exit_code=73, fault="cleanup")
        run.update(child_ok=False, safe_to_continue=False)
        result = classify(guest, run, analysis)
        self.assertEqual(result["cleanup"], "failed")
        self.assertTrue(result["recovery_required"])

    def test_remaining_process_blocks_ready_even_with_complete_cleanup_claim(self):
        guest, run, analysis = evidence()
        guest["remaining_pids"] = [1234]
        result = classify(guest, run, analysis)
        self.assertEqual(result["cleanup"], "failed")
        self.assertFalse(result["passed"])
        self.assertTrue(result["recovery_required"])

    def test_known_setup_failure_is_not_malformed_but_not_ready(self):
        guest, run, analysis = evidence()
        guest.update(outcome="execution_failed", exit_code=71, fault="setup")
        guest["phases"] = [{"phase": "setup", "passed": False}, {"phase": "teardown", "passed": True}]
        run.update(child_ok=False, a_done=False, b_done=False, safe_to_continue=False, control_valid=False)
        run["reset"].update(called=False, rc=-999)
        analysis.update(control_valid=False)
        result = classify(guest, run, analysis)
        self.assertTrue(result["evidence_valid"])
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["recovery_required"])

    def test_local_cleanup_uncertainty_blocks_even_with_empty_pid_list(self):
        guest, run, analysis = evidence()
        guest["local_cleanup"] = {"confirmed": False, "errors": ["process identity lookup failed"]}
        result = classify(guest, run, analysis)
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["recovery_required"])
        self.assertFalse(result["passed"])

    def test_local_cleanup_true_with_errors_is_not_a_confirmation(self):
        guest, run, analysis = evidence()
        guest["local_cleanup"] = {"confirmed": True, "errors": ["could not inspect descendant"]}
        result = classify(guest, run, analysis)
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertTrue(result["recovery_required"])

    def test_wrong_order_duplicate_or_missing_phase_cannot_pass(self):
        for mutation in ("out_of_order", "duplicate", "missing"):
            guest, run, analysis = evidence()
            if mutation == "out_of_order":
                guest["phases"][0], guest["phases"][1] = guest["phases"][1], guest["phases"][0]
            elif mutation == "duplicate":
                guest["phases"].append(copy.deepcopy(guest["phases"][-1]))
            else:
                guest["phases"].pop(1)
            with self.subTest(mutation=mutation):
                result = classify(guest, run, analysis)
                self.assertFalse(result["passed"])
                self.assertTrue(result["recovery_required"])

    def test_wrong_role_call_count_is_not_a_complete_scenario(self):
        guest, run, analysis = evidence()
        guest["phases"][2]["a_calls"] = 2
        result = classify(guest, run, analysis)
        self.assertEqual(result["property"], "not_evaluated")
        self.assertEqual(result["cleanup"], "unconfirmed")

    def test_wrong_property_oracle_cannot_be_substituted(self):
        guest, run, analysis = evidence()
        guest["phases"][3]["oracle"] = "always-success"
        result = classify(guest, run, analysis)
        self.assertFalse(result["evidence_valid"])
        self.assertFalse(result["passed"])

    def test_strict_bool_integer_boundary(self):
        cases = (
            ("exit_code", True), ("pid", True), ("calls", True),
            ("phase_passed", 1), ("run_passed", 1), ("reset_rc", False),
            ("timeouts", False), ("analysis", 1), ("schema", True),
        )
        for name, replacement in cases:
            guest, run, analysis = evidence()
            if name == "exit_code": guest["exit_code"] = replacement
            elif name == "pid": guest["remaining_pids"] = [replacement]
            elif name == "calls": guest["phases"][2]["a_calls"] = replacement
            elif name == "phase_passed": guest["phases"][0]["passed"] = replacement
            elif name == "run_passed": run["control_valid"] = replacement
            elif name == "reset_rc": run["reset"]["rc"] = replacement
            elif name == "timeouts": run["A"]["timeouts"] = replacement
            elif name == "analysis": analysis["trace_valid"] = replacement
            elif name == "schema": guest["schema_version"] = replacement
            with self.subTest(field=name):
                result = classify(guest, run, analysis)
                self.assertFalse(result["passed"])
                self.assertFalse(result["evidence_valid"])
                self.assertTrue(result["recovery_required"])

    def test_no_raw_analysis_cannot_establish_success(self):
        guest, run, _ = evidence()
        result = classify(guest, run)
        self.assertEqual(result["trace"], "invalid")
        self.assertEqual(result["control"], "unknown")
        self.assertFalse(result["passed"])
        self.assertEqual(result["cleanup"], "clean")

    def test_raw_errors_do_not_change_into_a_kernel_bug(self):
        guest, run, analysis = evidence()
        analysis["errors"] = ["A: raw count differs from exported events"]
        result = classify(guest, run, analysis)
        self.assertEqual(result["trace"], "invalid")
        self.assertEqual(result["property"], "not_evaluated")
        self.assertFalse(result["passed"])

    def test_contradictory_safe_to_continue_cannot_clear_dirty_state(self):
        guest, run, analysis = evidence()
        run["reset"]["rc"] = -1
        result = classify(guest, run, analysis)
        self.assertFalse(result["evidence_valid"])
        self.assertTrue(result["recovery_required"])

    def test_completed_nonzero_exit_is_not_completed_execution(self):
        guest, run, analysis = evidence()
        guest["exit_code"] = 9
        result = classify(guest, run, analysis)
        self.assertEqual(result["execution"], "failed")
        self.assertTrue(result["recovery_required"])

    def test_phase_parse_errors_block_cleanup_and_property_certainty(self):
        guest, run, analysis = evidence()
        guest["phase_errors"] = ["Malformed KCONC_PHASE JSON"]
        result = classify(guest, run, analysis)
        self.assertEqual(result["property"], "not_evaluated")
        self.assertEqual(result["cleanup"], "unconfirmed")
        self.assertFalse(result["passed"])

    def test_unknown_types_and_missing_fields_fail_closed_without_throwing(self):
        for guest, run, analysis in ((None, None, None), ({}, {}, {}), ([], [], [])):
            with self.subTest(guest=guest):
                result = classify(guest, run, analysis)
                self.assertFalse(result["passed"])
                self.assertTrue(result["recovery_required"])
                self.assertTrue(result["issues"])

    def test_classifier_does_not_modify_input_or_claim_proof(self):
        original = evidence()
        saved = copy.deepcopy(original)
        result = classify(*original)
        self.assertEqual(original, saved)
        self.assertFalse(result["kernel_bug_claim"])
        self.assertEqual(tuple(row["phase"] for row in original[0]["phases"]), PHASES)


if __name__ == "__main__":
    unittest.main()

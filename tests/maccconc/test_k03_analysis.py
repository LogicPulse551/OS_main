"""K03 evidence rejection tests, independent of a guest or kernel build.

Run from the repository: python -B -m unittest discover -s tests/maccconc -v
These are synthetic export-format fixtures, not recorded kernel evidence.
The raw placeholders test length/format checks, not the upstream KCOV decoder.
"""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[2] / "adapters/maccconc/k03_analysis.py"
spec = importlib.util.spec_from_file_location("k03_analysis", MODULE)
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="k03-analysis-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.reference, self.actual = self.base / "reference", self.base / "actual"
        self.target_ip, self.other_ip = "0xffffffff81858758", "0xffffffff8185817e"
        self.stack = [{"ip": "0xffffffff81858000", "parent_idx": 0},
                      {"ip": self.target_ip, "parent_idx": 1}]
        self.plan = self.base / "saved-plan.txt"
        self.plan.write_text("MACCCONC_K03_PLAN_V1\nspin_limit 1000000\nrole A\ncount 2\nffffffff81858000 0\nffffffff81858758 1\n", encoding="ascii")
        self.mapping = {
            ip: {"found": True, "file": "/source/linux/fs/file.c", "line": line,
                 "symbol": symbol, "exact_line": True, "mapping_kind": "exact_line"}
            for ip, line, symbol in ((self.target_ip, 1037, "__fget_files_rcu"),
                                     (self.other_ip, 727, "file_close_fd_locked"))
        }
        memory = {"kind": "MEMORY", "record_type": "0x3000000000000000",
                  "ip": self.target_ip, "address": "0xffff000000000001",
                  "size": 8, "flags": 256, "value": "0xffff000000000002",
                  "timestamp": "0x0000000000000003", "stack": self.stack}
        other = {**memory, "ip": self.other_ip,
                 "stack": [self.stack[0], {"ip": self.other_ip, "parent_idx": 1}]}
        a = [{"kind": "WAKE", "record_type": "0x5000000000000000", "flagidx": 0,
              "timed_out": False, "thread": "A", "word_index": 0},
             {"kind": "WAIT", "record_type": "0x4000000000000000", "flagidx": 1,
              "timed_out": False, "thread": "A", "word_index": 1},
             {**memory, "thread": "A", "word_index": 2}]
        b = [{**other, "thread": "B", "word_index": 0}]
        a_stats = {"events": 3, "memory_records": 1, "waits": 1, "wakes": 1,
                   "wait1": 1, "wake0": 1, "timeouts": 0, "target_matches": 1,
                   "adjacent_target_hits": 1}
        b_stats = {"events": 1, "memory_records": 1, "waits": 0, "wakes": 0,
                   "wait1": 0, "wake0": 0, "timeouts": 0, "target_matches": 0,
                   "adjacent_target_hits": 0}
        for directory, loaded in ((self.reference, False), (self.actual, True)):
            directory.mkdir()
            (directory / "plan.txt").write_bytes(self.plan.read_bytes())
            metadata = {
                "schema_version": 1, "roles": {"A": "test_thread1", "B": "test_thread2"},
                "sequential_A_B": False, "plan_loaded_from_file": loaded,
                "spin_limit": 1000000, "child_status": 0, "child_ok": True,
                "a_done": True, "b_done": True,
                "reset": {"called": True, "rc": 0, "errno": 0},
                "gate0": {"called": True, "rc": 0, "errno": 0},
                "b_completed_wake1": {"called": True, "rc": 0, "errno": 0},
                "overflow": False, "raw_words_well_formed": True,
                "control_valid": True, "safe_to_continue": True, "buffer_words": 1000,
                "A_words": 7, "B_words": 5, "A": a_stats, "B": b_stats,
            }
            for thread, rows, count in (("A", a, 7), ("B", b, 5)):
                self.write_events(directory, thread, rows)
                (directory / f"{thread}.words").write_text("0000000000000000\n" * count, encoding="ascii")
            (directory / "run.json").write_text(json.dumps(metadata), encoding="utf-8")
            (directory / "testcase.stdout.txt").write_text("dup(5) = 5 (success)\n", encoding="utf-8")

    @staticmethod
    def write_events(directory, thread, rows):
        (directory / f"{thread}.events.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def compare(self):
        return analysis.compare_runs(self.reference, self.actual, self.plan, self.mapping)

    def mutate_event(self, thread, index, key, value):
        path = self.actual / f"{thread}.events.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[index][key] = value
        self.write_events(self.actual, thread, rows)

    def mutate_metadata(self, key, value):
        path = self.actual / "run.json"
        data = json.loads(path.read_text())
        data[key] = value
        path.write_text(json.dumps(data), encoding="utf-8")

    def make_function_only(self, ip):
        self.mapping[ip].update(line=0, exact_line=False, mapping_kind="function_only")

    def test_dynamic_values_are_preserved_but_not_compared(self):
        for key, value in (("value", "0xffff000000000099"),
                           ("address", "0xffff000000000098"),
                           ("timestamp", "0x0000000000000001")):
            self.mutate_event("A", 2, key, value)
        result = self.compare()
        self.assertTrue(result["passed"], result)
        self.assertNotEqual(result["projection"]["reference"]["A"][0]["value"],
                            result["projection"]["actual"]["A"][0]["value"])

    def test_plan_byte_change_rejected(self):
        with (self.actual / "plan.txt").open("a", encoding="ascii") as file:
            file.write("\n")
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.plan_bytes_identical"])

    def test_timeout_rejected_despite_declared_success(self):
        self.mutate_event("A", 1, "timed_out", True)
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.neither_trace_timed_out"])

    def test_target_occurrence_mismatch_rejected(self):
        stack = copy.deepcopy(self.stack)
        stack[0]["parent_idx"] += 1
        self.mutate_event("A", 2, "stack", stack)
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.a_exactly_one_target"])

    def test_b_path_change_rejected(self):
        self.mutate_event("B", 0, "size", 4)
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertEqual(result["counts"]["differences"], 1)

    def test_missing_mapping_rejected(self):
        del self.mapping[self.other_ip]
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertTrue(result["errors"])

    def test_failed_reset_rejected(self):
        self.mutate_metadata("reset", {"called": True, "rc": -1, "errno": 5})
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.reset_succeeded"])

    def test_replay_flag_rejected(self):
        self.mutate_metadata("plan_loaded_from_file", False)
        self.assertFalse(self.compare()["passed"])

    def test_raw_truncation_rejected(self):
        (self.actual / "B.words").write_text("0000000000000000\n" * 4, encoding="ascii")
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.B.raw_count_and_format"])

    def test_multiple_dup_outcomes_rejected(self):
        (self.actual / "testcase.stdout.txt").write_text("dup(5) = 5 (success)\n" * 2)
        self.assertFalse(self.compare()["passed"])

    def test_candidate_classification_preserves_failure(self):
        self.reference.rename(self.base / "candidate-000010")
        self.actual.rename(self.base / "candidate-000002")
        (self.base / "candidate-000001").mkdir()
        rows = analysis.classify_candidates(self.base)
        self.assertEqual([row["candidate"] for row in rows], [1, 2, 10])
        self.assertFalse(rows[0]["control_valid"])
        self.assertTrue(rows[0]["errors"])
        self.assertTrue(rows[1]["control_valid"])

    def test_function_only_mapping_keeps_event_and_still_compares_path(self):
        self.make_function_only(self.other_ip)
        result = self.compare()
        self.assertTrue(result["passed"], result)
        self.assertEqual(len(result["projection"]["actual"]["B"]), 1)
        self.assertEqual(result["projection"]["actual"]["B"][0]["source"]["line"], 0)
        self.mutate_event("B", 0, "size", 4)
        changed = self.compare()
        self.assertFalse(changed["passed"])
        self.assertFalse(changed["checks"]["B.ordered_fs_file_memory_path_matches"])

    def test_function_only_target_rejected(self):
        self.make_function_only(self.target_ip)
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["actual.target_has_exact_source_line"])

    def test_function_only_mapping_without_symbol_rejected(self):
        self.make_function_only(self.other_ip)
        self.mapping[self.other_ip]["symbol"] = ""
        self.assertFalse(self.compare()["passed"])

    def test_line_zero_cannot_claim_exact_location(self):
        self.mapping[self.other_ip]["line"] = 0
        result = self.compare()
        self.assertFalse(result["passed"])
        self.assertTrue(any("precision" in error for error in result["errors"]))

    def test_missing_precision_fields_rejected(self):
        del self.mapping[self.other_ip]["exact_line"]
        self.assertFalse(self.compare()["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

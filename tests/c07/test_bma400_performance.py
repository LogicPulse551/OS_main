import copy
import itertools
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kconc.bma400_performance import ARMS, summarize


ORDERS = list(itertools.permutations(ARMS))


def rows(skip=(90,) * 6):
    result = []
    for r, order in enumerate(ORDERS, 1):
        for arm in order:
            for phase, count in (("warmup", 2), ("measured", 4)):
                for batch in range(1, count + 1):
                    ns = {"original": 100, "cached": 97, "skip-noop": skip[r - 1]}[arm] if phase == "measured" else 400
                    result.append(dict(round=r, variant=arm, phase=phase, batch=batch, calls=20000, elapsed_ns=20000 * ns))
    return result


class Bma400TimingTests(unittest.TestCase):
    def test_exact_pairs_warmups_and_ci(self):
        actual = summarize(rows(), ORDERS)
        self.assertIs(actual["value_gate_passed"], True)
        self.assertEqual(actual["planned_batches"], 108)
        self.assertEqual(actual["inference_pairs_per_comparison"], 24)
        self.assertEqual(actual["distributions"]["original"]["max"], 100)
        self.assertEqual(actual["comparisons"]["primary"]["bootstrap_draws"], 46656)
        for val in actual["comparisons"]["primary"]["reduction_95_pct_interval"]:
            self.assertAlmostEqual(val, 10)
        self.assertEqual(actual["comparisons"]["primary"]["saved_ns_per_call_95_interval"], [10, 10])
        self.assertAlmostEqual(actual["comparisons"]["secondary"]["reduction_percent"], 3)

    def test_missing_warmup_excludes_whole_round(self):
        actual = summarize(rows()[1:], ORDERS)
        self.assertEqual(actual["excluded_rounds"], [1])
        self.assertEqual(actual["inference_pairs_per_comparison"], 20)
        self.assertEqual(actual["missing_batches"][0]["phase"], "warmup")
        self.assertIs(actual["pairs"][0]["included"], False)
        self.assertEqual(actual["pairs"][0]["ns_per_call"]["original"], 100)

    def test_too_few_rounds(self):
        actual = summarize(rows()[36:], ORDERS)
        self.assertFalse(actual["eligible"])
        self.assertIsNone(actual["value_gate_passed"])
        self.assertEqual(actual["comparisons"], {})
        self.assertEqual(actual["inference_pairs_per_comparison"], 0)
        self.assertTrue(all(not p["included"] for p in actual["pairs"]))

    def test_positive_point_with_uncertain_interval(self):
        actual = summarize(rows((60, 60, 60, 120, 120, 120)), ORDERS)
        self.assertGreater(actual["comparisons"]["primary"]["reduction_percent"], 5)
        self.assertLess(actual["comparisons"]["primary"]["reduction_95_pct_interval"][0], 0)
        self.assertFalse(actual["value_gate_passed"])

    def test_negative_and_small_positive_effects(self):
        for ns in (104, 98):
            with self.subTest(ns=ns):
                actual = summarize(rows((ns,) * 6), ORDERS)
                self.assertTrue(actual["eligible"])
                self.assertFalse(actual["value_gate_passed"])
                self.assertAlmostEqual(actual["comparisons"]["primary"]["reduction_percent"], 100 - ns)

    def test_reject_mistyped_duplicate_and_unregistered_input(self):
        data = rows()
        with self.assertRaises(ValueError):
            summarize([*data, data[-1]], ORDERS)
        with self.assertRaises(ValueError):
            summarize(data, ORDERS[:5] + [ORDERS[0]])
        for key, value in (("calls", True), ("calls", 0), ("elapsed_ns", 0), ("elapsed_ns", 100.), ("batch", True)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                altered = copy.deepcopy(data)
                altered[0][key] = value
                summarize(altered, ORDERS)

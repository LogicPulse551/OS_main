from collections import Counter
from itertools import permutations
from math import factorial
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc.multi_regmap import plan_cases, verify_case


def depth(order):
    return sum(a != b for a, b in zip(order, order[1:]))


class PlanTests(unittest.TestCase):
    def test_independent_enumeration_and_depth_cutoff(self):
        expected = set(permutations((0, 0, 1, 1, 2, 2)))
        for maximum in range(7):
            plan = plan_cases(3, maximum)
            orders = {tuple(x) for x in plan["orders"]}
            self.assertEqual(orders, {s for s in expected if depth(s) <= maximum})
            self.assertEqual(len(orders), len(plan["orders"]))
            self.assertEqual(plan["counts_by_depth"], Counter(map(depth, expected)))

    def test_all_sizes_and_small_budgets(self):
        for n in range(2, 6):
            expected = factorial(2 * n) // (2 ** n)
            for budget in (0, 1, 2, n, 2 * n, 35):
                plan = plan_cases(n, 2 * n - 1, budget)
                selected = min(budget, expected)
                observed = list(plan["orders"])
                self.assertEqual(observed, list(plan["orders"]))
                self.assertEqual(plan["total_eligible"], expected)
                self.assertEqual(plan["selected"], selected)
                self.assertEqual(plan["unexplored"], expected - selected)
                self.assertEqual(len({tuple(o) for o in observed}), selected)
                self.assertEqual(len({o[0] for o in observed}), min(selected, n))
                if budget >= 2:
                    self.assertEqual([depth(o) for o in observed[:2]], [2 * n - 1, n - 1])

    def test_budget_prefix_and_full_stream(self):
        small = list(plan_cases(5, 8, 24)["orders"])
        self.assertEqual(small, list(plan_cases(5, 8, 50)["orders"])[:24])
        plan = plan_cases(5, 9)
        self.assertNotIsInstance(plan["orders"], list)
        self.assertEqual(len(plan["orders"]), 113400)
        self.assertEqual(plan["counts_by_depth"],
                         {4: 120, 5: 1200, 6: 6600, 7: 22200, 8: 43800, 9: 39480})
        seen = bytearray((5 ** 10 + 7) // 8)
        counts = Counter()
        for order in plan["orders"]:
            self.assertEqual(Counter(order), {i: 2 for i in range(5)})
            key = 0
            for role in order:
                key = 5 * key + role
            byte, bit = divmod(key, 8)
            self.assertFalse(seen[byte] & (1 << bit))
            seen[byte] |= 1 << bit
            counts[depth(order)] += 1
        self.assertEqual(counts, plan["counts_by_depth"])

    def test_first_schedule_per_deep_and_shallow_stratum(self):
        for n in range(2, 6):
            first_round = plan_cases(n, 2 * n - 1, n * (n + 1))["orders"]
            first_order = {}
            for order in first_round:
                first_order.setdefault((depth(order), order[0]), order)
            for first in range(n):
                rotation = [(first + i) % n for i in range(n)]
                self.assertEqual(first_order[(2*n-1, first)], rotation * 2)
                shallow = first_order[(n-1, first)]
                self.assertEqual(shallow[::2], shallow[1::2])
                self.assertEqual(set(shallow[::2]), set(range(n)))

    def test_invalid_arguments(self):
        for args in ((1, 1, 1), (6, 1, 1), (3, -1, None), (3, True, None), (3, 4, False), (3, 3, -1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                plan_cases(*args)


class VerifyTests(unittest.TestCase):
    order = [0, 1, 0, 2, 1, 2]
    values = [0, 1, 3, 2, 6, 4, 0]

    def fixture(self):
        return [dict(step=i, role=r, pid=100 + r, before=self.values[i], after=self.values[i+1], rc=0)
                for i, r in enumerate(self.order)]

    def test_verified(self):
        result = verify_case(3, self.order, self.fixture(), 0)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["switches"], 5)
        self.assertEqual(result["pids"], {"0": 100, "1": 101, "2": 102})

    def test_incorrect_middle_even_when_final_is_correct(self):
        for i, key, bad in ((1, "pid", 100), (2, "pid", 111), (4, "step", 0), (4, "role", 0),
                            (3, "before", 0), (1, "after", 4), (5, "rc", -5), (2, "pid", True)):
            rows = self.fixture()
            rows[i][key] = bad
            with self.subTest(i=i, key=key), self.assertRaises(ValueError):
                verify_case(3, self.order, rows, 0)

    def test_malformed_observation_count_schedule_and_final(self):
        rows = self.fixture()
        for order, events, final in ((self.order, rows[:-1], 0), (self.order, rows, 1),
                                     (self.order, rows, False), ([0,1,2,0,1,0], rows, 0)):
            with self.assertRaises(ValueError):
                verify_case(3, order, events, final)


if __name__ == "__main__":
    unittest.main()

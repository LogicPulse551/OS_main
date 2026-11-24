from copy import deepcopy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import iio_path as scan


def sample(key, axis, reg, begin):
    op = scan.Read(key, axis, begin + 10, 2, 0, 0, 2, begin=begin, end=begin + 3)
    op.driver = ["drivers/iio/demo/test.c::sample"]
    op.regmap = [["regmap_hw_read_start", {"reg": reg}],
                 ["regmap_hw_read_done", {"reg": reg}]]
    return op


class IIOPaths(unittest.TestCase):
    def setUp(self):
        self.samples = [sample(str(i), axis, reg, 10 * i + 1) for i, (axis, reg) in
                        enumerate((("X", "a"), ("Y", "e"), ("Y", "e"), ("X", "a")))]
        self.meta = {key: "a" * (40 if key.endswith("build_id") else 64) for key in scan.IDENTITY}
        self.meta["boot_id"] = "716658e9-cc9f-4e00-a93e-9709753b901c"
        self.rows = {op.key: op for op in self.samples}
        self.ref = scan.train(self.meta, self.rows, {}, {})

    def test_path_learns_from_middle_with_identical_returns(self):
        self.assertFalse(self.ref["driver_path_distinguishes_axes"])
        self.assertTrue(scan.compare(self.ref, self.samples[:2], "XY")["passed"])
        self.assertTrue(scan.compare(self.ref, self.samples[2:], "YX")["passed"])
        self.assertTrue(scan.negative_checks(self.ref, self.samples[:2], "XY")["passed"])
        wrong = deepcopy(self.samples[:2])
        wrong[0].regmap = deepcopy(wrong[1].regmap)
        result = scan.compare(self.ref, wrong, "XY")
        self.assertFalse(result["passed"])
        self.assertEqual(result["observations"][0]["identified_by_path"], ["Y"])

    def test_overlapping_or_opposite_order_is_rejected(self):
        self.samples[0].end = self.samples[1].begin + 2
        self.assertFalse(scan.compare(self.ref, self.samples[:2], "XY")["passed"])
        self.assertFalse(scan.compare(self.ref, self.samples[1::-1], "YX")["passed"])

    def test_inconsistent_group_and_uninformative_middle(self):
        self.samples[3].regmap.reverse()
        with self.assertRaisesRegex(ValueError, "unstable"):
            scan.train(self.meta, self.rows, {}, {})
        for op in self.samples:
            op.regmap = self.samples[0].regmap
        with self.assertRaisesRegex(ValueError, "does not distinguish"):
            scan.train(self.meta, self.rows, {}, {})

    def test_ignore_other_tids_and_return_values_inside_middle_events(self):
        op = scan.Read("q", "X", 44, 2, 0, 0, 2)
        rows = ["t-44 [001] .... 1.1: tracing_mark_write: IIO_BEGIN key=q axis=X",
                "t-55 [001] .... 1.2: regmap_hw_read_start: other reg=aa",
                "t-44 [001] .... 1.3: regmap_reg_read: device reg=ee val=ef",
                "t-44 [001] .... 1.4: tracing_mark_write: IIO_END key=q axis=X rc=0 value=0"]
        scan.attach_trace("\n".join(rows), {"q": op})
        self.assertEqual(op.regmap, [["regmap_reg_read", {"reg": "ee"}]])
        rows[3] = rows[3].replace("value=0", "value=10")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            scan.attach_trace("\n".join(rows), {"q": scan.Read("q", "X", 44, 2, 0, 0, 2)})

    def test_three_axes_learned_and_middle_paths_exchanged(self):
        # All endpoints and values coincide. Changing just the regmap events
        # must identify the other axis even on a different traversal order.
        regs = {"X": "ce", "Y": "1b", "Z": "b4"}
        ops = [sample(str(i), axis, regs[axis], i * 10 + 1)
               for i, axis in enumerate("XYZZYX")]
        meta = dict(self.meta, mode="train3")
        ref = scan.train(meta, {op.key: op for op in ops}, {}, {})
        self.assertEqual(ref["schema"], scan.THREE_AXIS_SCHEMA)
        for pair, order in ((ops[:3], "XYZ"), (ops[3:], "ZYX")):
            result = scan.compare(ref, pair, order)
            self.assertTrue(result["passed"])
            self.assertEqual([op["identified_by_path"] for op in result["observations"]],
                             [[axis] for axis in order])
            control = scan.negative_checks(ref, pair, order)
            self.assertTrue(control["passed"])
            wrong = control["exchanged_regmap_paths"]["observations"]
            for op, observation in zip(pair, wrong):
                self.assertEqual(observation["returned"], op.returned())
                self.assertEqual(observation["identified_by_path"], [{"X": "X", "Y": "Z", "Z": "Y"}[op.axis]])
        ops[2].tid = ops[1].tid
        self.assertFalse(scan.compare(ref, ops[:3], "XYZ")["passed"])
        ops[2].tid += 1
        ops[2].begin = ops[1].end
        self.assertFalse(scan.compare(ref, ops[:3], "XYZ")["passed"])

    def test_three_axis_reference_rejects_missing_or_indistinguishable_z(self):
        meta = dict(self.meta, mode="train3")
        with self.assertRaisesRegex(ValueError, "missing"):
            scan.train(meta, self.rows, {}, {})
        for index in (61, 71):
            op = sample(str(index), "Z", "e", index)
            self.rows[op.key] = op
        with self.assertRaisesRegex(ValueError, "does not distinguish"):
            scan.train(meta, self.rows, {}, {})

    def test_entry_decoding_skips_payload_and_rejects_active_hooks(self):
        words = (0x00ffffff81001000, 0, 0x3000000000000000, 0, 0, 0, 0, 0x1000000000000000)
        self.assertEqual(scan.entry_pcs(struct.pack("<8Q", *words), 8), ["0xffffffff81001000"])
        for raw in ((0x4000000000000000,), (0x3000000000000000,)):
            with self.assertRaises(ValueError):
                scan.entry_pcs(struct.pack("<Q", *raw), 1)


if __name__ == "__main__":
    unittest.main()

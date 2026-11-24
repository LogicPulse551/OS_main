"""Keep the two independent driver entries inside the same submitted SPI message."""
import unittest
from dataclasses import replace

import three
from inspect_overlap import Event


def event(line, tid, name):
    return Event(line, 10 * line, tid, name, "")


def fixture():
    ops, control = {}, {}
    for i, axis in enumerate(three.AXES):
        tid = 101 + i
        start = 10 * (i + 1)
        entry = (5, 12, 13)[i]
        ops[axis] = {
            "axis": axis, "tid": tid, "regmap": [axis], "size": 2, "rc": 0, "value": 0,
            "payload": "00 00", "entry": event(entry, tid, "entry"),
            "spi": {"submit": event(start, tid, "submit"), "start": event(start + 5, tid, "start"),
                    "done": event(start + 6, tid, "done"), "length": 3, "dev": "spi0.0"},
        }
        prefix = axis.lower()
        control.update({prefix + "_key": prefix + "3", prefix + "_tid": str(tid), prefix + "_exit": "0"})
    control.update(callback_tid="101", state_before="0", state_armed="1", state_observed="2",
                   state_after="3", y_state="2", z_state="2", arm_ns="1", warming_seen_ns="2",
                   y_started_ns="4", z_started_ns="3", joined_ns="5")
    return ops, control


class ThreeReaders(unittest.TestCase):
    def test_no_order_required_between_peers(self):
        ops, control = fixture()
        ops["Z"]["entry"] = replace(ops["Z"]["entry"], ns=ops["Y"]["entry"].ns)
        self.assertTrue(three.assess(ops, control, ops)["passed"])

    def test_one_matching_reader_is_insufficient(self):
        ops, control = fixture()
        ops["Z"]["entry"] = replace(ops["Z"]["entry"], ns=ops["X"]["spi"]["submit"].ns)
        result = three.assess(ops, control, ops)
        self.assertFalse(result["passed"])
        self.assertEqual({"Y": True, "Z": False}, result["per_peer"])
        self.assertTrue(all(result["readouts_matched"].values()))

    def test_strict_line_order_too(self):
        ops, _ = fixture()
        ops["Y"]["entry"] = replace(ops["Y"]["entry"], line=ops["X"]["spi"]["start"].line)
        self.assertFalse(three.assess_window(ops)["strict_window"])

    def test_no_reader_alias(self):
        ops, _ = fixture()
        ops["Z"]["tid"] = ops["Y"]["tid"]
        with self.assertRaisesRegex(ValueError, "TIDs"):
            three.group(ops, three.AXES)

    def test_all_unchanged_data_counterexamples(self):
        ops, control = fixture()
        self.assertTrue(three.assess(ops, control, ops)["passed"])
        negatives = three.negative_controls(ops, control, ops)
        self.assertEqual(5, len(negatives))
        for record in negatives.values():
            self.assertFalse(record["passed"])
            self.assertTrue(all(record["readouts_matched"].values()))


if __name__ == "__main__":
    unittest.main()

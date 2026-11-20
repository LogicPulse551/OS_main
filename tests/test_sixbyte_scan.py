"""Candidate discovery is broader than admission to a reviewed SPI profile."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import sixbyte_scan


class ScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.kernel = Path(tmp.name)

    def write(self, rel, data):
        path = self.kernel / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8"))
        return path

    def test_arbitrary_driver_source_discovered_without_profile(self):
        raw = """/* µ */
#define XYZ_BYTES 6
void readit(void) {
    regmap_bulk_read(map, reg(i, j), &buf[aliased(i,j)], XYZ_BYTES);
    regmap_bulk_read(map, a, buf, 6U);
    regmap_bulk_read(map, a, buf, user_count);
    regmap_bulk_read(map, a, buf, 2);
}
"""
        path = self.write("drivers/new/bus.c", raw)
        result = sixbyte_scan.scan(self.kernel)
        rows = result["candidates"]
        self.assertEqual([r["length"] for r in rows], [6, 6, None])
        self.assertTrue(all(r["decision"] == "keep_original" for r in rows))
        self.assertTrue(all(r["byte_length"] is None for r in rows))
        self.assertEqual(result["coverage"]["direct_four_argument_sites"], 4)
        self.assertEqual(result["coverage"]["other_value_counts"], 1)
        self.assertEqual(rows[0]["args"][1], "reg(i, j)")
        self.assertEqual(path.read_bytes()[rows[0]["offset"]:rows[0]["end_offset"]],
                         b"regmap_bulk_read(map, reg(i, j), &buf[aliased(i,j)], XYZ_BYTES)")

    def test_comments_strings_and_multiline_comment_continuations_are_not_reads(self):
        source = (
            '/* regmap_bulk_read(m,r,b,6) */\n'
            'char *s = "regmap_bulk_read(m,r,b,6)";\n'
            '// continuation \\\nregmap_bulk_read(m,r,b,6);\n'
            'regmap_bulk_read(/* ignored (, */ m, r, b, 0x6);\n'
        )
        self.write("drivers/a.c", source)
        rows = sixbyte_scan.scan(self.kernel)["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["line"], 5)
        self.assertEqual(rows[0]["length"], 6)

    def test_changed_caller_and_missing_identity_are_retained(self):
        self.write(sixbyte_scan.KX_CORE,
                   "regmap_bulk_read(data->regmap, data->chip_info->xout_l, "
                   "data->buffer, KX022A_FIFO_SAMPLES_SIZE_BYTES);\n")
        row, = sixbyte_scan.scan(self.kernel, sixbyte_scan.KX_CORE)["candidates"]
        self.assertEqual(row["profile"], "kx022a-spi")
        self.assertEqual(row["reason"], "source_binding_mismatch")
        self.assertEqual(row["decision"], "keep_original")
        self.assertIn(sixbyte_scan.KX_CORE, row["mismatched_inputs"])
        self.assertIn("drivers/base/regmap/regmap.c", row["mismatched_inputs"])

    def test_lookalike_named_caller_in_other_directory_is_never_accepted(self):
        self.write("drivers/other/bma400_core.c",
                   "regmap_bulk_read(data->regmap, BMA400_ACC_X_LSB_REG, "
                   "&data->buffer.buff, sizeof(data->buffer.buff));\n")
        row, = sixbyte_scan.scan(self.kernel)["candidates"]
        self.assertIsNone(row["profile"])
        self.assertEqual(row["decision"], "keep_original")

    def test_ambiguous_macro_is_unresolved(self):
        self.write("drivers/b.c", "#ifdef X\n#define N 4\n#else\n#define N 6\n#endif\n"
                                  "regmap_bulk_read(m,r,b,N);\n")
        row, = sixbyte_scan.scan(self.kernel)["candidates"]
        self.assertIsNone(row["length"])

    def test_outside_driver_scope_not_followed(self):
        self.write("drivers/a.c", "regmap_bulk_read(m,r,b,6);")
        self.write("elsewhere/b.c", "regmap_bulk_read(m,r,b,6);")
        with self.assertRaises(ValueError):
            sixbyte_scan.scan(self.kernel, "drivers/../elsewhere")


if __name__ == "__main__":
    unittest.main()

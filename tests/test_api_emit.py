import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import api_emit as emit


class AdmittedCallLowering(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.tree = Path(temp.name)
        self.name = "drivers/unit/byte_ranges.c"
        # Token fragments only; the analyzer separately decides their ownership.
        self.data = (b"regmap_bulk_read(m, 2, b, 6);\r\n"
                     b"regmap_bulk_read(m, 3, b, n);\r\n"
                     b"regmap_bulk_read(m, 4294967295U, b, 6);\r\n")
        path = self.tree / self.name
        path.parent.mkdir(parents=True)
        path.write_bytes(self.data)
        self.row = {"decision": "admit", "register": 2, "source": self.name, "offset": 0,
                    "source_sha256": hashlib.sha256(self.data).hexdigest()}
        mocked = patch.object(emit, "framework_overlay", side_effect=lambda _: {emit.REGMAP: b"runtime"})
        self.runtime = mocked.start()
        self.addCleanup(mocked.stop)

    def test_ranges_are_original_byte_offsets(self):
        last = dict(self.row, offset=self.data.rindex(emit.ORIGINAL), register=0xffffffff)
        overlay = emit.emit_overlay(self.tree, [last, self.row])
        lines = self.data.splitlines(keepends=True)
        lines[0] = lines[0].replace(emit.ORIGINAL, emit.ENTRY)
        lines[2] = lines[2].replace(emit.ORIGINAL, emit.ENTRY)
        self.assertEqual(overlay, {self.name: b"".join(lines), emit.REGMAP: b"runtime"})
        self.assertEqual((self.tree / self.name).read_bytes(), self.data)

    def test_invalid_scope_or_evidence_rejects_all_edits(self):
        changes = [{"decision": "reject"}, {"source_sha256": "f" * 64},
                   {"offset": 1}, {"offset": -1}, {"offset": True},
                   {"source": "drivers/../unit/byte_ranges.c"},
                   {"register": -1}, {"register": 1 << 32}, {"register": True}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                emit.emit_overlay(self.tree, [dict(self.row, **change)])
        with self.assertRaises(ValueError):
            emit.emit_overlay(self.tree, [self.row, self.row])

    def test_no_admissions_skip_the_framework_too(self):
        self.assertEqual(emit.emit_overlay(self.tree, []), {})
        self.runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()

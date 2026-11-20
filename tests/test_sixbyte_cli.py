"""Public CLI behavior for unknown drivers and for output isolation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ENTRY = Path(__file__).resolve().parents[1] / "kconc.py"


class SixByteCommandTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.kernel = self.base / "linux"
        self.driver = self.kernel / "drivers/meter.c"
        self.driver.parent.mkdir(parents=True)
        self.content = b"int sample(void) { return regmap_bulk_read(m, start, buf, 6); }\n"
        self.driver.write_bytes(self.content)

    def invoke(self, target, *extra):
        p = subprocess.run([sys.executable, "-B", str(ENTRY), "optimize", "--kernel", str(self.kernel),
                            "--config", str(self.base / "absent.config"), "--output", str(target), *extra],
                           capture_output=True, encoding="utf-8")
        return p.returncode, json.loads(p.stdout)

    def test_unknown_six_value_read_keeps_actual_source(self):
        out = self.base / "out"
        code, result = self.invoke(out, "--materialize")
        self.assertEqual(code, 0)
        self.assertEqual(result["decision"], "keep_original")
        self.assertEqual(result["files"], {})
        self.assertEqual((out / "linux.patch").read_bytes(), b"")
        self.assertEqual((out / "linux/drivers/meter.c").read_bytes(), self.content)
        self.assertEqual(self.driver.read_bytes(), self.content)
        row, = json.loads((out / "scan.json").read_bytes())["candidates"]
        self.assertEqual((row["length"], row["byte_length"], row["action"]), (6, None, "keep_original"))

    def test_output_cannot_be_inside_input(self):
        out = self.kernel / "overlay"
        code, result = self.invoke(out)
        self.assertEqual((code, result["error"]["code"]), (2, "invalid_output"))
        self.assertFalse(out.exists())

    def test_refuses_to_overwrite_a_prior_output(self):
        out = self.base / "old"
        out.mkdir()
        code, result = self.invoke(out)
        self.assertEqual((code, result["error"]["code"]), (2, "output_exists"))
        self.assertEqual(list(out.iterdir()), [])

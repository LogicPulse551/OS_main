"""Check the public fallback and compatibility routes without a kernel toolchain."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ENTRY = Path(__file__).resolve().parents[1] / "kconc.py"


class PolicyTest(unittest.TestCase):
    def checks(self, options, expected):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            src = base / "src"
            (src / "drivers").mkdir(parents=True)
            path = src / "drivers" / "source.c"
            original = b"int f(void){ return regmap_bulk_read(p, 1, buf, 6); }\n"
            path.write_bytes(original)
            out = base / "output"
            command = [sys.executable, "-B", str(ENTRY), "optimize", "--kernel", str(src),
                       "--config", str(base/"missing.config"), "--output", str(out), "--materialize", *options]
            p = subprocess.run(command, check=True, capture_output=True)
            result = json.loads(p.stdout)
            self.assertEqual(result["policy"], expected)
            self.assertEqual(result["decision"], "keep_original")
            self.assertEqual((out / "linux.patch").read_bytes(), b"")
            self.assertEqual((out / "linux/drivers/source.c").read_bytes(), original)
            row, = json.loads((out/"scan.json").read_bytes())["candidates"]
            self.assertEqual(row["action"], "keep_original")

    def test_explicit_source_policy_without_a_build(self):
        self.checks(["--policy", "private-api"], "private-api")

    def test_build_context_selects_source_analysis(self):
        self.checks(["--build-dir", "absent-build"], "private-api")

    def test_earlier_source_only_command(self):
        self.checks([], "registered")

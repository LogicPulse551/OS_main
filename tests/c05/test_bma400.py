"""The original source is always recoverable when the scoped source cannot be issued."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[2] / "scripts/optimization/bma400.py"
UNIT = Path("drivers/base/regmap/regmap.c")


class FallbackTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.tree = self.root / "input"
        self.original = self.tree / UNIT
        self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b"/* A different kernel revision. */\r\n")
        self.out = self.root / "result"

    def run_command(self, *args, tool=TOOL):
        unused = str(self.root / "unavailable")
        return subprocess.run([sys.executable, "-B", str(tool), "--kernel-tree", str(self.tree),
                               "--output", str(self.out), "--clang", unused, "--config", unused,
                               "--compcert", unused, "--coq-bin", unused, *args], capture_output=True)

    def test_source_drift_preserves_exact_original(self):
        self.assertEqual(self.run_command().returncode, 3)
        result = json.loads((self.out / "result.json").read_text())
        self.assertEqual(result["decision"], "original_fallback")
        self.assertEqual(result["reason"], "original regmap.c differs")
        self.assertEqual((self.out / "package/original" / UNIT).read_bytes(), self.original.read_bytes())
        self.assertFalse((self.out / "package/optimized").exists())
        self.assertFalse((self.out / "package/certificate.json").exists())

    def test_observation_uses_original_without_proof_tools(self):
        self.assertEqual(self.run_command("--mode", "observe").returncode, 0)
        result = json.loads((self.out / "result.json").read_text())
        self.assertEqual(result["decision"], "original_selected")
        self.assertFalse(result["kernel_install_allowed"])
        self.assertFalse((self.out / "work/proof").exists())

    def test_retry_keeps_previous_output(self):
        self.assertEqual(self.run_command("--mode", "original").returncode, 0)
        before = (self.out / "result.json").read_bytes()
        self.assertEqual(self.run_command().returncode, 1)
        self.assertEqual((self.out / "result.json").read_bytes(), before)

    def test_missing_original_publishes_no_package(self):
        self.original.rename(self.tree/"different.c")
        self.assertEqual(self.run_command().returncode, 1)
        result = json.loads((self.out / "result.json").read_text())
        self.assertEqual(result["decision"], "error")
        self.assertIn("regmap.c", result["reason"])
        self.assertFalse((self.out / "package").exists())

    def test_changed_rule_is_rejected_before_using_its_hashes(self):
        checkout = self.root / "checkout"
        script = checkout / "scripts/optimization/bma400.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(TOOL, script)
        shutil.copyfile(TOOL.with_name("bma400_entry.py"), script.with_name("bma400_entry.py"))
        rule = checkout / "configs/optimization/bma400-six-byte.json"
        rule.parent.mkdir(parents=True)
        rule.write_text('{"scope": "different"}', encoding="utf-8")
        self.assertEqual(self.run_command(tool=script).returncode, 3)
        self.assertEqual(json.loads((self.out / "result.json").read_text())["reason"], "rule declaration differs")
        self.assertEqual((self.out / "package/original" / UNIT).read_bytes(), self.original.read_bytes())


if __name__ == "__main__":
    unittest.main()

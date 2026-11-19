"""The offline report entry never dispatches a kernel operation."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from kconc import cli
from kconc.manifest import ManifestError, normalize_manifest


class TraceReportTests(unittest.TestCase):
    def test_manifest_optional_attempt_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            inputs = {"bundle": "bundle", "source_root": "sources", "build_record": "build.json"}
            manifest = {"schema_version": 1, "operation": "report.trace", "inputs": inputs}
            self.assertNotIn("attempt", normalize_manifest(manifest, base)["inputs"])
            inputs["attempt"] = "old attempt"
            self.assertEqual(normalize_manifest(manifest, base)["inputs"]["attempt"], str(base / "old attempt"))
            del inputs["build_record"]
            with self.assertRaises(ManifestError):
                normalize_manifest(manifest, base)

    def test_report_subcommand_uses_offline_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report"
            flags = ["report", "--bundle", "bundle", "--source-root", "source", "--build-record", "build",
                     "--attempt", "attempt", "--output", str(out)]
            with patch.object(cli, "run_live") as live, patch.object(cli, "implementation", return_value={}), \
                 patch("kconc.trace_report.write_report", return_value={"new_guest_executions": 0}) as writer, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(flags), 0)
                self.assertEqual(cli.main(flags), 2)
            writer.assert_called_once()
            live.assert_not_called()
            envelope = json.loads((out/"result.json").read_bytes())
            self.assertEqual(envelope["status"], "read")
            self.assertIsNone(envelope["backend"])

    def test_file_mismatch_records_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report"
            inputs = {"bundle": "bundle", "source_root": "source", "build_record": "build"}
            with patch("kconc.trace_report.write_report", side_effect=ValueError("source fingerprint mismatch")), \
                 patch.object(cli, "implementation", return_value={}), patch.object(cli, "run_live") as live:
                result = cli.run_task(inline={"schema_version": 1, "operation": "report.trace", "inputs": inputs}, output=out)
            self.assertEqual(result["status"], "failed")
            self.assertIn("source fingerprint mismatch", result["error"]["message"])
            self.assertFalse((out/"index.html").exists())
            live.assert_not_called()

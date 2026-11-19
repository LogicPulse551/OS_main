"""An offline report must fail before publishing evidence from an invalid bundle."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kconc.competition_demo import Evidence, render_bundle


class DemoEvidenceTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.base = Path(folder.name)
        self.bundle = self.base / "bundle.json"
        self.hash = hashlib.sha256(b"{}").hexdigest()

    def manifest(self, files):
        self.bundle.write_text(json.dumps(dict(kind="kconc.regmap-demo", schema=1, files=files)), encoding="utf8")

    def test_manifest_cannot_introduce_an_external_or_executable_path(self):
        for path in ("../record.json", "/tmp/record.json", "d:/record.json", "test/./file.json", "script.html"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.manifest({path: self.hash})
                Evidence(self.bundle)

    def test_unlisted_file_cannot_substitute_for_listed_file(self):
        (self.base / "record.json").write_bytes(b"{}")
        self.manifest({})
        with self.assertRaisesRegex(ValueError, "Unlisted"):
            Evidence(self.bundle).json("record.json")

    def test_verify_the_content_that_will_be_copied(self):
        path = self.base / "record.json"
        path.write_bytes(b"{}")
        self.manifest({"record.json": self.hash})
        evidence = Evidence(self.bundle)
        self.assertEqual(evidence.json("record.json"), {})
        path.write_bytes(b"null")
        self.assertEqual(evidence.raw("record.json"), b"{}")
        with self.assertRaisesRegex(ValueError, "Changed"):
            Evidence(self.bundle).raw("record.json")

    def test_incomplete_bundle_publishes_no_report(self):
        self.manifest({})
        with self.assertRaisesRegex(ValueError, "Unlisted"):
            render_bundle(self.bundle, self.base)
        self.assertFalse((self.base / "index.html").exists())
        self.assertFalse((self.base / "evidence").exists())

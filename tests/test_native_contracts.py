"""Source facts that identify a caller must stay distinct from permission to rewrite it."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc.native_contracts import assess


class NativeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src = "arbitrary.c"
        (self.root / self.src).write_text("/* EXPORT_SYMBOL(custom_probe); */\n")
        self.owner = dict(function="custom_probe", registry_lookup=[], registrations=[dict(source=self.src, line=28)])
        self.site = dict(source=self.src, count=6, owners=[self.owner], private_path=[{"line": 11}],
                         decision="keep_original")

    def test_lookup_keeps_its_source_location(self):
        self.owner["registry_lookup"] = [dict(source=self.src, line=88, unnamed=True)]
        result = assess(self.root, self.site)
        self.assertEqual(result["reason"], "unnamed_regmap_lookup")
        self.assertEqual(result["open_conditions"][0]["line"], 88)
        self.assertEqual(result["decision"], "keep_original")

    def test_export_is_code_and_not_a_comment(self):
        self.assertEqual(assess(self.root, self.site)["reason"], "shared_poll_lifetime_unproved")
        (self.root / self.src).write_text("EXPORT_SYMBOL_NS_GPL(custom_probe, SENSOR);\n")
        self.assertEqual(assess(self.root, self.site)["reason"], "exported_probe_callers_not_closed")

    def test_known_parent_does_not_prove_every_dispatch(self):
        (self.root / self.src).write_text("iio_trigger_poll_nested(own);\n.validate_device = own_device\n")
        result = assess(self.root, self.site)
        self.assertEqual(result["reason"], "shared_poll_lifetime_unproved")
        self.assertTrue(result["contracts"]["matched_nested_dispatch"])
        self.assertEqual(result["decision"], "keep_original")

    def test_missing_count_or_binding_is_reported_at_its_own_stage(self):
        for update, reason in [({"count": None}, "value_count_unresolved"),
                               ({"count": 3}, "not_six_one_byte_values"),
                               ({"owners": []}, "managed_iio_owner_not_established")]:
            with self.subTest(update=update):
                self.assertEqual(assess(self.root, dict(self.site, **update))["reason"], reason)
        self.owner["registrations"] = []
        self.assertEqual(assess(self.root, self.site)["reason"], "poll_registration_not_established")

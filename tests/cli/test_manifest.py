"""Manifest rejection and normalization tests; no VM or backend is invoked."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kconc.manifest import CATALOG, MAX_MANIFEST_BYTES, ManifestError, load_manifest, normalize_manifest


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.profile = {
            "lab_dir": "vm", "ssh_port": 2224,
            "build_lab": "build-lab", "kernel_build": "kernel",
            "probe_guest_build": "/home/lab/k02/build",
            "scenario_guest_build": "/home/lab/k03/build",
        }

    def manifest(self, operation="env.status", **fields):
        return {"schema_version": 1, "operation": operation,
                "runtime": copy.deepcopy(self.profile), **fields}

    def rejected(self, value):
        with self.assertRaises(ManifestError) as caught:
            normalize_manifest(value, self.base)
        self.assertEqual(caught.exception.code, "invalid_manifest")
        self.assertTrue(caught.exception.message)

    def load_bytes(self, data):
        path = self.base / "task.json"
        path.write_bytes(data)
        return load_manifest(path)

    def test_catalog_is_capabilities_not_completion(self):
        self.assertEqual(len(CATALOG), 68)
        self.assertEqual({key for key, value in CATALOG.items() if value["supported"]},
                         {"env.status", "env.check", "build.identity", "artifact.check", "artifact.loaded", "k03.record",
                          "k03.bind", "k03.replay", "k03.view", "result.read", "report.trace", "optimize.bma400", "demo.review",
                          "native.regmap-two-prelock",
                          "runtime.initialize", "runtime.status", "runtime.recover", "scenario.run", "scenario.cancel",
                          "regmap.initialize", "regmap.status", "regmap.recover", "regmap.baseline",
                          "regmap.fault-reset", "regmap.record", "regmap.replay", "regmap.setup-fault",
                          "rmw.initialize", "rmw.status", "rmw.recover", "rmw.matrix", "rmw.record", "rmw.replay",
                          "mutex.initialize", "mutex.status", "mutex.recover", "mutex.matrix", "mutex.record", "mutex.replay",
                          "sample.initialize", "sample.status", "sample.recover", "sample.run", "candidate.export",
                          "search.initialize", "search.status", "search.recover", "kernel.check",
                          "replay.initialize", "replay.status", "replay.recover", "replay.bind", "replay.run",
                          "regression.initialize", "regression.status", "regression.recover", "kernel.regress", "feedback.initialize", "feedback.status", "feedback.recover", "kernel.explore", "reduction.initialize", "reduction.status", "reduction.recover", "kernel.reduce"})
        for item in CATALOG.values():
            self.assertIs(type(item["supported"]), bool)
            self.assertIsInstance(item["project_task"], str)
            self.assertTrue(item["scope"])
            self.assertNotIn("verified", item)

    def test_relative_host_and_absolute_guest_paths(self):
        original = self.manifest("k03.replay", inputs={"binding": "previous/binding", "source_mapper": "bin/source-map"})
        before = copy.deepcopy(original)
        actual = normalize_manifest(original, self.base)
        self.assertEqual(actual["runtime"]["lab_dir"], str((self.base / "vm").resolve()))
        self.assertEqual(actual["inputs"]["binding"], str((self.base / "previous/binding").resolve()))
        self.assertEqual(actual["runtime"]["scenario_guest_build"], "/home/lab/k03/build")
        self.assertEqual(original, before)
        self.assertFalse((self.base / "vm").exists())

    def test_prelock_binds_inputs_without_overriding_the_kernel(self):
        task = {"schema_version": 1, "operation": "native.regmap-two-prelock",
                "inputs": {"bundle": "bundle", "disk": "disk.qcow2", "reference": "previous"}}
        normalized = normalize_manifest(task, self.base)
        self.assertEqual(normalized["inputs"]["reference"], str((self.base / "previous").resolve()))
        self.rejected({**task, "runtime": {"kernel_build": "unregistered"}})
        self.rejected({**task, "inputs": {"reference": "previous"}})

    def test_load_relative_to_manifest_not_process_cwd(self):
        value = {"schema_version": 1, "operation": "result.read", "inputs": {"result": "run/result.json"}}
        actual = self.load_bytes(json.dumps(value).encode())
        self.assertEqual(actual["inputs"]["result"], str((self.base / "run/result.json").resolve()))
        self.assertEqual(actual["runtime"], {})
        self.assertNotIn("name", actual)

    def test_home_expansion(self):
        expected = str((Path.home() / "kconc-nonexistent-input.json").resolve())
        value = {"schema_version": 1, "operation": "result.read", "inputs": {"result": "~/kconc-nonexistent-input.json"}}
        self.assertEqual(normalize_manifest(value, self.base)["inputs"]["result"], expected)

    def test_unsupported_operations_are_valid_manifests(self):
        for operation, metadata in CATALOG.items():
            if not metadata["supported"]:
                with self.subTest(operation=operation):
                    actual = normalize_manifest({"schema_version": 1, "operation": operation}, self.base)
                    self.assertEqual(actual, {"schema_version": 1, "operation": operation, "runtime": {}, "inputs": {}})

    def test_unsupported_does_not_bypass_profile_validation(self):
        for operation, metadata in CATALOG.items():
            if metadata["supported"]:
                continue
            for fields in ({"runtime": False}, {"inputs": False},
                           {"runtime": {"unknown": False}}, {"inputs": {"unknown": False}}):
                with self.subTest(operation=operation, fields=fields):
                    self.rejected({"schema_version": 1, "operation": operation, **fields})

    def test_required_profiles_and_inputs_per_operation(self):
        expected = {
            "env.status": ({"lab_dir", "ssh_port"}, set()),
            "env.check": ({"lab_dir", "ssh_port", "build_lab", "kernel_build", "probe_guest_build"}, set()),
            "build.identity": ({"lab_dir", "ssh_port", "build_lab", "kernel_build", "scenario_guest_build"}, set()),
            "k03.record": ({"lab_dir", "ssh_port", "build_lab", "kernel_build", "scenario_guest_build"}, set()),
            "k03.bind": ({"lab_dir", "ssh_port", "build_lab", "kernel_build", "scenario_guest_build"}, {"record", "source_mapper"}),
            "k03.replay": ({"lab_dir", "ssh_port", "build_lab", "kernel_build", "scenario_guest_build"}, {"binding", "source_mapper"}),
            "k03.view": ({"lab_dir", "ssh_port"}, {"trace"}),
            "result.read": (set(), {"result"}),
        }
        for operation, (required_runtime, required_inputs) in expected.items():
            value = self.manifest(operation, inputs={key: "missing-but-allowed" for key in required_inputs})
            normalize_manifest(value, self.base)
            for key in required_runtime:
                with self.subTest(operation=operation, missing=key):
                    missing = copy.deepcopy(value)
                    del missing["runtime"][key]
                    self.rejected(missing)
            for key in required_inputs:
                with self.subTest(operation=operation, missing=key):
                    missing = copy.deepcopy(value)
                    del missing["inputs"][key]
                    self.rejected(missing)

    def test_schema_version_and_operation_fail_closed(self):
        for value in (True, False, 1.0, "1", 0, 2, None):
            with self.subTest(schema_version=value):
                self.rejected({**self.manifest(), "schema_version": value})
        for value in (None, "", "shell", "K03.REPLAY", 1, ["env.status"]):
            with self.subTest(operation=value):
                self.rejected({**self.manifest(), "operation": value})
        self.rejected([])
        self.rejected(None)

    def test_unknown_keys_and_cross_operation_inputs(self):
        for value in (
            self.manifest(command="touch should-not-run"),
            self.manifest(runtime={**self.profile, "password": "not-accepted"}),
            self.manifest(inputs={"trace": "unrelated"}),
            self.manifest("result.read", inputs={"result": "ok", "source_mapper": "unexpected"}),
        ):
            self.rejected(value)

    def test_nested_types_and_strict_port(self):
        for key in ("runtime", "inputs"):
            for value in (None, [], "text", 0):
                with self.subTest(key=key, value=value):
                    self.rejected(self.manifest(**{key: value}))
        for port in (True, False, "2224", 2224.0, 0, -1, 65536, float("nan")):
            with self.subTest(port=port):
                self.rejected(self.manifest(runtime={**self.profile, "ssh_port": port}))
        for port in (1, 65535):
            self.assertEqual(normalize_manifest(self.manifest(runtime={**self.profile, "ssh_port": port}), self.base)["runtime"]["ssh_port"], port)

    def test_path_types_and_guest_escape_rejected(self):
        for key in ("lab_dir", "build_lab", "kernel_build", "probe_guest_build", "scenario_guest_build"):
            for value in (None, False, 123, [], "", "bad\0path"):
                with self.subTest(key=key, value=value):
                    self.rejected(self.manifest(runtime={**self.profile, key: value}))
        for path in ("relative", "C:\\guest", "/home/lab/k03/../other", "/home/lab/k03", "/home/lab/k030/build", "/tmp/build"):
            with self.subTest(guest=path):
                self.rejected(self.manifest(runtime={**self.profile, "scenario_guest_build": path}))
        self.rejected(self.manifest(runtime={**self.profile, "probe_guest_build": "/home/lab/k02/../build"}))

    def test_name_validation_and_unicode(self):
        value = self.manifest(name="内核检查")
        self.assertEqual(normalize_manifest(value, self.base)["name"], "内核检查")
        normalize_manifest(self.manifest(name="x" * 100), self.base)
        self.assertEqual(normalize_manifest(self.manifest(name=""), self.base)["name"], "")
        for name in ("x" * 101, None, False, 1, []):
            with self.subTest(name=name):
                self.rejected(self.manifest(name=name))

    def test_duplicate_keys_rejected_at_all_levels(self):
        values = (
            b'{"schema_version":1,"operation":"result.read","operation":"optimize"}',
            b'{"schema_version":1,"operation":"env.status","runtime":{"lab_dir":"x","ssh_port":22,"ssh_port":23}}',
            b'{"schema_version":1,"operation":"result.read","inputs":{"result":"a","result":"b"}}',
        )
        for data in values:
            with self.subTest(data=data), self.assertRaises(ManifestError) as caught:
                self.load_bytes(data)
            self.assertIn("Duplicate JSON key", caught.exception.message)

    def test_nonfinite_and_malformed_json_rejected(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999", b"1E+999"):
            data = b'{"schema_version":1,"operation":"optimize","unused":' + constant + b'}'
            with self.subTest(constant=constant), self.assertRaises(ManifestError) as caught:
                self.load_bytes(data)
            self.assertIn("Non-finite", caught.exception.message)
        for data in (b"{", b"[]", b"null", b"\xff", b'{"schema_version":1} trailing',
                     b'{"schema_version":' + b'1' * 10000 + b',"operation":"optimize"}'):
            with self.subTest(data=data), self.assertRaises(ManifestError) as caught:
                self.load_bytes(data)
            self.assertEqual(caught.exception.code, "invalid_manifest")

    def test_byte_limit_is_not_character_limit(self):
        prefix = b'{"schema_version":1,"operation":"optimize"}'
        result = self.load_bytes(prefix + b" " * (MAX_MANIFEST_BYTES - len(prefix)))
        self.assertEqual(result["operation"], "optimize")
        with self.assertRaises(ManifestError) as caught:
            self.load_bytes(prefix + b" " * (MAX_MANIFEST_BYTES + 1 - len(prefix)))
        self.assertIn("64 KiB", caught.exception.message)

    def test_missing_file_is_read_error(self):
        with self.assertRaises(ManifestError) as caught:
            load_manifest(self.base / "absent.json")
        self.assertEqual(caught.exception.code, "manifest_read_error")

    def test_nonregular_input_rejected_before_open(self):
        with patch("pathlib.Path.is_file", return_value=False), \
             patch("pathlib.Path.open", side_effect=AssertionError("must not open a nonregular file")), \
             self.assertRaises(ManifestError) as caught:
            load_manifest(self.base / "special-file")
        self.assertEqual(caught.exception.code, "manifest_read_error")
        with self.assertRaises(ManifestError) as directory:
            load_manifest(self.base)
        self.assertEqual(directory.exception.code, "manifest_read_error")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixture requires POSIX")
    def test_fifo_rejected_without_waiting_for_writer(self):
        fifo = self.base / "task.fifo"
        os.mkfifo(fifo)
        with patch("pathlib.Path.open", side_effect=AssertionError("must not open a FIFO")), \
             self.assertRaises(ManifestError) as caught:
            load_manifest(fifo)
        self.assertEqual(caught.exception.code, "manifest_read_error")

    def test_normalization_does_not_probe_referenced_files(self):
        value = self.manifest("k03.replay", inputs={"binding": "not-created", "source_mapper": "absent"})
        with patch("pathlib.Path.exists", side_effect=AssertionError("must not probe existence")), \
             patch("pathlib.Path.open", side_effect=AssertionError("must not open runtime inputs")):
            actual = normalize_manifest(value, self.base)
        self.assertTrue(Path(actual["inputs"]["binding"]).is_absolute())


if __name__ == "__main__":
    unittest.main()

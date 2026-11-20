import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import api_inputs as inputs


class ApiDependencyIdentity(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.src, self.obj, self.resource = base / "source", base / "build", base / "resource"
        self.tu = self.src / "drivers/unit/ranges.c"
        self.cc = base / "compiler"
        self.header = self.src / "include/linux/regmap.h"
        self.generated = self.obj / "include/generated/autoconf.h"
        self.label = self.obj / "include/generated/utsversion.h"
        for file in (self.tu, self.cc, self.header, self.generated, self.label):
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"\n")
        self.resource.mkdir()

    def deps(self, *others):
        paths = " ".join(map(str, (self.tu, *others)))
        reply = subprocess.CompletedProcess([], 0, ("kconc_inputs: " + paths).encode(), b"")
        with patch.object(subprocess, "run", return_value=reply), patch.object(
                subprocess, "check_output", return_value=str(self.resource)):
            return inputs.bind_dependencies(self.src, self.obj, self.tu, self.cc, [], self.obj)

    def test_records_kernel_and_generated_dependencies(self):
        bound = self.deps(self.header, self.generated)
        self.assertEqual(set(bound), {"source/drivers/unit/ranges.c", "source/include/linux/regmap.h",
                                      "build/include/generated/autoconf.h"})
        self.assertEqual(bound["build/include/generated/autoconf.h"], inputs.file_hash(self.generated))

    def test_private_header_and_build_labels_refuse_admission(self):
        private = self.tu.parent / "local.h"
        private.write_text("#pragma pack(1)\n")
        for bad in (self.label, private):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                self.deps(self.header, bad)

    def test_timestamp_can_vary_but_another_generated_header_cannot(self):
        def tree():
            return inputs.tree_inputs(self.obj, ("include",), (self.src, self.obj))
        original = tree()
        self.label.write_text("different host and date")
        self.assertEqual(tree(), original)
        self.generated.write_text("#define CONFIG_REGMAP_DIFFERENT 1")
        self.assertNotEqual(tree(), original)

    def test_actual_source_guard_is_relocatable_and_rest_is_bound(self):
        import hashlib
        canon = b'files := Kconfig\nifneq "$(srctree)" "$SOURCE"\nendif\n'
        with patch.object(inputs, "KCONFIG_MAKE_PORTABLE", hashlib.sha256(canon).hexdigest()):
            for source in (self.src, self.src.parent / "moved"):
                data = canon.replace(b"$SOURCE", os.fsencode(source))
                self.assertEqual(inputs.kconfig_make_identity(data, source), inputs.KCONFIG_MAKE_ORIGINAL)
                bad = (data.replace(b"Kconfig", b"Other"),
                       data + b'include extra.mk\n',
                       data + data,
                       data.replace(os.fsencode(source), b"/foreign/tree"),
                       canon)
                for mutation in bad:
                    with self.subTest(source=source, mutation=mutation), self.assertRaises(ValueError):
                        inputs.kconfig_make_identity(mutation, source)

    @unittest.skipIf(os.name == "nt", "suite uses Linux symlinks")
    def test_header_symlink_to_unbound_input_rejected(self):
        alias = self.header.parent / "extra.h"
        alias.symlink_to(self.tu)
        with self.assertRaises(ValueError):
            inputs.tree_inputs(self.src, ("include",))
        with self.assertRaises(ValueError):
            self.deps(alias)


if __name__ == "__main__":
    unittest.main()

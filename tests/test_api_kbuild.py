"""Recorded compiler flags have to keep their exact meaning for AST replay."""
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import api_kbuild as kbuild


class CompilationTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.base = Path(workspace.name).resolve()
        self.root, self.obj = self.base / "linux", self.base / "obj"
        self.source = self.root / "drivers/sensors/meter.c"
        self.clang = self.base / "clang"
        self.clang.touch()
        self.source.parent.mkdir(parents=True)
        self.source.touch()
        self.includes = [self.root / "arch/x86/include", self.obj / "arch/x86/include/generated",
                         self.root / "include", self.obj / "include", self.root / "arch/x86/include/uapi",
                         self.obj / "arch/x86/include/generated/uapi", self.root / "include/uapi",
                         self.obj / "include/generated/uapi"]
        for path in self.includes:
            path.mkdir(parents=True, exist_ok=True)
        self.headers = ["compiler-version.h", "kconfig.h", "compiler_types.h"]
        (self.root / "include/linux").mkdir()
        for name in self.headers:
            (self.root / "include/linux" / name).touch()

    def example(self, external, alter=lambda flags: None):
        cwd = self.source.parent if external else self.obj
        obj = Path("meter.o") if external else Path("drivers/sensors/meter.o")
        objpath = cwd / obj
        objpath.parent.mkdir(exist_ok=True, parents=True)
        objpath.touch()
        src = self.source.name if external else str(self.source)
        dep = (obj.parent / ".meter.o.d").as_posix()
        tokens = [str(self.clang), "-Wp,-MMD," + dep, "-nostdinc"]
        for path in self.includes:
            value = path.relative_to(cwd) if path.is_relative_to(cwd) else path
            tokens.append("-I" + str(value))
        for header in self.headers:
            tokens.extend(("-include", str(self.root / "include/linux" / header)))
        tokens.extend(kbuild.PREFIX)
        if not external:
            tokens.append("-fmacro-prefix-map=" + str(self.root) + "/=")
        tokens.extend(kbuild.OPTIONS)
        if external:
            tokens.append("-DMODULE")
        else:
            tokens.extend(["-I"+str(self.source.parent), "-I"+obj.parent.as_posix(),
                           '-DKBUILD_MODFILE="drivers/sensors/meter"'])
        tokens.extend(['-DKBUILD_BASENAME="meter"', '-DKBUILD_MODNAME="meter"',
                       "-D__KBUILD_MODNAME=meter", "-c", "-o", obj.as_posix(), src])
        alter(tokens)
        command = shlex.join(tokens)
        if external:
            command += " ; " + shlex.join([str(self.obj / "tools/objtool/objtool"),
                                            *kbuild.OBJTOOL, obj.as_posix()])
        record = objpath.with_name(".meter.o.cmd")
        record.write_text(f"savedcmd_{obj.as_posix()} := {command}\n\nsource_{obj.as_posix()} := {src}\n",
                          encoding="utf-8")
        return record

    def read(self):
        return kbuild.compilation(self.root, self.obj, self.source, self.clang)

    def test_in_tree_record_preserves_relative_search_dirs(self):
        self.example(False)
        flags, cwd = self.read()
        self.assertEqual(cwd, self.obj)
        self.assertEqual(flags[:2], ["--no-default-config", "-nostdinc"])
        self.assertIn("-O2", flags)
        self.assertIn("-Idrivers/sensors", flags)
        self.assertNotIn("-o", flags)
        self.assertNotIn("-c", flags)
        self.assertFalse(any("-MMD" in token for token in flags))

    def test_module_in_source_tree_uses_its_own_working_directory(self):
        self.example(True)
        flags, cwd = self.read()
        self.assertEqual(cwd, self.source.parent)
        self.assertIn("-DMODULE", flags)
        self.assertNotIn("--module", flags)

    def test_no_guess_between_two_records(self):
        self.example(True)
        self.example(False)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.read()

    def test_unknown_compiler_options_are_not_replayed(self):
        for extra in (["-include", "override.h"], ["--config=extra.cfg"], ["-Xclang", "anything"],
                      ["-I../other"], ["-DKBUILD_MODNAME=bad"], ["-O0"], ["@extra.rsp"]):
            with self.subTest(extra=extra):
                self.example(True, lambda a: a.__setitem__(slice(-4, -4), extra))
                with self.assertRaises(ValueError):
                    self.read()

    def test_output_source_compiler_and_headers_must_match_the_request(self):
        for old, new in [(str(self.clang), str(self.base / "other")), ("meter.c", "other.c"),
                         ("meter.o", "other.o"), ("-Wp,-MMD,.meter.o.d", "-Wp,-MMD,something.d"),
                         (str(self.root / "include/linux/kconfig.h"), str(self.source)),
                         ('-DKBUILD_MODNAME="meter"', '-DKBUILD_MODNAME="bad;name"')]:
            with self.subTest(old=old, new=new):
                self.example(True, lambda a: a.__setitem__(a.index(old), new))
                with self.assertRaises(ValueError):
                    self.read()

    def test_wrong_metadata_or_second_command_rejected(self):
        for old, new in (("source_meter.o", "source_unrelated.o"), ("--hacks=noinstr", "--other"),
                         ("--link --module", "--link --module extra")):
            with self.subTest(old=old):
                path = self.example(True)
                original = path.read_text(encoding="utf-8")
                self.assertIn(old, original)
                path.write_text(original.replace(old, new), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.read()

    def test_alternate_driver_mode_for_same_binary_rejected(self):
        alias = self.base / "clang++"
        try:
            alias.symlink_to(self.clang)
        except OSError:
            self.skipTest("creating symbolic links is unavailable")
        self.example(True, lambda args: args.__setitem__(0, str(alias)))
        with self.assertRaisesRegex(ValueError, "compiler identity"):
            self.read()


if __name__ == "__main__":
    unittest.main()

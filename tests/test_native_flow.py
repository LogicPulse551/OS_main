"""Driver provenance is reported only for the typed input that supplies an edge."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import native_flow as native


class ProbeFlowTests(unittest.TestCase):
    def test_index_can_start_at_arbitrary_driver_names(self):
        index = native.bodies(b"/* static int fake() { f(); } */\n"
                              b"static int\npecan_read(int x)\n{\n if (x) { z(); }\n return x;\n}\n")
        self.assertEqual(set(index), {"pecan_read"})
        self.assertIn("return x;", index["pecan_read"])

    def test_count_uses_the_c_expression_type(self):
        sizeof = lambda typ: {"kind":"UnaryExprOrTypeTraitExpr", "name":"sizeof", "argType":{"qualType":typ}}
        self.assertEqual(native.constant(sizeof("__le16[3]")), 6)
        self.assertEqual(native.constant(sizeof("unsigned short")), 2)
        self.assertIsNone(native.constant(sizeof("struct sample")))
        self.assertIsNone(native.constant(sizeof("u8[n]")))
        self.assertIsNone(native.constant({"kind":"MemberExpr","name":"external_length"}))

    def test_plain_arithmetic_and_dynamic_register(self):
        fields = [{"kind":"IntegerLiteral","value":str(i)} for i in (2,3)]
        self.assertEqual(native.constant({"kind":"BinaryOperator","opcode":"*","inner":fields}), 6)
        fields[0] = {"kind":"DeclRefExpr","referencedDecl":{"kind":"VarDecl","id":"other"}}
        self.assertIsNone(native.constant({"kind":"BinaryOperator","opcode":"*","inner":fields}))

    def test_empty_and_unknown_descriptors_do_not_create_a_format(self):
        observed = native.configurations(None, [{"status":"unverified_source_reference"}], {})
        self.assertEqual(observed["known_configs"], [])
        self.assertEqual(observed["known_descriptors"], [])
        self.assertTrue(observed["declared_values_only"])

    def test_field_matching_includes_owning_struct(self):
        def member(kind):
            return {"kind":"MemberExpr","name":"map","referencedMemberDecl":"member-id",
                    "type":{"qualType":"struct regmap *"},"inner":[{"type":{"qualType":kind}}]}
        self.assertNotEqual(native.signatures(member("struct tea *")),native.signatures(member("struct water *")))

    def test_field_addresses_and_mutations_are_distinct_from_pointer_reads(self):
        member = {"kind":"MemberExpr","referencedMemberDecl":"alpha"}
        for kind,op,effect in (("UnaryOperator","&","field_address_taken"),
                               ("UnaryOperator","++","read_modify_write"),
                               ("BinaryOperator","=","assignment")):
            node = {"kind":kind,"opcode":op,"inner":[member]}
            self.assertEqual(list(native.field_effects(node)),[("alpha",member,effect)])
        self.assertEqual(list(native.field_effects({"kind":"CallExpr","inner":[member]})),[])

    def test_dependencies_bind_only_observed_driver_headers_and_distinguish_unbuilt_frontend(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            root, obj = base / "source", base / "obj"
            folder = root / "drivers/tea"
            folder.mkdir(parents=True)
            (obj / "drivers/tea").mkdir(parents=True)
            paths = [folder / n for n in ("probe.c", "wire.c", "other.c", "local.h")]
            core, built, unbuilt, header = paths
            compiler = base / "clang"
            conf = obj / "include/generated/autoconf.h"
            conf.parent.mkdir(parents=True)
            for f in (*paths, compiler, conf):
                f.write_text(f.name)
            source_hash = native.api_inputs.file_hash(core)
            shared = {"clang_sha256": "cc", "generated_files": {"include/generated/autoconf.h": native.api_inputs.file_hash(conf)}}
            rel = lambda p: p.relative_to(root).as_posix()
            for f in (core, built):
                output = (obj / rel(f)).with_suffix(".o")
                output.write_bytes(b"obj")
                output.with_name("." + output.name + ".cmd").write_bytes(b"receipt")
            rows = [{"source": rel(core), "source_sha256": source_hash, "owners": [{"frontends": [
                {"constructor": {"source": rel(built)}}, {"source": rel(unbuilt), "line": 17,
                "reason": "missing receipt", "status": "unverified_source_reference"}]}]}]

            def dependencies(command, **kw):
                import shlex
                files = tuple(shlex.quote(str(p)) for p in (command[-1], header, conf))
                return subprocess.CompletedProcess(command, 0, ("kconc_inputs: " + " ".join(files)).encode(), b"")

            with patch.object(native.api_inputs, "verify", return_value=shared), patch.object(
                    native, "compilation", return_value=([], obj)), patch.object(
                    subprocess, "run", side_effect=dependencies), patch.object(
                    subprocess, "check_output", return_value=str(base)):
                result = native.bind_native_inputs(root, obj, compiler, core, rows)
                self.assertEqual(set(result["translation_units"]), {rel(core), rel(built)})
                self.assertEqual(set(result["source_only"]), {rel(unbuilt)})
                for record in result["translation_units"].values():
                    self.assertEqual(record["driver_headers"], {rel(header): native.api_inputs.file_hash(header)})
                    self.assertEqual(record["dependencies"]["build/include/generated/autoconf.h"],
                                     shared["generated_files"]["include/generated/autoconf.h"])
                with self.assertRaisesRegex(ValueError, "outside the reviewed API inputs"):
                    native.api_inputs.bind_dependencies(root, obj, core, compiler, [], obj)
                core.write_text("different source")
                with self.assertRaisesRegex(ValueError, "source revision"):
                    native.bind_native_inputs(root, obj, compiler, core, rows)


if __name__ == "__main__":
    unittest.main()

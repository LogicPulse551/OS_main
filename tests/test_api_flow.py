import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import api_flow as flow


class DriverProofInputs(unittest.TestCase):
    def test_preprocessing_before_api_is_not_a_locked_header(self):
        for source in (b"#define CONFIG_REGMAP 0\n#include <linux/regmap.h>",
                       b"#include \"elsewhere.h\"", b"#include <linux/../x>",
                       b"_Pragma(\"pack(1)\")", b"#define read(x) f(x)",
                       b"asm(\".something\")", b"int alias __attribute__((weak));"):
            with self.subTest(source=source):
                self.assertIsNotNone(flow.inspect_directives(source))
        self.assertIsNone(flow.inspect_directives(b"/* asm */\n#include <linux/regmap.h>\n#define BASE (0x17U)\n"))

    def test_actual_file_is_part_of_api_binding(self):
        header, impostor = Path("one/regmap.h"), Path("two/regmap.h")
        loc = {"offset": 1, "includedFrom": {"file": "source.c"}}
        self.assertTrue(flow.header_position("x", loc, b" x()", header, header))
        self.assertFalse(flow.header_position("x", loc, b" x()", header, impostor))
        self.assertFalse(flow.header_position("x", {}, b" x()", header, header))
        d = {"loc": {"offset": 2, "file": "header.h", "includedFrom": {"file": "other.c"}},
             "range": {"end": {"expansionLoc": {"offset": 13, "file": "caller.c"}}}}
        self.assertEqual(list(flow.explicit_files(d)), ["header.h", "caller.c"])

    def test_c_integer_narrowing_cannot_be_treated_as_the_literal(self):
        literal = {"kind": "IntegerLiteral", "value": "256"}
        expr = {"kind": "ImplicitCastExpr", "castKind": "IntegralCast",
                "type": {"qualType": "unsigned char"}, "inner": [literal]}
        self.assertIsNone(flow.integer(expr))
        expr["type"]["qualType"] = "unsigned int"
        self.assertEqual(flow.integer(expr), 256)

    def test_only_error_returns_can_skip_filling_output(self):
        n = {"kind": "IntegerLiteral", "value": "22"}
        err = {"kind": "UnaryOperator", "opcode": "-", "inner": [n]}
        self.assertTrue(flow.error_return({"kind": "ReturnStmt", "inner": [err]}))
        for ret in ({"kind": "IntegerLiteral", "value": "0"},
                    {"kind": "CallExpr", "inner": [n]}, n):
            self.assertFalse(flow.error_return({"kind": "ReturnStmt", "inner": [ret]}))

    def test_stream_retains_declaration_boundaries(self):
        source = b'{\n  "inner": [\n    {\n      "name": "a"\n    },\n    {\n      "name": "b"\n    }\n  ]\n}\n'
        self.assertEqual(list(flow.declarations(io.BytesIO(source))), [{"name": "a"}, {"name": "b"}])
        with self.assertRaises(ValueError):
            list(flow.declarations(io.BytesIO(source[:25])))

    def test_callback_or_caller_symbol_alias_is_not_a_definition(self):
        self.assertTrue(flow.unusual_function({"inner": [{"kind": "AliasAttr"}]}))
        self.assertFalse(flow.unusual_function({"inner": [{"kind": "NoInlineAttr"}]}))

    def test_memcpy_ref_requires_the_real_architecture_prototype(self):
        header = Path("kernel/arch/x86/include/asm/string_64.h")
        text = b"extern void *memcpy(void *to, const void *from, size_t len);"
        decl = {"kind": "FunctionDecl", "name": "memcpy", "storageClass": "extern",
                "loc": {"offset": text.index(b"memcpy"), "includedFrom": {"file": "string.h"}},
                "type": {"qualType": "void *(void *, const void *, __size_t)"},
                "inner": [{"kind": "BuiltinAttr"}, {"kind": "NoThrowAttr"}]}
        self.assertEqual(flow.copy_declaration(decl, header, text, header), "linux_x86_64_memcpy")
        self.assertIsNone(flow.copy_declaration(decl, header, text, Path("driver.h")))
        for change in ({"inner": []}, {"inner": decl["inner"] + [{"kind": "CompoundStmt"}]},
                       {"inner": decl["inner"] + [{"kind": "AsmLabelAttr"}]},
                       {"type": {"qualType": "int ()"}}, {"storageClass": "static"}):
            with self.subTest(change=change):
                self.assertIsNone(flow.copy_declaration(dict(decl, **change), header, text, header))

    def test_copy_symbol_binding_uses_declaration_id_and_rejects_shadowing(self):
        unit = flow.Unit.__new__(flow.Unit)
        unit.copy_redeclared = False
        unit.copy_decls = {"actual": "linux_x86_64_memcpy"}
        callee = {"kind": "DeclRefExpr", "referencedDecl": {"kind": "FunctionDecl", "id": "driver", "name": "memcpy"}}
        self.assertIsNone(unit.copy_contract(callee))
        callee["referencedDecl"]["id"] = "actual"
        self.assertEqual(unit.copy_contract(callee), "linux_x86_64_memcpy")
        unit.copy_redeclared = True
        self.assertIsNone(unit.copy_contract(callee))


if __name__ == "__main__":
    unittest.main()

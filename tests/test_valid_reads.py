"""Regression tests for narrowing a rewrite to the caller's six-byte output."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import api_emit, valid_emit, valid_opt


def owner(ident):
    return {"kind": "DeclRefExpr", "referencedDecl": {"id": ident}}


def member(base, name, typ, arrow=True):
    return {"kind":"MemberExpr", "referencedMemberDecl":"member-"+name, "name":name,
            "type":{"qualType":typ}, "isArrow":arrow, "inner":[base]}


class ValidReadTests(unittest.TestCase):
    def setUp(self):
        self.data = owner("private")
        self.map = member(self.data, "map", "struct regmap *")

    def test_inline_output_uses_the_same_private_object(self):
        dest = member(member(self.data, "buffer", "struct sample"), "xyz", "__le16[3]", False)
        dest = {"kind":"UnaryOperator", "opcode":"&", "inner":[dest]}
        self.assertEqual(valid_opt.inline_output(dest, self.map)["capacity"], 6)
        self.assertIsNone(valid_opt.inline_output(dest, member(owner("other"), "map", "struct regmap *")))

    def test_pointer_short_buffer_and_indirect_destination_keep_the_original(self):
        for value in [member(self.data,"buf","char *"), member(self.data,"buf","u8[5]"),
                      member(member(self.data,"ptr","struct alias *"),"buf","u8[8]"),
                      member(self.data,"output","unsigned char[]")]:
            with self.subTest(value=value):
                self.assertIsNone(valid_opt.inline_output(value, self.map))

    def test_register_expression_and_macro_count_are_preserved_byte_for_byte(self):
        text = b"regmap_bulk_read(p->m, p->cfg->base, p->buf, SAMPLE_BYTES);"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rel = "drivers/random.c"
            path = root/rel
            path.parent.mkdir()
            path.write_bytes(text)
            row = dict(source=rel, source_sha256=hashlib.sha256(text).hexdigest(), offset=0,
                       decision="admit",register=None)
            emitted = api_emit.driver_overlay(root,[row],{},valid_emit.ENTRY)
            self.assertEqual(emitted[rel], valid_emit.ENTRY+text[len(api_emit.ORIGINAL):])
            self.assertEqual(path.read_bytes(),text)
            with self.assertRaises(ValueError):
                api_emit.driver_overlay(root,[dict(row, source_sha256="0"*64)],{},valid_emit.ENTRY)

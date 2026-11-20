"""Bounds used to admit a variable read are properties of the actual C count."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import var_flow as vf


def literal(n):
    return {"kind": "IntegerLiteral", "value": str(n), "type": {"qualType": "unsigned long"}}


def parameter(name, typ="unsigned long"):
    return {
        "kind": "DeclRefExpr",
        "type": {"qualType": typ},
        "referencedDecl": {"kind": "ParmVarDecl", "id": name, "name": name},
    }


def bound(var, n):
    return {
        "kind": "IfStmt",
        "inner": [
            {"kind": "BinaryOperator", "opcode": ">", "inner": [var, literal(n)]},
            {"kind": "ReturnStmt"},
        ],
    }


class VariableBulkReadTests(unittest.TestCase):
    def test_fixed_bounds_use_capacity_and_original_signed_index(self):
        for n in (1, 7, 31, 47, 256, 65535, 2**31 - 1):
            self.assertTrue(vf.bounded_count(literal(n), n, []))
            self.assertFalse(vf.bounded_count(literal(n), n - 1, []))
        for n in (0, 2**31, 2**64 - 1):
            self.assertFalse(vf.bounded_count(literal(n), 2**64, []))

    def test_runtime_guard_binds_the_same_length(self):
        count = parameter("n")
        self.assertTrue(vf.bounded_count(count, 47, [bound(count, 47)]))
        self.assertFalse(vf.bounded_count(count, 47, [bound(count, 48)]))
        self.assertFalse(vf.bounded_count(count, 47, [bound(parameter("other"), 47)]))
        self.assertFalse(vf.bounded_count(count, 47, [bound(count, 47), {"kind": "CallExpr"}]))

    def test_a_comparison_without_an_early_exit_does_not_bound_the_read(self):
        count = parameter("n")
        guard = bound(count, 47)
        guard["inner"][1] = {"kind": "NullStmt"}
        self.assertFalse(vf.bounded_count(count, 47, [guard]))
        self.assertFalse(vf.bounded_count(parameter("n", "int"), 47, [bound(count, 47)]))

    def test_narrowing_cast_does_not_prove_a_bound_on_the_original_parameter(self):
        n = parameter("n")
        small = {
            "kind": "ImplicitCastExpr",
            "castKind": "IntegralCast",
            "type": {"qualType": "unsigned char"},
            "inner": [n],
        }
        self.assertIsNone(vf.unsigned_id(small))
        self.assertFalse(vf.bounded_count(n, 47, [bound(small, 47)]))

    def test_a_sizeof_bound_cannot_come_from_an_unknown_pointee(self):
        size = {"kind": "UnaryExprOrTypeTraitExpr", "name": "sizeof", "argType": {"qualType": "u8[37]"}}
        self.assertEqual(vf.constant_size(size), 37)
        size["argType"]["qualType"] = "struct regmap *"
        self.assertIsNone(vf.constant_size(size))

    def test_dynamic_count_belongs_to_this_invocation(self):
        n = parameter("n")
        fn = {"inner": [dict(n["referencedDecl"])]}
        vf.check_count_parameter(fn, n)
        with self.assertRaisesRegex(ValueError, "by_value"):
            vf.check_count_parameter(fn, parameter("different"))
        for typ, kind in (("unsigned long", "VarDecl"), ("volatile unsigned long", "ParmVarDecl")):
            shared = parameter("n", typ)
            shared["referencedDecl"]["kind"] = kind
            with self.assertRaisesRegex(ValueError, "by_value"):
                vf.check_count_parameter(fn, shared)

    def test_an_address_escape_or_write_invalidates_the_length(self):
        n = parameter("n")
        for kind, opcode in (
            ("UnaryOperator", "&"),
            ("UnaryOperator", "++"),
            ("BinaryOperator", "="),
            ("CompoundAssignOperator", "+="),
        ):
            op = {"kind": kind, "opcode": opcode, "inner": [n, literal(1)]}
            fn = {"inner": [dict(n["referencedDecl"]), op]}
            with self.assertRaisesRegex(ValueError, "address_taken"):
                vf.check_count_parameter(fn, n)
        with self.assertRaisesRegex(ValueError, "assembly"):
            vf.check_count_parameter({"inner": [dict(n["referencedDecl"]), {"kind": "GCCAsmStmt"}]}, n)

    def test_other_initializers_cannot_replace_the_allocated_buffer(self):
        root = Path("/kernel")
        location = {
            "expansionLoc": {"offset": 0},
            "spellingLoc": {"file": str(root / "include/linux/alloc_tag.h")},
        }
        result = parameter("result")
        allocation = {"kind": "CallExpr", "inner": [parameter("_kmalloc_noprof"), literal(3)]}
        assignment = {"kind": "BinaryOperator", "opcode": "=", "inner": [result, allocation]}
        block = {
            "kind": "CompoundStmt",
            "inner": [
                {"kind": "DeclStmt", "inner": [{"kind": "VarDecl", "id": "result"}]},
                {"kind": "IfStmt", "inner": [literal(1), assignment, assignment]},
                result,
            ],
        }
        init = {"kind": "StmtExpr", "range": {"begin": location}, "inner": [block]}
        decl = {"kind": "VarDecl", "id": "raw", "init": "c", "inner": [init]}
        null = {"kind": "UnaryOperator", "opcode": "!", "inner": [parameter("raw")]}
        prefix = [
            {"kind": "DeclStmt", "inner": [decl]},
            {"kind": "IfStmt", "inner": [null, {"kind": "ReturnStmt"}]},
        ]
        unit = SimpleNamespace(raw=b"kmalloc(3, GFP_KERNEL)")
        self.assertEqual(vf.fresh_extent(unit, root, decl, prefix, literal(3))["capacity"], 3)
        overwrite = {
            "kind": "BinaryOperator",
            "opcode": "=",
            "inner": [parameter("raw"), parameter("other")],
        }
        prefix[0]["inner"].append({"kind": "VarDecl", "inner": [overwrite]})
        self.assertIsNone(vf.fresh_extent(unit, root, decl, prefix, literal(3)))

    def test_read_arguments_cannot_change_capacity_or_pointer_before_the_call(self):
        for kind in ("CompoundAssignOperator", "StmtExpr", "AtomicExpr", "VAArgExpr", "CallExpr"):
            call = {
                "kind": "CallExpr",
                "inner": [
                    parameter("regmap_bulk_read"),
                    parameter("map"),
                    {"kind": kind},
                    parameter("raw"),
                    literal(2),
                ],
            }
            with self.assertRaisesRegex(ValueError, "argument_has_unresolved_effects"):
                vf.check_arguments(call)

"""Recognize writable output objects for a variable-length regmap bulk read."""

from pathlib import Path
import re

from . import api_emit, api_opt, native_flow, valid_opt
from .api_flow import children, integer, plain, qual, ref, walk
from .api_kbuild import command_location, compilation
from .cli import digest


def extent(node):
    return native_flow.constant(
        {"kind": "UnaryExprOrTypeTraitExpr", "name": "sizeof", "argType": node["type"]}
    )


def constant_size(node):
    """Only use a constant bound whose value survives the C conversions."""
    direct = integer(node)
    if direct is not None:
        return direct
    kind = node.get("kind")
    if kind == "UnaryExprOrTypeTraitExpr" and node.get("name") == "sizeof":
        return native_flow.constant(node)
    if kind == "ParenExpr":
        return constant_size(children(node)[0])
    if kind == "ImplicitCastExpr" and node.get("castKind") in {"NoOp", "IntegralCast"}:
        value = constant_size(children(node)[0])
        t = node["type"].get("desugaredQualType", qual(node))
        if value is not None and 0 <= value < 2**64 and t in {"unsigned long", "unsigned long long"}:
            return value
    return None


def unsigned_id(expr):
    value = plain(expr)
    if value.get("kind") != "DeclRefExpr" or ref(value).get("kind") != "ParmVarDecl":
        return None
    t = value.get("type", {})
    if t.get("desugaredQualType", t.get("qualType")) not in {
        "unsigned long",
        "unsigned int",
        "unsigned short",
        "unsigned char",
        "unsigned long long",
    }:
        return None
    # A narrowing cast between the allocation size, guard and call may change
    # the effective count. Support only the implicit widening to x86 size_t.
    current = expr
    while current is not value:
        if current.get("kind") == "ImplicitCastExpr" and current.get("castKind") not in {
            "LValueToRValue",
            "NoOp",
            "IntegralCast",
        }:
            return None
        if current.get("castKind") == "IntegralCast" and qual(current) not in {
            "size_t",
            "__size_t",
            "unsigned long",
        }:
            return None
        current = children(current)[0]
    return ref(value).get("id")


def check_count_parameter(fn, count):
    ident = unsigned_id(count)
    if not ident or not any(d.get("kind") == "ParmVarDecl" and d.get("id") == ident for d in children(fn)):
        raise ValueError("length_not_a_by_value_unsigned_parameter")
    for node in walk(fn):
        kind = node.get("kind")
        if kind in {"GCCAsmStmt", "MSAsmStmt"}:
            raise ValueError("length_may_change_in_assembly")
        uses_lvalue = (
            (kind == "UnaryOperator" and node.get("opcode") in {"&", "++", "--"})
            or (kind == "BinaryOperator" and node.get("opcode") == "=")
            or kind == "CompoundAssignOperator"
        )
        if uses_lvalue and any(
            n.get("referencedDecl", {}).get("id") == ident for n in walk(children(node)[0])
        ):
            raise ValueError("length_parameter_modified_or_address_taken")


def returning(stmt):
    if stmt.get("kind") == "CompoundStmt" and len(children(stmt)) == 1:
        (stmt,) = children(stmt)
    return stmt.get("kind") == "ReturnStmt"


def bounded_count(count, capacity, prefix):
    fixed = constant_size(count)
    if fixed is not None:
        return 0 < fixed <= min(capacity, 2**31 - 1)
    ident = unsigned_id(count)
    if not ident or not prefix or prefix[-1].get("kind") != "IfStmt":
        return False
    parts = children(prefix[-1])
    if len(parts) != 2 or not returning(parts[1]):
        return False
    cond = plain(parts[0])
    if cond.get("kind") != "BinaryOperator" or cond.get("opcode") != ">":
        return False
    length, bound = children(cond)
    limit = constant_size(bound)
    return unsigned_id(length) == ident and limit is not None and 0 <= limit <= capacity


def map_object(node):
    m = plain(node)
    if qual(m) == "struct regmap *":
        if m.get("kind") == "DeclRefExpr" and ref(m).get("kind") == "ParmVarDecl":
            return {"kind": "public_api_map_parameter", "name": ref(m)["name"]}
        if native_flow.field(m) and native_flow.direct_id(children(m)[0]):
            return {"kind": "typed_regmap_field", "name": m["name"]}
    raise ValueError("map_not_a_direct_typed_api_argument")


def fresh_extent(unit, root, decl, prefix, count):
    """Bind a successful kmalloc at this point to its checked size and lifetime."""
    if len(prefix) < 2 or prefix[-2].get("kind") != "DeclStmt" or prefix[-1].get("kind") != "IfStmt":
        return None
    declarations = children(prefix[-2])
    if len(declarations) != 1 or declarations[0] is not decl:
        return None
    check = children(prefix[-1])
    if len(check) != 2 or not returning(check[1]):
        return None
    test = plain(check[0])
    if (
        test.get("kind") != "UnaryOperator"
        or test.get("opcode") != "!"
        or native_flow.direct_id(children(test)[0]) != decl["id"]
    ):
        return None
    if not decl.get("init") or not children(decl):
        return None
    init = plain(children(decl)[0])
    loc = init.get("range", {}).get("begin", {})
    pos = loc.get("expansionLoc", {}).get("offset", -1)
    if (
        pos < 0
        or not re.match(rb"kmalloc\s*\(", unit.raw[pos:])
        or Path(loc.get("spellingLoc", {}).get("file", "")) != root / "include/linux/alloc_tag.h"
    ):
        return None
    # alloc_hooks in the bound kernel returns the very same local result from
    # both of its profiling branches. Reject a wrapped or substituted pointer.
    expr = init
    while expr.get("kind") == "StmtExpr":
        (block,) = children(expr)
        body = [x for x in children(block) if x.get("kind") != "NullStmt"]
        if len(body) == 1:
            expr = plain(body[0])
            continue
        break
    else:
        return None
    if len(body) != 3 or [n.get("kind") for n in body[:2]] != ["DeclStmt", "IfStmt"]:
        return None
    result = native_flow.direct_id(body[-1])
    if len(children(body[0])) != 1 or children(body[0])[0].get("id") != result:
        return None
    branches = children(body[1])
    if len(branches) != 3:
        return None
    sizes = []
    for branch in branches[1:]:
        assigns = [
            n
            for n in walk(branch)
            if n.get("kind") == "BinaryOperator"
            and n.get("opcode") == "="
            and native_flow.direct_id(children(n)[0]) == result
        ]
        if len(assigns) != 1:
            return None
        call = plain(children(assigns[0])[1])
        if native_flow.symbol(call) != "_kmalloc_noprof":
            return None
        arg = children(call)[1]
        n = constant_size(arg)
        token = unsigned_id(arg)
        if n is not None and bounded_count(count, n, []):
            sizes.append({"capacity": n, "bound": "allocation_size"})
        elif token and token == unsigned_id(count):
            sizes.append({"capacity": None, "bound": "same_unsigned_length_as_allocation"})
        else:
            return None
    return sizes[0] if sizes[0] == sizes[1] else None


def output_evidence(unit, root, fn, call, count, prefix):
    _, map_arg, _, dest, _ = children(call)
    node = plain(dest)
    addressed = node.get("kind") == "UnaryOperator" and node.get("opcode") == "&"
    if addressed:
        node = plain(children(node)[0])
    offset = 0
    if addressed and node.get("kind") == "ArraySubscriptExpr":
        base, index = children(node)
        index_value = constant_size(index)
        element = extent(node)
        if index_value is None or index_value < 0 or not element:
            raise ValueError("unresolved_output_array_offset")
        offset = index_value * element
        node = plain(base)
    if re.search(r"\b(?:const|volatile|_Atomic)\b", qual(node)):
        raise ValueError("qualified_output_not_supported")
    if node.get("kind") == "DeclRefExpr":
        ident = ref(node).get("id")
        decl = next((d for d in walk(fn) if d.get("kind") == "VarDecl" and d.get("id") == ident), None)
        if decl and not decl.get("storageClass"):
            size = extent(node)
            if size and (addressed or "[" in qual(node)) and bounded_count(count, size - offset, prefix):
                return dict(kind="local_object", capacity=size - offset, object=decl["name"])
            allocation = (
                fresh_extent(unit, root, decl, prefix, count)
                if not addressed and "*" in qual(node)
                else None
            )
            if allocation:
                return dict(kind="checked_fresh_allocation", object=decl["name"], **allocation)
    size = extent(node)
    if size and native_flow.field(node) and native_flow.field(map_arg) and (addressed or "[" in qual(node)):
        base_id = native_flow.direct_id(children(plain(map_arg))[0])
        members = []
        cur = node
        while cur.get("kind") == "MemberExpr":
            members.append(cur["name"])
            base = plain(children(cur)[0])
            if cur.get("isArrow"):
                if (
                    base_id
                    and native_flow.direct_id(base) == base_id
                    and bounded_count(count, size - offset, prefix)
                ):
                    return dict(
                        kind="inline_member", members=list(reversed(members)), capacity=size - offset
                    )
                break
            cur = base
    raise ValueError("output_extent_or_independent_object_unproved")


def check_direct_statement(fn, statement, call):
    kind = statement.get("kind")
    direct = statement is call
    if kind == "ReturnStmt":
        direct = plain(children(statement)[0]) is call
    if kind == "BinaryOperator" and statement.get("opcode") == "=":
        lhs, rhs = children(statement)
        direct = bool(native_flow.direct_id(lhs)) and plain(rhs) is call
    other_calls = any(n is not call and n.get("kind") == "CallExpr" for n in walk(statement))
    labels = any(n.get("kind") in {"GotoStmt", "IndirectGotoStmt", "LabelStmt"} for n in walk(fn))
    if not direct or other_calls or labels:
        raise ValueError("allocation_or_dynamic_count_control_flow_unproved")


def check_arguments(call):
    effects = any(
        n.get("opcode") in {"++", "--", "="}
        or n.get("kind")
        in {
            "CompoundAssignOperator",
            "StmtExpr",
            "AtomicExpr",
            "VAArgExpr",
            "GCCAsmStmt",
            "MSAsmStmt",
            "CallExpr",
        }
        for arg in children(call)[1:]
        for n in walk(arg)
    )
    if effects:
        raise ValueError("read_argument_has_unresolved_effects")


def bind_inputs(root, build, clang, path, sites):
    flags, cwd = compilation(root, build, path, clang)
    receipt, _, target, external = command_location(root, build, path)
    headers = valid_opt.public_inputs(root, build, clang, path)
    rel = path.relative_to(root).as_posix()
    if any(s["source"] != rel or s["source_sha256"] != headers["source/" + rel] for s in sites):
        raise ValueError("driver_source_changed")
    return dict(
        dependencies=headers,
        flags=flags,
        cwd=str(cwd),
        cmd_sha256=digest(receipt),
        object_sha256=digest(cwd / target),
        external_module=external,
    )


def analyze_unit(root, build, clang, path, rows):
    original = bind_inputs(root, build, clang, path, [])
    unit = native_flow.Translation(root, build, clang, path)
    by_offset = {r["offset"]: r for r in rows}
    code = api_opt._TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), unit.raw.decode("latin1"))
    arguments = {off: args for off, _, args in api_opt._calls(code)}
    sites = []
    for name, body_text in unit.index.items():
        if not re.search(r"\bregmap_bulk_read\s*\(", body_text):
            continue
        fn = unit.function(name)
        block = next(n for n in children(fn) if n.get("kind") == "CompoundStmt")
        for index, statement in enumerate(children(block)):
            for call in walk(statement):
                if native_flow.symbol(call) != api_emit.ORIGINAL.decode() or len(children(call)) != 5:
                    continue
                off = native_flow.spelled(call).get("offset")
                if off not in by_offset or off not in arguments:
                    continue
                row = by_offset[off]
                row.update(
                    function=name,
                    source_sha256=digest(path),
                    arguments=dict(zip(("map", "register", "destination", "value_count"), arguments[off])),
                )
                try:
                    _, m, reg, _, n = valid_opt.direct_call(unit, root, row)
                    check_arguments(call)
                    row.update(
                        map=map_object(m), register=native_flow.constant(reg), count=constant_size(n)
                    )
                    if row["count"] == 0:
                        raise ValueError("zero_count_original_error")
                    if row["count"] is not None and not 0 < row["count"] <= 2**31 - 1:
                        raise ValueError("count_outside_original_signed_loop")
                    if row["count"] is None:
                        check_count_parameter(fn, n)
                    prefix = list(children(block))[:index]
                    if row["count"] is None or plain(children(call)[3]).get("kind") == "DeclRefExpr":
                        check_direct_statement(fn, statement, call)
                    buffer = output_evidence(unit, root, fn, call, n, prefix)
                    row.update(decision="admit", reason="valid_map_length_and_output", buffer=buffer)
                except ValueError as err:
                    row["reason"] = str(err)
                sites.append(
                    dict(
                        source=row["source"],
                        offset=off,
                        source_sha256=row["source_sha256"],
                        decision=row["decision"],
                        reason=row["reason"],
                    )
                )
    if bind_inputs(root, build, clang, path, sites) != original:
        raise ValueError("driver_inputs_changed_during_analysis")
    return sites, original

"""Check a short-lived raw regmap from its constructor to its last use."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from .sixbyte_scan import _TRIVIA


API_HEADER = {
    "regmap_bulk_read": "regmap.h", "__regmap_init": "regmap.h",
    "regmap_exit": "regmap.h", "IS_ERR": "err.h", "PTR_ERR": "err.h",
}


class Unproved(Exception):
    def __init__(self, reason, detail):
        self.reason = reason
        self.detail = detail


def require(ok, reason, detail):
    if not ok:
        raise Unproved(reason, detail)


def children(node):
    return node.get("inner", ())


def walk(node):
    yield node
    for item in children(node):
        yield from walk(item)


def plain(node):
    while (node.get("kind") in {"ImplicitCastExpr", "ParenExpr", "ConstantExpr"}
           and len(children(node)) == 1):
        node = children(node)[0]
    return node


def ref(node):
    return plain(node).get("referencedDecl", {})


def integer(node):
    kind = node.get("kind")
    if kind == "DeclRefExpr" and node.get("referencedDecl", {}).get("kind") == "EnumConstantDecl":
        return node.get("kconc_enum_value")
    if kind == "ImplicitValueInitExpr":
        return 0
    if kind in {"IntegerLiteral", "CharacterLiteral", "ConstantExpr"} and "value" in node:
        return int(node["value"])
    if kind == "ParenExpr":
        return integer(children(node)[0])
    if kind == "ImplicitCastExpr" and node.get("castKind") in {
        "IntegralCast", "IntegralToBoolean", "NoOp", "NullToPointer",
    }:
        n = integer(children(node)[0])
        # All supported small integer fields, including a promoted u8, represent 0..127.
        # Larger values must survive narrowing too; unknown target integer types fail closed.
        t = node["type"].get("desugaredQualType", node["type"]["qualType"])
        upper = {"_Bool": 1, "bool": 1, "char": 127, "signed char": 127,
                 "unsigned char": 255, "short": 32767, "unsigned short": 65535,
                 "int": 2**31-1, "unsigned int": 2**32-1, "long": 2**63-1,
                 "unsigned long": 2**64-1, "unsigned long long": 2**64-1}.get(t)
        if n == 0 or (n is not None and upper is not None and 0 <= n <= upper):
            return n
    if kind == "CStyleCastExpr" and node.get("castKind") in {"NullToPointer", "NoOp"}:
        if integer(children(node)[0]) == 0:
            return 0
    return None


def zero(node):
    return integer(node) == 0


def addr(node):
    n = plain(node)
    if n.get("kind") == "UnaryOperator" and n.get("opcode") == "&":
        return ref(children(n)[0]).get("id")
    return None


def qual(node):
    return node.get("type", {}).get("qualType", "")


def bytes_array(node, const=False):
    prefix = "const " if const else ""
    m = re.fullmatch(prefix + r"(?:u8|__u8|unsigned char)\[(\d+)\]", qual(node))
    return int(m[1]) if m else None


def declarations(stream):
    """Clang pretty prints each top-level declaration at four spaces."""
    chunk = None
    for line in stream:
        if line.rstrip() == b"    {":
            chunk = [line]
        elif chunk is not None:
            if line.rstrip() in {b"    }", b"    },"}:
                chunk.append(b"}")
                yield json.loads(b"".join(chunk))
                chunk = None
            else:
                chunk.append(line)
    if chunk is not None:
        raise ValueError("Incomplete clang AST declaration")


def inspect_directives(raw):
    """Keep the authenticated API headers independent of TU-local preprocessing."""
    src = raw.decode("latin1").replace("\\\r\n", "").replace("\\\n", "")
    # Preserve literals as single tokens while blanking comments, including their newlines.
    clean = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith("/") else m[0], src)
    tokens = _TRIVIA.sub(lambda m: " " * len(m[0]), clean)
    if (re.search(r"\b(?:asm|__asm|__asm__|__attribute|__attribute__|__alias|__weak|_Pragma|__pragma)\b", tokens)
            or "%:" in tokens or "??=" in tokens):
        return "driver contains assembly, custom symbol attributes or alternate directives"
    includes_done = False
    for line in clean.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            directive = line[1:].strip()
            if directive.startswith("include"):
                approved = re.fullmatch(r"include\s*<(?:linux|asm|uapi|trace|dt-bindings)/[\w./-]+>", directive)
                if not approved or ".." in directive or includes_done:
                    return "requires unmodified kernel headers before driver declarations or definitions"
                continue
            if re.fullmatch(r"define\s+[A-Za-z]\w*\s+(?:\(?\s*(?:0[xX][\da-fA-F]+|\d+)[uUlL]*\s*\)?|\"[^\"\\]*\")", directive):
                name = directive.split()[1]
                if name.startswith(("CONFIG_", "KBUILD_", "MODULE_", "regmap_", "IS_ERR", "PTR_ERR")):
                    return "driver overrides a reserved build or API identifier"
            elif not re.match(r"(?:if|ifdef|ifndef|else|elif|endif)\b", directive):
                return "driver uses an unmodeled preprocessor directive"
        includes_done = True
    return None


def header_position(name, loc, data, path, actual_file):
    if not loc.get("includedFrom") or not data or actual_file != path:
        return False
    i = loc.get("offset", -1)
    token = name.encode()
    return i >= 0 and data[i:i+len(token)] == token


def explicit_files(value):
    # Clang elides a file name when its last emitted *physical* location used
    # the same file. includedFrom identifies the includer, never that location.
    if isinstance(value, dict):
        if "offset" in value and "file" in value:
            yield value["file"]
        for k, v in value.items():
            if k != "includedFrom":
                yield from explicit_files(v)
    elif isinstance(value, list):
        for v in value:
            yield from explicit_files(v)


def copy_declaration(decl, header, header_bytes, file):
    """The direct call must bind the compiler intrinsic or the real x86 ABI declaration."""
    if decl.get("kind") != "FunctionDecl" or decl.get("storageClass") != "extern":
        return None
    attrs = {n["kind"] for n in children(decl) if n["kind"].endswith("Attr")}
    if "BuiltinAttr" not in attrs or attrs - {"BuiltinAttr", "NoThrowAttr"} or body(decl):
        return None
    name = decl["name"]
    signature = qual(decl)
    if name == "__builtin_memcpy" and decl.get("isImplicit") and signature in {
            "void *(void *, const void *, unsigned long)", "void *(void *, const void *, __size_t)"}:
        return "clang_builtin_memcpy"
    if name != "memcpy" or signature != "void *(void *, const void *, __size_t)":
        return None
    loc = decl.get("loc", {})
    prototype = b"extern void *memcpy(void *to, const void *from, size_t len);"
    at = header_bytes.find(prototype)
    if (at < 0 or header_bytes.count(prototype) != 1 or loc.get("offset") != at + len(b"extern void *")
            or not header_position(name, loc, header_bytes, header, file)):
        return None
    return "linux_x86_64_memcpy"


class Unit:
    def __init__(self, source, raw, cwd, kernel, decls):
        self.globals = {}
        self.functions = {}
        self.records = {}
        self.api = {}
        self.enums = {}
        self.copy_decls = {}
        self.copy_redeclared = False
        self.source = source
        self.raw = raw
        self.directive_error = inspect_directives(raw)
        if kernel not in source.parents:
            raise ValueError("The translation unit must belong to the validated Kbuild source tree")
        header_dir = kernel / "include/linux"
        headers = {name: (header_dir / name).read_bytes() for name in set(API_HEADER.values())}
        copy_header = kernel / "arch/x86/include/asm/string_64.h"
        copy_bytes = copy_header.read_bytes()
        previous_file = None
        enum_values = {}
        for d in decls:
            name, kind, loc = d.get("name", ""), d.get("kind"), d.get("loc", {})
            physical = loc.get("file", previous_file)
            actual_file = (cwd / physical).resolve() if physical else None
            for previous_file in explicit_files(d):
                pass
            if kind == "FileScopeAsmDecl":
                loc = d.get("loc") or d.get("range", {}).get("begin", {})
                caller = loc.get("expansionLoc", loc)
                if not caller.get("includedFrom") and (caller.get("file") == str(source) or actual_file == source):
                    at = caller.get("offset", -1)
                    if at < 0 or not re.match(rb"EXPORT_SYMBOL(?:_GPL)?\b", raw[at:at+25]):
                        self.directive_error = "unmodeled file-scope assembly in driver"
            if kind == "EnumDecl":
                current = -1
                for c in children(d):
                    if c.get("kind") == "EnumConstantDecl":
                        self.enums[c["id"]] = c["name"]
                        vals = [x for x in children(c) if not x["kind"].endswith("Attr")]
                        current = integer(vals[0]) if vals else (current + 1 if current is not None else None)
                        enum_values[c["id"]] = current
            if not name:
                continue
            if name in {"regmap_config", "regmap_bus"} and kind == "RecordDecl" and d.get("completeDefinition"):
                if header_position(name, loc, headers["regmap.h"], header_dir / "regmap.h", actual_file):
                    self.records[name] = [n.get("name") for n in children(d) if n["kind"] == "FieldDecl"]
            if kind == "FunctionDecl" and name in API_HEADER:
                h = API_HEADER[name]
                if header_position(name, loc, headers[h], header_dir / h, actual_file):
                    self.api[d["id"]] = name
            if kind == "FunctionDecl" and name in {"memcpy", "__builtin_memcpy"}:
                contract = copy_declaration(d, copy_header, copy_bytes, actual_file)
                if contract is None:
                    self.copy_redeclared = True
                else:
                    self.copy_decls[d["id"]] = contract
            start = loc.get("offset", -1)
            spelled_here = (start >= 0 and not loc.get("includedFrom")
                            and actual_file == source
                            and raw[start:start+len(name)] == name.encode())
            if spelled_here and kind == "VarDecl":
                self.globals[d["id"]] = d
            if spelled_here and kind == "FunctionDecl" and body(d):
                self.functions[d["id"]] = d
            if spelled_here and kind in {"VarDecl", "FunctionDecl"}:
                for n in walk(d):
                    r = n.get("referencedDecl", {})
                    if r.get("kind") == "EnumConstantDecl":
                        n["kconc_enum_value"] = enum_values.get(r["id"])

    def api_call(self, n, name):
        return (n.get("kind") == "CallExpr" and bool(children(n))
                and self.api.get(ref(children(n)[0]).get("id")) == name)

    def copy_contract(self, callee):
        symbol = ref(callee)
        if symbol.get("kind") == "FunctionDecl" and not self.copy_redeclared:
            return self.copy_decls.get(symbol["id"])
        return None

    def fields(self, ident, tag):
        var = self.globals.get(ident, {})
        fields = self.records.get(tag)
        init = next((c for c in children(var) if c["kind"] == "InitListExpr"), {})
        require(var.get("storageClass") == "static" and qual(var) == "const struct " + tag
                and fields and len(fields) == len(children(init)) and all(fields),
                "initializer_unproved", "expected a const static " + tag + " with its complete C initializer")
        return dict(zip(fields, children(init)))


def body(fun):
    return next((n for n in children(fun) if n["kind"] == "CompoundStmt"), {})


def nested(node, target):
    return any(n is target for n in walk(node))


def local_pointer(n, ident):
    return bool(ident) and ref(n).get("id") == ident


def direct_count(n, buf):
    v = integer(n)
    if v is not None:
        return v
    n = plain(n)
    if (n.get("kind") == "UnaryExprOrTypeTraitExpr" and n.get("name") == "sizeof"
            and len(children(n)) == 1 and local_pointer(children(n)[0], buf)):
        return bytes_array(ref(children(n)[0]))
    return None


def literal_initializer(var, buffer_id):
    init = children(var)
    if not init:
        return True
    if len(init) != 1:
        return False
    expr = init[0]
    if integer(expr) is not None:
        return True
    if var["id"] != buffer_id or expr.get("kind") != "InitListExpr":
        return False
    elements = list(children(expr)) + list(expr.get("array_filler", ()))
    return all(isinstance(element, dict) and integer(element) is not None for element in elements)


def return_scalar(stmt, locals_=()):
    if stmt.get("kind") == "CompoundStmt" and len(children(stmt)) == 1:
        stmt = children(stmt)[0]
    if stmt.get("kind") != "ReturnStmt" or len(children(stmt)) != 1:
        return False
    return scalar(children(stmt)[0], locals_)


def error_return(stmt):
    if stmt.get("kind") == "CompoundStmt" and len(children(stmt)) == 1:
        stmt = children(stmt)[0]
    if stmt.get("kind") != "ReturnStmt" or len(children(stmt)) != 1:
        return False
    expr = plain(children(stmt)[0])
    return (expr.get("opcode") == "-" and expr.get("kind") == "UnaryOperator"
            and integer(children(expr)[0]) in range(1, 4096))


def scalar(n, ids):
    n = plain(n)
    k = n.get("kind")
    if k in {"IntegerLiteral", "CharacterLiteral"}:
        return True
    if k == "DeclRefExpr":
        return ref(n).get("id") in ids or ref(n).get("kind") == "EnumConstantDecl"
    if k == "UnaryOperator" and n.get("opcode") in {"!", "+", "-", "~"}:
        return scalar(children(n)[0], ids)
    if k == "BinaryOperator" and n.get("opcode") in {
        "==", "!=", "<", ">", "<=", ">=", "&&", "||", "+", "-", "&", "|", "^",
    }:
        return all(scalar(part, ids) for part in children(n))
    return False


def byte_dest(n, ptrs):
    n = plain(n)
    if n.get("kind") == "CStyleCastExpr":
        if qual(n) not in {"u8 *", "__u8 *", "unsigned char *"}:
            return False
        n = children(n)[0]
    return ref(n).get("id") in ptrs


def source_byte(unit, n, idx, scalars):
    n = plain(n)
    if scalar(n, scalars):
        return True
    if n.get("kind") != "ArraySubscriptExpr":
        return False
    base, sub = children(n)
    array = unit.globals.get(ref(base).get("id"), {})
    extent = bytes_array(array, const=True)
    return (array.get("storageClass") == "static" and extent is not None and extent >= 6
            and (local_pointer(sub, idx) if idx else integer(sub) in range(6)))


def byte_store(unit, n, ptrs, idx=None, scalars=()):
    if n.get("kind") != "BinaryOperator" or n.get("opcode") != "=":
        return False
    lhs, rhs = children(n)
    if lhs.get("kind") != "ArraySubscriptExpr" or qual(lhs) not in {"u8", "__u8", "unsigned char"}:
        return False
    base, sub = children(lhs)
    return (byte_dest(base, ptrs) and (local_pointer(sub, idx) if idx else integer(sub) in range(6))
            and source_byte(unit, rhs, idx, scalars))


def fill_loop(unit, n, ptrs, length, indices):
    # Clang retains an empty condition-variable slot in a C for statement.
    parts = children(n)
    if len(parts) != 5:
        return False
    init, empty, cond, step, store = parts
    if empty or cond.get("opcode") != "<" or step.get("opcode") != "++":
        return False
    if init.get("kind") == "DeclStmt" and len(children(init)) == 1:
        i = children(init)[0]
        if len(children(i)) != 1 or not zero(children(i)[0]):
            return False
    elif init.get("opcode") == "=" and zero(children(init)[1]):
        i = ref(children(init)[0])
        if i.get("id") not in indices:
            return False
    else:
        return False
    if qual(i) not in {"int", "unsigned int", "size_t", "unsigned long"}:
        return False
    idx = i["id"]
    a, b = children(cond)
    if not (local_pointer(a, idx) and (local_pointer(b, length) or integer(b) == 6)
            and local_pointer(children(step)[0], idx)):
        return False
    if store["kind"] == "CompoundStmt" and len(children(store)) == 1:
        store = children(store)[0]
    return byte_store(unit, store, ptrs, idx, {idx, length})


def callback_ok(unit, fld, reading):
    fun = unit.functions.get(ref(fld).get("id"), {})
    stmts = children(body(fun))
    pars = [c for c in children(fun) if c.get("kind") == "ParmVarDecl"]
    if (fun.get("storageClass") != "static" or len(pars) != (5 if reading else 3) or not stmts
            or unusual_function(fun)):
        return False
    if not reading:
        return len(stmts) == 1 and return_scalar(stmts[0])
    length = pars[4]["id"]
    scalars = {pars[2]["id"], length}
    ptrs, indices = {pars[3]["id"]}, set()
    initialized = set()
    for n in stmts[:-1]:
        k = n.get("kind")
        if k == "DeclStmt" and len(children(n)) == 1:
            var = children(n)[0]
            if var.get("storageClass") or any(p.get("kind", "").endswith("Attr") for p in children(var)):
                return False
            if len(children(var)) == 1 and qual(var) in {"u8 *", "__u8 *", "unsigned char *"}:
                if not byte_dest(children(var)[0], ptrs):
                    return False
                ptrs.add(var["id"])
            elif qual(var) in {"int", "unsigned int", "size_t", "unsigned long"} and not children(var):
                indices.add(var["id"])
            else:
                return False
        elif k == "IfStmt" and len(children(n)) == 2:
            if not scalar(children(n)[0], scalars) or not error_return(children(n)[1]):
                return False
        elif k == "ForStmt" and fill_loop(unit, n, ptrs, length, indices):
            initialized.update(range(6))
        elif byte_store(unit, n, ptrs):
            lhs = children(n)[0]
            initialized.add(integer(children(lhs)[1]))
        elif k == "CallExpr" and len(children(n)) == 4:
            callee, dst, src, count = children(n)
            glob = unit.globals.get(ref(src).get("id"), {})
            if not (unit.copy_contract(callee) and byte_dest(dst, ptrs)
                    and glob.get("storageClass") == "static" and (bytes_array(glob, True) or 0) >= 6
                    and (integer(count) == 6 or local_pointer(count, length))):
                return False
            initialized.update(range(6))
        else:
            return False
    return initialized == set(range(6)) and return_scalar(stmts[-1], scalars)


def unusual_function(fun):
    allowed = {"UnusedAttr", "UsedAttr", "NoInlineAttr", "AlwaysInlineAttr", "ColdAttr", "SectionAttr",
               "WarnUnusedResultAttr", "NoInstrumentFunctionAttr"}
    return any(c["kind"].endswith("Attr") and c["kind"] not in allowed for c in children(fun))


def enum_or_default(unit, n, choices):
    return zero(n) or unit.enums.get(ref(n).get("id")) in choices


def strict_fields(fields, allowed, why):
    for name, value in fields.items():
        if name not in allowed and not zero(value):
            raise Unproved(why, "unmodeled non-default field " + name)


def ctor_details(unit, init, row):
    args = children(init)[1:]
    require(len(args) == 6 and zero(args[0]) and zero(args[2]) and
            zero(args[4]) and zero(args[5]), "map_ownership_unproved",
            "expected NULL device, bus context and lockdep arguments")
    cfg = unit.fields(addr(args[3]), "regmap_config")
    bus = unit.fields(addr(args[1]), "regmap_bus")
    require(integer(cfg["reg_bits"]) == 8, "register_format_unproved", "register width is not eight bits")
    vbits = integer(cfg["val_bits"])
    endian = unit.enums.get(ref(cfg["val_format_endian"]).get("id"))
    start = row["register"]
    if vbits in {8, 16} and row["count"] is not None:
        row["byte_count"] = row["count"] * (vbits // 8)
    require(integer(cfg["disable_locking"]) == 1, "map_ownership_unproved",
            "the private constructor must disable debugfs registration via disable_locking")
    require(integer(cfg["reg_stride"]) in {0, 1} and enum_or_default(unit, cfg["cache_type"], {"REGCACHE_NONE"}),
            "raw_path_unproved", "requires unit stride and REGCACHE_NONE")
    limit = integer(cfg["max_register"])
    count = row["count"]
    require(start is not None and count is not None and count > 0 and 0 <= start <= 255
            and start+count-1 <= 255 and limit is not None and (limit == 0 or start+count-1 <= limit),
            "register_range_unproved", "consecutive registers must fit the selected address range")
    allowed_endian = {"REGMAP_ENDIAN_DEFAULT", "REGMAP_ENDIAN_BIG", "REGMAP_ENDIAN_LITTLE", "REGMAP_ENDIAN_NATIVE"}
    for fields, names in ((cfg, ("reg_format_endian", "val_format_endian")),
                          (bus, ("reg_format_endian_default", "val_format_endian_default"))):
        for name in names:
            require(enum_or_default(unit, fields[name], allowed_endian), "raw_path_unproved", "unknown " + name)
    allowed_cfg = {"reg_bits", "val_bits", "reg_stride", "disable_locking", "cache_type", "max_register",
                   "reg_format_endian", "val_format_endian"}
    if plain(cfg["name"]).get("kind") == "StringLiteral":
        allowed_cfg.add("name")
    strict_fields(cfg, allowed_cfg, "raw_path_unproved")
    strict_fields(bus, {"read", "write", "max_raw_read", "reg_format_endian_default", "val_format_endian_default"},
                  "bus_effects_unproved")
    if enum_or_default(unit, cfg["val_format_endian"], {"REGMAP_ENDIAN_DEFAULT"}):
        endian = unit.enums.get(ref(bus["val_format_endian_default"]).get("id"))
        if enum_or_default(unit, bus["val_format_endian_default"], {"REGMAP_ENDIAN_DEFAULT"}):
            endian = "REGMAP_ENDIAN_BIG"
    if vbits == 16 and endian == "REGMAP_ENDIAN_BIG" and ref(bus["read"]) and ref(bus["write"]):
        raise Unproved("callback_nonempty", "the raw constructor installs regmap_parse_16_be_inplace")
    require(vbits == 8, "callback_unproved", "value width does not establish the eight-bit empty converter")
    max_read = integer(bus["max_raw_read"])
    require(max_read is not None and (max_read == 0 or max_read >= 6), "raw_path_unproved", "bus may split read")
    require(callback_ok(unit, bus["read"], True), "bus_effects_unproved",
            "read callback is outside the bounded synchronous byte-store contract")
    require(callback_ok(unit, bus["write"], False), "bus_effects_unproved",
            "write callback is outside the side-effect-free return contract")
    reader = unit.functions[ref(bus["read"])["id"]]
    copies = {unit.copy_contract(children(n)[0]) for n in walk(body(reader)) if n.get("kind") == "CallExpr"}
    return {"constructor": "__regmap_init", "device": "NULL", "context": "NULL", "debugfs_disabled": True,
            "configuration": unit.globals[addr(args[3])]["name"], "bus": unit.globals[addr(args[1])]["name"],
            "read_callback": ref(bus["read"])["name"], "write_callback": ref(bus["write"])["name"],
            "val_bits": vbits, "cache_type": "REGCACHE_NONE", "raw_bytes": 6, "byte_copy_contracts": sorted(copies)}


def map_argument(n, ident):
    return len(children(n)) == 2 and local_pointer(children(n)[1], ident)


def check_guard(unit, stmt, ident):
    parts = children(stmt)
    if stmt.get("kind") != "IfStmt" or len(parts) != 2:
        return False
    cond, ret = parts
    if ret.get("kind") == "CompoundStmt" and len(children(ret)) == 1:
        ret = children(ret)[0]
    if ret.get("kind") != "ReturnStmt" or len(children(ret)) != 1:
        return False
    value = plain(children(ret)[0])
    return (unit.api_call(plain(cond), "IS_ERR") and map_argument(plain(cond), ident) and
            (scalar(value, ()) or unit.api_call(value, "PTR_ERR") and map_argument(value, ident)))


def standalone(stmt, expr):
    if stmt is expr:
        return True
    if stmt.get("kind") == "DeclStmt" and len(children(stmt)) == 1:
        var = children(stmt)[0]
        return var.get("kind") == "VarDecl" and len(children(var)) == 1 and plain(children(var)[0]) is expr
    return (stmt.get("kind") == "BinaryOperator" and stmt.get("opcode") == "="
            and ref(children(stmt)[0]).get("kind") == "VarDecl" and plain(children(stmt)[1]) is expr)


def check_site(unit, fun, call, row):
    parts = children(call)
    require(unit.directive_error is None, "translation_unit_features_unproved", unit.directive_error)
    require(not unusual_function(fun), "control_flow_unproved", "caller has an unmodeled function attribute")
    require(len(parts) == 5 and unit.api_call(call, "regmap_bulk_read"), "api_binding_unproved",
            "callee declaration is not the in-tree regmap API")
    require(row["direct_spelling"], "macro_call", "call must be directly spelled in the driver source")
    mapid, bufid = ref(parts[1]).get("id"), ref(parts[3]).get("id")
    stmts = children(body(fun))
    variables = {n["id"]: n for n in walk(fun) if n.get("kind") == "VarDecl"}
    var = variables.get(mapid, {})
    require(qual(var) == "struct regmap *" and not var.get("storageClass"), "map_alias_unproved",
            "first argument is not an automatic local map")
    definitions = []
    for i, stmt in enumerate(stmts):
        for n in walk(stmt):
            if unit.api_call(n, "__regmap_init") and standalone(stmt, n):
                lhs = children(stmt)[0]
                bound = lhs.get("id") if stmt["kind"] == "DeclStmt" else ref(lhs).get("id")
                if bound == mapid:
                    definitions.append((i, n))
    require(len(definitions) == 1, "map_alias_unproved", "a single local map constructor does not reach this call")
    ctor_idx, init = definitions[0]
    info = ctor_details(unit, init, row)
    buf = variables.get(bufid, {})
    require(bytes_array(buf) == 6 and not buf.get("storageClass"), "buffer_extent_unproved",
            "destination must be a local array of six bytes")
    require(row["count"] == 6, "count_unproved", "the call must request exactly six eight-bit values")
    guard_idx = ctor_idx+1
    require(guard_idx < len(stmts) and check_guard(unit, stmts[guard_idx], mapid), "error_guard_unproved",
            "a returning IS_ERR check must immediately follow initialization")
    exits = [(i, n) for i, n in enumerate(stmts) if unit.api_call(n, "regmap_exit") and map_argument(n, mapid)]
    require(len(exits) == 1, "map_alias_unproved", "a single unconditional regmap_exit must release the local map")
    exit_idx, release = exits[0]
    uses = sorted(n["id"] for n in walk(fun) if n.get("kind") == "DeclRefExpr" and ref(n).get("id") == mapid)
    allowed = [stmts[guard_idx], parts[1], release]
    if stmts[ctor_idx]["kind"] == "BinaryOperator":
        allowed.append(children(stmts[ctor_idx])[0])
    known = sorted(n["id"] for x in allowed for n in walk(x)
                   if n.get("kind") == "DeclRefExpr" and ref(n).get("id") == mapid)
    if uses != known:
        extra = set(uses) - set(known)
        sites = [ref(children(n)[0]).get("name", "<indirect>") for n in walk(fun)
                 if n.get("kind") == "CallExpr" and children(n)
                 and any(q.get("id") in extra for q in walk(n))]
        for n in walk(fun):
            if n.get("kind") == "BinaryOperator" and n.get("opcode") == "=":
                lhs, rhs = children(n)
                if any(q.get("id") in extra for q in walk(rhs)):
                    sites.append("assignment to " + (ref(lhs).get("name") or lhs.get("name") or "<lvalue>"))
        raise Unproved("map_alias_unproved", "map is used outside constructor, guard, read and exit"
                       + (" by " + ", ".join(sorted(set(sites))) if sites else " in another expression"))
    idx = next(i for i, stmt in enumerate(stmts) if nested(stmt, call))
    require(guard_idx < idx < exit_idx and standalone(stmts[idx], call), "control_flow_unproved",
            "requires an unconditional read on the successful constructor path")
    if stmts[idx]["kind"] == "BinaryOperator":
        lhs = ref(children(stmts[idx])[0])
        require(lhs.get("id") in variables and not variables[lhs["id"]].get("storageClass")
                and qual(lhs) == "int", "control_flow_unproved", "read status must bind an automatic local int")
        row["ret"] = lhs["name"]
    if stmts[idx]["kind"] == "DeclStmt":
        status = children(stmts[idx])[0]
        require(not status.get("storageClass") and qual(status) == "int", "control_flow_unproved",
                "read status must initialize an automatic local int")
        row["ret"] = status["name"]
    buf_refs = [n for stmt in stmts[:exit_idx+1] for n in walk(stmt)
                if n.get("kind") == "DeclRefExpr" and ref(n).get("id") == bufid]
    require(all(nested(parts[3], n) or nested(parts[4], n) for n in buf_refs),
            "buffer_alias_unproved", "a destination alias is used before release")
    for i, stmt in enumerate(stmts[:exit_idx]):
        if i in {ctor_idx, guard_idx, idx}:
            continue
        require(stmt["kind"] == "DeclStmt" and all(
            v.get("kind") == "VarDecl" and not v.get("storageClass") and
            (v.get("id") in {mapid, bufid} or qual(v) in {
                "int", "unsigned int", "size_t", "unsigned long", "u8", "unsigned char"})
            and literal_initializer(v, bufid)
            for v in children(stmt)), "control_flow_unproved",
            "only unescaped automatic locals may precede the read and release")
    forbidden = {"LabelStmt", "GotoStmt", "IndirectGotoStmt", "GCCAsmStmt", "MSAsmStmt", "AddrLabelExpr",
                 "CleanupAttr", "CapturedStmt", "StmtExpr"}
    require(not any(n.get("kind") in forbidden for n in walk(fun)), "control_flow_unproved",
            "non-local control flow, cleanup or inline assembly in the caller")
    row["byte_count"] = 6
    row["evidence"] = info | {"map": var["name"], "buffer": buf["name"], "release": "regmap_exit",
                              "result": "same call expression and return status"}


def analyze(source: Path, clang: Path, flags: list, cwd: Path, kernel_root: Path = None):
    """Read the authenticated TU. The caller locks the compilation command and include tree."""
    cwd = Path(cwd).resolve()
    source = (cwd / source).resolve(strict=True)
    if kernel_root is None:
        # A stand-alone calibration can discover an in-tree source; production
        # passes the root authenticated by the Kbuild input checker explicitly.
        kernel_root = next((p for p in source.parents if (p / "include/linux/regmap.h").is_file()
                            and (p / "drivers/base/regmap/regmap.c").is_file()), None)
        if kernel_root is None:
            raise ValueError("Kernel source root is unavailable")
    kernel = Path(kernel_root).resolve(strict=True)
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    with tempfile.TemporaryFile("w+b") as stream:
        cmd = [str(clang), *flags, "-fsyntax-only", "-fno-color-diagnostics",
               "-Xclang", "-ast-dump=json", str(source)]
        result = subprocess.run(cmd, cwd=cwd, stdout=stream, stderr=subprocess.PIPE)
        if result.returncode:
            raise ValueError("Clang AST failed: " + result.stderr.decode(errors="replace")[-4000:])
        stream.seek(0)
        unit = Unit(source, raw, cwd, kernel, declarations(stream))
    rows = []
    for fun in unit.functions.values():
        for call in walk(body(fun)):
            if call.get("kind") != "CallExpr" or not children(call):
                continue
            callee = plain(children(call)[0])
            if ref(callee).get("name") != "regmap_bulk_read":
                continue
            loc = callee.get("range", {}).get("begin", {})
            offset = loc.get("offset", loc.get("expansionLoc", {}).get("offset", -1))
            direct = "offset" in loc and raw[offset:offset+16] == b"regmap_bulk_read" and not loc.get("includedFrom")
            parts = children(call)
            count = direct_count(parts[4], ref(parts[3]).get("id")) if len(parts) == 5 else None
            target = None
            for stmt in children(body(fun)):
                if standalone(stmt, call):
                    if stmt.get("kind") == "DeclStmt":
                        target = children(stmt)[0]["name"]
                    elif stmt.get("kind") == "BinaryOperator":
                        target = ref(children(stmt)[0]).get("name")
                    break
            row = {"source": source.as_posix(), "source_sha256": digest, "offset": offset,
                   "direct_spelling": direct, "function": fun["name"], "register": integer(parts[2]) if len(parts)>2 else None,
                   "count": count, "byte_count": None, "decision": "keep_original", "ret": target, "evidence": {}}
            try:
                check_site(unit, fun, call, row)
            except Unproved as error:
                row.update(reason=error.reason, reason_detail=error.detail)
            else:
                row.update(decision="admit", reason="private_raw_eight_bit", reason_detail="private synchronous read of six bytes")
            rows.append(row)
    return sorted(rows, key=lambda row: row["offset"])

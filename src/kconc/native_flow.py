"""Recover source-level IIO probe/trigger edges for conservative regmap admission."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from .api_flow import children, declarations, integer, plain, ref, walk
from . import api_inputs
from .api_kbuild import command_location, compilation
from .sixbyte_scan import _TRIVIA, _calls


# Lexical indexing selects declarations to request from Clang. It supplies no
# field identity, C types, callback identity or conclusion about reachable runs.
DEFINITION = re.compile(r"^\w[\w\s*]*?\b(\w+)\s*\([^;{}]*?\)\s*\{", re.M)


def bodies(raw):
    text = raw.decode("latin1")
    code = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), text)
    out = {}
    for match in DEFINITION.finditer(code):
        count = 1
        for brace in re.compile(r"[{}]").finditer(code, match.end()):
            count += 1 if brace[0] == "{" else -1
            if count == 0:
                out[match[1]] = code[match.end():brace.start()]
                break
    return out


def spelled(node):
    start = node.get("range", {}).get("begin", {})
    return start.get("expansionLoc", start)


def field(node):
    value = plain(node)
    return value.get("referencedMemberDecl") if value.get("kind") == "MemberExpr" else None


def symbol(node):
    if node.get("kind") != "CallExpr" or not children(node):
        return None
    return ref(children(node)[0]).get("name")


def direct_id(node):
    return ref(node).get("id")


def bindings(fn):
    """Assignments and initializers retain TU-local declaration IDs."""
    for n in walk(fn):
        if n.get("kind") == "VarDecl" and n.get("init") and children(n):
            yield n["id"], n, plain(children(n)[-1])
        if n.get("kind") == "BinaryOperator" and n.get("opcode") == "=":
            left, right = children(n)
            yield direct_id(left), left, plain(right)


def constant(n):
    """Evaluate constant counts for the pinned x86_64 ABI. Counts are in values."""
    direct = integer(n)
    if direct is not None:
        return direct
    n = plain(n)
    items = children(n)
    if n.get("kind") == "UnaryExprOrTypeTraitExpr" and n.get("name") == "sizeof":
        t = n.get("argType") or (items[0].get("type", {}) if items else {})
        name = t.get("desugaredQualType", t.get("qualType", ""))
        m = re.fullmatch(r"(?:const )?([\w ]+?)(?:\[(\d+)\])?", name)
        if m:
            # Clang retains the typedef in array element spellings.
            sizes = {"char": 1, "signed char": 1, "unsigned char": 1, "u8": 1, "s8": 1,
                     "__u8": 1, "__s8": 1, "short": 2, "unsigned short": 2, "__le16": 2,
                     "__be16": 2, "__u16": 2, "u16": 2, "s16": 2, "int": 4,
                     "unsigned int": 4, "__le32": 4, "u32": 4, "__u32": 4}
            size = sizes.get(m[1])
            if size:
                return size * int(m[2] or 1)
    if n.get("kind") == "BinaryOperator" and n.get("opcode") in {"*", "+"}:
        lhs, rhs = map(constant, items)
        if lhs is not None and rhs is not None:
            return lhs * rhs if n["opcode"] == "*" else lhs + rhs
    return None


class Translation:
    def __init__(self, kernel, obj, clang, path):
        self.path = path
        self.clang = clang
        self.relative = path.relative_to(kernel).as_posix()
        self.raw = path.read_bytes()
        self.index = bodies(self.raw)
        self.flags, self.cwd = compilation(kernel, obj, path, clang)
        self.functions = {}
        self.named = {}

    def declarations(self, name):
        if name in self.named:
            return self.named[name]
        args = [str(self.clang), *self.flags, "-fsyntax-only", "-fno-color-diagnostics",
                "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", name,
                str(self.path)]
        p = subprocess.run(args, cwd=self.cwd, capture_output=True, timeout=120)
        if p.returncode:
            raise ValueError("Clang failed for " + self.relative + ": " + p.stderr.decode(errors="replace")[-1200:])
        text = p.stdout.decode()
        decoder = json.JSONDecoder()
        i = 0
        found = []
        while i < len(text):
            if text[i].isspace():
                i += 1
                continue
            n, i = decoder.raw_decode(text, i)
            if n.get("name") == name:
                found.append(n)
        self.named[name] = found
        return found

    def function(self, name):
        if name in self.functions:
            return self.functions[name]
        found = [n for n in self.declarations(name) if n.get("kind") == "FunctionDecl" and
                 (self.cwd / n.get("loc",{}).get("file", "")).resolve() == self.path and
                 any(c.get("kind") == "CompoundStmt" for c in children(n))]
        if len(found) != 1:
            raise ValueError(f"Expected one compiled definition of {name} in {self.relative}")
        self.functions[name] = found[0]
        return found[0]

    def initializer(self, tag, name):
        defs = [d for d in self.declarations(name) if d.get("kind") == "VarDecl" and
                d.get("type",{}).get("qualType") == "const struct "+tag and
                (self.cwd / d.get("loc",{}).get("file", "")).resolve() == self.path]
        inits = [c for d in defs for c in children(d) if c.get("kind") == "InitListExpr"]
        records = [d for d in self.declarations(tag) if d.get("kind") == "RecordDecl"
                   and d.get("completeDefinition")]
        if len(inits) != 1 or len(records) != 1:
            return {}
        fields = [c.get("name") for c in children(records[0]) if c.get("kind") == "FieldDecl"]
        if len(fields) != len(children(inits[0])) or not all(fields):
            return {}
        return dict(zip(fields,children(inits[0])))

    def location(self, n, **more):
        loc = spelled(n)
        pos = loc.get("offset", -1)
        if pos < 0 or pos >= len(self.raw):
            raise ValueError("No direct source range for a driver edge")
        line = self.raw.count(b"\n", 0, pos) + 1
        return dict(source=self.relative, line=line, offset=pos,
                    text=self.raw.splitlines()[line-1].decode(errors="replace").strip(), **more)


def signatures(member):
    base = plain(children(member)[0]) if children(member) else {}
    return (member.get("name"), member.get("type", {}).get("qualType"),
            base.get("type", {}).get("qualType"))


def private_recovery(unit, fn, member):
    """Find the poll argument -> iio_dev -> private data used by this exact load."""
    base = direct_id(children(member)[0])
    rows = list(bindings(fn))
    for lhs, _, call in rows:
        if lhs != base or symbol(call) != "iio_priv":
            continue
        args = children(call)
        idev = direct_id(args[1]) if len(args) == 2 else None
        for target, _, rhs in rows:
            if target != idev or not field(rhs) or rhs.get("name") != "indio_dev":
                continue
            src = plain(children(rhs)[0])
            if src.get("type", {}).get("qualType") != "struct iio_poll_func *":
                continue
            for pf, _, value in rows:
                if pf == direct_id(src) and ref(value).get("kind") == "ParmVarDecl":
                    return [unit.location(value, edge="poll_function_argument"),
                            unit.location(rhs, edge="poll_function_iio_device"),
                            unit.location(call, edge="iio_private_storage")]
    return []


def core_edges(unit, fn, handler, member):
    rows = list(bindings(fn))
    params = [c for c in children(fn) if c.get("kind") == "ParmVarDecl"]
    for _, left, right in rows:
        if not field(left) or signatures(plain(left)) != signatures(member):
            continue
        private_id = direct_id(children(plain(left))[0])
        for receiver, _, call in rows:
            if receiver != private_id or symbol(call) != "iio_priv":
                continue
            idev = direct_id(children(call)[1])
            alloc = [expr for dest, _, expr in rows if dest == idev and symbol(expr) in
                     {"devm_iio_device_alloc", "__devm_iio_device_alloc"}]
            registrations = []
            for expr in walk(fn):
                if symbol(expr) not in {"devm_iio_triggered_buffer_setup_ext", "devm_iio_triggered_buffer_setup"}:
                    continue
                a = children(expr)[1:]
                if len(a) >= 4 and direct_id(a[1]) == idev and any(
                    ref(n).get("kind") == "FunctionDecl" and ref(n).get("name") == handler
                    for n in walk(a[3])):
                    same_device = any(direct_id(children(e)[1]) == direct_id(a[0])
                                      for e in alloc if len(children(e)) > 1 and direct_id(a[0]))
                    registrations.append(unit.location(expr, edge="register_trigger_handler", handler=handler,
                                                       same_device_argument_as_allocation=same_device))
            if not alloc or not registrations:
                continue
            arg = next((i for i, param in enumerate(params) if param["id"] == direct_id(right)), None)
            lookups = [expr for dest, _, expr in rows if dest == direct_id(right) and symbol(expr) == "dev_get_regmap"]
            result = dict(function=fn["name"], map_parameter=arg,
                          allocation=unit.location(alloc[0], edge="managed_iio_alloc"),
                          private=unit.location(call, edge="private_owner_for_assignment"),
                          store=unit.location(left, edge="store_map_in_private_field"),
                          registrations=registrations)
            result["registry_lookup"] = [unit.location(e, edge="device_regmap_lookup",
                unnamed=integer(children(e)[2]) == 0) for e in lookups]
            return result
    return None


def addressed_name(n):
    n = plain(n)
    if n.get("kind") == "UnaryOperator" and n.get("opcode") == "&":
        return ref(children(n)[0]).get("name")
    return None


def constructor_uses(unit, fn, core):
    stored = []
    for dest, lhs, call in bindings(fn):
        api = symbol(call)
        if api and re.fullmatch(r"__?devm_regmap_init(?:_\w+)?|devm_regmap_init(?:_\w+)?", api):
            where = unit.location(call, edge="managed_regmap_constructor", api=api)
            for value in children(call)[1:]:
                qtype = value.get("type",{}).get("qualType")
                if qtype == "const struct regmap_config *":
                    arg = plain(value)
                    where["configuration"] = dict(global_name=addressed_name(arg),
                        member=arg.get("name") if field(arg) else None,
                        owner_type=signatures(arg)[2] if field(arg) else None)
                if qtype == "const struct regmap_bus *":
                    where["bus_object"] = addressed_name(value)
            stored.append((dest, where))
    edges = []
    for n in walk(fn):
        if symbol(n) != core["function"]:
            continue
        idx = core["map_parameter"]
        actual = direct_id(children(n)[idx+1]) if idx is not None and idx+1 < len(children(n)) else None
        for dest, where in stored:
            edges.append(dict(constructor=where, core_call=unit.location(n, edge="call_core_probe"),
                              same_map_argument=bool(dest and dest == actual),
                              argument_evidence="same_local_declaration" if dest and dest == actual else "not_passed",
                              wrapper=fn["name"], wrapper_type=fn.get("type", {}).get("qualType")))
    return edges


def frontends(kernel, obj, clang, source, core):
    """Index companion TUs, including unbuilt transport bindings as source-only leads."""
    target = core["function"]
    word = re.compile(rb"\b"+re.escape(target.encode())+rb"\s*\(")
    result = []
    for path in sorted(source.parent.glob("*.c")):
        if path == source or path.resolve() != path:
            continue
        raw = path.read_bytes()
        if not word.search(raw):
            continue
        names = [name for name, text in bodies(raw).items() if word.search(text.encode("latin1"))]
        if not names:
            continue
        try:
            unit = Translation(kernel, obj, clang, path)
            for name in names:
                fn = unit.function(name)
                edges = constructor_uses(unit, fn, core)
                if not edges:
                    for n in walk(fn):
                        if symbol(n) == target:
                            edges.append(unit.location(n, status="compiled_core_reference",
                                                       reason="managed_constructor_not_linked"))
                result.extend(edges)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            for m in word.finditer(raw):
                result.append(dict(source=path.relative_to(kernel).as_posix(), line=raw.count(b"\n",0,m.start())+1,
                                   status="unverified_source_reference", reason=str(exc)))
    return result


def configurations(core_unit, edges, address_expr):
    """Give widths in observed constant descriptors, without assuming closed dispatch."""
    observed = set()
    descriptors = {}
    for entry in edges:
        cfg = entry.get("constructor", {}).get("configuration", {})
        if cfg.get("global_name"):
            observed.add(cfg["global_name"])
        t = re.fullmatch(r"const struct (\w+) \*", cfg.get("owner_type") or "")
        if not t or not cfg["member"]:
            continue
        tag = t[1]
        pattern = rb"\bconst\s+struct\s+"+tag.encode()+rb"\s+(\w+)\s*=\s*\{"
        for match in re.finditer(pattern, core_unit.raw):
            name = match[1].decode()
            values = core_unit.initializer(tag, name)
            expr = values.get(cfg["member"])
            if expr is None or not (config := addressed_name(expr)):
                continue
            observed.add(config)
            detail = core_unit.location(expr, edge="descriptor_configuration", descriptor=name, config=config)
            if field(address_expr) and signatures(plain(address_expr))[2] == cfg["owner_type"]:
                address = values.get(plain(address_expr)["name"])
                if address is not None:
                    detail["start_register"] = constant(address)
                    detail["address_source"] = core_unit.location(address)
            descriptors[name] = detail
    result = []
    for name in sorted(observed):
        fields = core_unit.initializer("regmap_config", name)
        if "val_bits" in fields:
            val = fields["val_bits"]
            result.append(core_unit.location(val, edge="configuration_value_width", config=name,
                val_bits=constant(val), reg_bits=constant(fields.get("reg_bits",{}))))
    return dict(known_configs=result, known_descriptors=list(descriptors.values()),
                declared_values_only=True)


def field_effects(node):
    """Yields immediate lvalue mutations and address creation, including macro expansions."""
    kind, op = node.get("kind"), node.get("opcode")
    effect = None
    if kind == "BinaryOperator" and op == "=":
        effect = "assignment"
    elif kind == "CompoundAssignOperator" or kind == "UnaryOperator" and op in {"++", "--"}:
        effect = "read_modify_write"
    elif kind in {"UnaryOperator", "AtomicExpr"} and op == "&":
        effect = "field_address_taken"
    if effect and children(node):
        operand = plain(children(node)[0])
        if field(operand):
            yield field(operand), operand, effect


def write_inventory(unit, sites):
    """Use one Clang process so field declaration IDs are comparable throughout the TU."""
    wanted = {r["offset"] for r in sites if r["count"] == 6 and r["map_field"]}
    if not wanted:
        return {}
    command = [str(unit.clang), *unit.flags, "-fsyntax-only", "-fno-color-diagnostics",
               "-Xclang","-ast-dump=json",str(unit.path)]
    selected, effects = {}, {}
    definitions = 0
    with tempfile.TemporaryFile("w+b") as stream:
        run = subprocess.run(command,cwd=unit.cwd,stdout=stream,stderr=subprocess.PIPE,timeout=150)
        if run.returncode:
            raise ValueError("Complete translation unit failed: "+run.stderr.decode(errors="replace")[-1200:])
        stream.seek(0)
        for decl in declarations(stream):
            if decl.get("kind")!="FunctionDecl" or not any(c.get("kind")=="CompoundStmt" for c in children(decl)):
                continue
            definitions += 1
            name, loc = decl.get("name",""), decl.get("loc",{})
            start = loc.get("offset",-1)
            main = start >= 0 and not loc.get("includedFrom") and (
                not loc.get("file") or (unit.cwd / loc["file"]).resolve()==unit.path) and (
                unit.raw[start:start+len(name)]==name.encode())
            for n in walk(decl):
                if main and symbol(n) == "regmap_bulk_read" and len(children(n)) == 5:
                    pos = spelled(n).get("offset")
                    if pos in wanted:
                        selected[pos]=field(children(n)[1])
                for ident, operand, effect in field_effects(n):
                    if operand.get("type",{}).get("qualType")!="struct regmap *":
                        continue
                    if main:
                        value = unit.location(operand, edge=effect, function=name)
                    else:
                        value = {"edge":effect,"function":name,"kind":"outside_spelled_main_function",
                                 "clang_location":spelled(operand)}
                    effects.setdefault(ident,[]).append(value)
    return {pos:{"functions_examined":definitions,"method":"same_clang_field_declaration_id",
                 "resolved":bool(ident), "direct_writes_and_address_uses":effects.get(ident,[]),
                 "indirect_aliases_closed":False} for pos,ident in selected.items()}


def analyze(root: Path, obj: Path, clang: Path, source: Path):
    """Report observed typed edges, separately from still-open environment obligations."""
    kernel = Path(root).resolve(strict=True)
    path = (kernel / source).resolve(strict=True)
    if kernel/"drivers" not in path.parents or path.suffix != ".c":
        raise ValueError("Expected a C translation unit under drivers/")
    unit = Translation(kernel, Path(obj).resolve(strict=True), Path(clang), path)
    rows = []
    code = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), unit.raw.decode("latin1"))
    spelled_arguments = {offset:args for offset, _, args in _calls(code)}
    hashes = hashlib.sha256(unit.raw).hexdigest()
    possible_owners = [name for name, text in unit.index.items()
                       if re.search(r"\bdevm_iio_device_alloc\s*\(", text)]
    for name, text in unit.index.items():
        if not re.search(r"\bregmap_bulk_read\s*\(", text):
            continue
        fn = unit.function(name)
        for call in walk(fn):
            if symbol(call) != "regmap_bulk_read" or len(children(call)) != 5:
                continue
            _, maparg, addr, destination, countarg = children(call)
            site = unit.location(call)
            row = dict(**site, function=name, source_sha256=hashes, count=constant(countarg),
                       register=constant(addr), map_field=None, private_path=[], owners=[],
                       byte_length=None, obligations=[], decision="keep_original")
            args = spelled_arguments.get(site["offset"],())
            row["arguments"] = dict(zip(("map","register","destination","value_count"),args))
            row["destination_source_type"] = plain(destination).get("type",{}).get("qualType")
            if field(maparg):
                member = plain(maparg)
                row["map_field"] = {"name": member["name"], "type": member["type"]["qualType"],
                                    "receiver": signatures(member)[2]}
                if row["count"] == 6:
                    row["private_path"] = private_recovery(unit, fn, member)
                    for factory in possible_owners:
                        owner = core_edges(unit, unit.function(factory), name, member)
                        if owner:
                            owner["frontends"] = frontends(kernel, obj, clang, path, owner)
                            owner["formats"] = configurations(unit, owner["frontends"], plain(addr))
                            row["owners"].append(owner)
            if row["count"] != 6:
                row["obligations"].append({"why":"value_count_unknown_or_not_six", "location":site})
            else:
                if not row["private_path"] or not row["owners"]:
                    row["obligations"].append({"why":"private_object_provenance_unestablished", "location":site})
                for owner in row["owners"]:
                    for lookup in owner["registry_lookup"]:
                        row["obligations"].append({"why":"registry_identity_requires_resolution","location":lookup})
                    row["obligations"].append({"why":"all_reaching_bindings_and_field_writers_must_be_checked",
                                                "location":owner["store"]})
                row["obligations"].append({"why":"lifetime_and_callback_write_exclusion_required","location":site})
            rows.append(row)
    writes = write_inventory(unit, rows)
    for row in rows:
        if row["offset"] in writes:
            row["field_inventory"] = writes[row["offset"]]
        if row["count"] is not None and row["map_field"]:
            widths = {c["val_bits"] for other in rows if other["map_field"]==row["map_field"]
                      for owner in other["owners"] for c in owner["formats"]["known_configs"]}
            row["byte_lengths_for_observed_configs"] = sorted(
                {row["count"]*(n//8) for n in widths if n and n%8==0})
    return sorted(rows,key=lambda r:r["offset"])


def bind_native_inputs(root, obj, clang, source, rows):
    """Replay each observed compiled TU's dependency scan in its original Kbuild context."""
    root, obj, clang = (Path(p).resolve(strict=True) for p in (root, obj, clang))
    core = root / source
    if core != core.resolve(strict=True) or root / "drivers" not in core.parents or core.suffix != ".c":
        raise ValueError("Expected a physical in-tree driver source")
    shared = api_inputs.verify(root, obj, obj / ".config", clang)
    core_key = core.relative_to(root).as_posix()
    units = {core_key: "core"}
    leads = {}
    for site in rows:
        if site.get("source") != core_key or site.get("source_sha256") != api_inputs.file_hash(core):
            raise ValueError("Native site provenance belongs to another driver or source revision")
        for owner in site["owners"]:
            for entry in owner["frontends"]:
                location = entry.get("constructor", entry)
                relative = location["source"]
                path = root / relative
                if (path != path.resolve(strict=True) or path.parent != core.parent or path.suffix != ".c"
                        or path.relative_to(root).as_posix() != relative):
                    raise ValueError("Native frontend source is outside the observed driver directory")
                target = path.with_suffix(".o").relative_to(root)
                receipt = obj / target.parent / ("." + target.name + ".cmd")
                standalone = path.with_name("." + path.stem + ".o.cmd")
                if not (receipt.exists() or standalone.exists()) and entry.get("status") == "unverified_source_reference":
                    leads.setdefault(relative, []).append({"line": location["line"], "reason": entry["reason"]})
                else:
                    units[relative] = "frontend"

    bound = {}
    for relative, role in sorted(units.items()):
        path = root / relative
        flags, cwd = compilation(root, obj, path, clang)
        receipt, _, target, external = command_location(root, obj, path)
        if external:
            raise ValueError("External-module receipt does not bind the native kernel build")
        cmd_hash = api_inputs.file_hash(receipt)
        headers = api_inputs.observe_driver_dependencies(root, obj, path, clang, flags, cwd)
        if headers.get("build/include/generated/autoconf.h") != shared["generated_files"]["include/generated/autoconf.h"]:
            raise ValueError("Clang did not consume the bound generated configuration")
        if cmd_hash != api_inputs.file_hash(receipt) or headers["source/" + relative] != api_inputs.file_hash(path):
            raise ValueError("Source or Kbuild receipt changed during native dependency scan")
        bound[relative] = {
            "role": role, "source_sha256": headers["source/" + relative],
            "receipt": receipt.relative_to(obj).as_posix(), "receipt_sha256": cmd_hash,
            "object": target.as_posix(), "object_sha256": api_inputs.file_hash(cwd / target),
            "compiler": str(clang), "compiler_sha256": shared["clang_sha256"],
            "cwd": str(cwd), "analysis_flags": flags, "dependencies": headers,
            "driver_headers": {k[7:]: v for k, v in headers.items() if k.startswith("driver/")},
        }
    return {"shared_identity": shared, "translation_units": bound, "source_only": leads}

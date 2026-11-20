"""Specialize direct IIO reads under the ordinary live-regmap API contract."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from . import api_emit, api_inputs, api_opt, native_contracts, native_flow, valid_emit
from .api_flow import children, plain, ref, walk
from .api_kbuild import compilation
from .cli import OperationError, digest, new_output, save
from .sixbyte import _publish_overlay


def slot_contract(root):
    core = root / api_emit.REGMAP
    expected, locations = native_contracts.FRAMEWORK[api_emit.REGMAP]
    if digest(core) != expected:
        raise ValueError("Unreviewed regmap implementation")
    lines = core.read_text().splitlines()
    facts = {name: [{"line": i, "text": lines[i-1].strip()} for i in positions]
             for name, positions in locations.items()}
    assignments = [i for i, line in enumerate(lines, 1) if re.search(r"\bparse_inplace\s*=(?!=)", line)]
    if assignments != [e["line"] for e in facts["format_initialization"]]:
        raise ValueError("Unreviewed converter assignments")
    return {"slot": "struct regmap.format.parse_inplace", "writes": facts["format_initialization"],
            "publish": facts["publish"], "reinit_cache": facts["reinit_cache"],
            "read_window": facts["read_window"], "source_sha256": digest(core),
            "private_layout_sha256": digest(core.parent/"internal.h"),
            "public_header_sha256": digest(root/api_emit.HEADER),
            "noop_definition": [{"line": i, "text": lines[i-1].strip()} for i in range(314,318)],
            "api_premises": ["the actual map remains alive for the original bulk read",
                             "driver and bus use documented operations and write only authorized output bytes",
                             "no concurrent raw mutation of regmap private storage or instrumentation changing callback effects",
                             "callback entries required for observation select callback-preserving boot mode"],
            "scope": "defined executions of the locked Linux regmap API"}


def inline_output(destination, map_arg):
    """Trace a fixed-size member array back to the same IIO private object as the map field."""
    dest = plain(destination)
    if dest.get("kind") == "UnaryOperator" and dest.get("opcode") == "&":
        dest = plain(children(dest)[0])
    value_type = dest.get("type", {}).get("qualType", "")
    size = native_flow.constant({"kind": "UnaryExprOrTypeTraitExpr", "name": "sizeof",
                                 "argType": {"qualType": value_type}})
    map_field = plain(map_arg)
    if (not re.fullmatch(r"[\w ]+\[\d+\]", value_type) or size is None or size < 6
            or not native_flow.field(map_field) or map_field.get("type", {}).get("qualType") != "struct regmap *"):
        return None
    owner = native_flow.direct_id(children(map_field)[0])
    members = []
    while dest.get("kind") == "MemberExpr":
        members.append(dest["name"])
        base = plain(children(dest)[0])
        if dest.get("isArrow"):
            if owner and native_flow.direct_id(base) == owner:
                return {"members": list(reversed(members)), "capacity": size, "type": value_type}
            break
        dest = base
    return None


def init_contract(root):
    contract = slot_contract(root)
    boot = root / "init/main.c"
    expected_boot = "e895a643df800a83857b88bebb6e990c17cd0890e485a48a7b972f5d2ae73516"
    if boot.resolve(strict=True) != boot or digest(boot) != expected_boot:
        raise ValueError("Unreviewed boot argument and initcall ordering")
    contract.update(
        boot_source_sha256=expected_boot,
        class_lifetime="one field of the live map, from its own format initialization until release",
        initial_default="preserve converter calls until construction records eligibility",
        observation="objects constructed before boot policy freeze retain callback entries",
        reconfiguration="under the API exclusion rule, cache selection changes and format qualification persists",
    )
    return contract


def direct_call(unit, root, site):
    name = api_emit.ORIGINAL.decode("ascii")
    decls = unit.declarations(name)
    header = root / api_emit.HEADER
    if len(decls) != 1:
        raise ValueError("Ambiguous declaration of the Linux read")
    decl = decls[0]
    location = decl.get("loc", {})
    if (decl.get("kind") != "FunctionDecl" or (unit.cwd / location.get("file", "")).resolve() != header
            or any(n.get("kind", "").endswith("Attr") or n.get("kind") == "CompoundStmt" for n in children(decl))
            or decl.get("storageClass") == "static"):
        raise ValueError("Read does not bind the public Linux prototype")
    calls = [c for c in walk(unit.function(site["function"])) if native_flow.symbol(c) == name and
             native_flow.spelled(c).get("offset") == site["offset"]]
    if len(calls) != 1:
        raise ValueError("Ambiguous call spelling in the compiled handler")
    args = children(calls[0])
    referenced = ref(args[0])
    if referenced.get("kind") != "FunctionDecl" or referenced.get("type") != decl.get("type"):
        raise ValueError("Read is indirect or has an unreviewed signature")
    return args


def actual_call(unit, root, site):
    _, map_arg, _, dest, count = direct_call(unit, root, site)
    buffer = inline_output(dest, map_arg)
    if not buffer or native_flow.constant(count) != 6:
        raise ValueError("Cannot bind six values to a separate writable inline array")
    return buffer


def public_inputs(root, build, clang, path):
    flags, cwd = compilation(root, build, path, clang)
    headers = api_inputs.observe_driver_dependencies(root, build, path, clang, flags, cwd)
    if "source/drivers/base/regmap/internal.h" in headers:
        raise ValueError("Driver accesses the private regmap layout")
    local = [path, *(root/key.removeprefix("driver/") for key in headers if key.startswith("driver/"))]
    for source in local:
        code = api_opt._TRIVIA.sub("", source.read_bytes().decode("latin1"))
        if re.search(r"\bparse_inplace\b|\bstruct\s+regmap\s*\{", code):
            raise ValueError("Driver bypasses the public regmap API")
    return headers


def analyze_unit(root, build, clang, path, rows):
    headers = public_inputs(root, build, clang, path)
    sites = native_flow.analyze(root, build, clang, path)
    binding = native_flow.bind_native_inputs(root, build, clang, path, sites)
    relative = path.relative_to(root).as_posix()
    if binding["translation_units"][relative]["dependencies"] != headers:
        raise ValueError("Driver inputs changed during the AST scan")
    unit = native_flow.Translation(root, build, clang, path)
    by_offset = {s["offset"]: s for s in sites}
    for row in rows:
        site = by_offset.get(row["offset"])
        if not site:
            continue
        row.update(function=site["function"], count=site["count"], source_sha256=site["source_sha256"],
                   arguments=site.get("arguments"), reason="value_count_is_not_six")
        if site["count"] != 6:
            continue
        registered = any(reg["same_device_argument_as_allocation"]
                         for owner in site["owners"] for reg in owner["registrations"])
        if not site["private_path"] or 6 not in site.get("byte_lengths_for_observed_configs", []) or not registered:
            row["reason"] = "unproved_iio_read_or_unobserved_byte_format"
            continue
        try:
            buffer = actual_call(unit, root, site)
        except ValueError as exc:
            row["reason"] = str(exc)
            continue
        row.update(decision="admit", reason="valid_regmap_post_read_guard", buffer=buffer,
                   register=site["register"], observed_byte_lengths=site["byte_lengths_for_observed_configs"])
    return sites, binding


def optimize(args):
    variable = args.policy in ("valid-n", "init-n")
    emitter, analyze, rebind = valid_emit, analyze_unit, native_flow.bind_native_inputs
    read_contract = slot_contract
    if variable:
        from . import var_emit, var_flow
        emitter, analyze, rebind = var_emit, var_flow.analyze_unit, var_flow.bind_inputs
    if args.policy == "init-n":
        from . import init_emit
        emitter = init_emit
        read_contract = init_contract
    root = args.kernel.resolve(strict=True)
    requested = args.output.resolve()
    if requested == root or root in requested.parents or requested in root.parents:
        raise OperationError("invalid_output", "Choose a directory separate from the Linux source")
    output = new_output(args.output)
    units = api_opt.inventory(root, args.scope)
    build = args.build_dir.resolve() if args.build_dir else None
    binary = args.clang or shutil.which("clang")
    clang = Path(binary).resolve() if binary else None
    verification, contract, contexts, selected, patch, checks = {}, {}, {}, [], {}, {}
    proof, reasons = None, []
    try:
        if not build or not clang:
            raise ValueError("verified_kbuild_context_unavailable")
        verification = api_inputs.verify(root, build, args.config.resolve(), clang)
        contract = read_contract(root)
        for path, rows in units.items():
            if not variable and b"devm_iio_triggered_buffer_setup" not in path.read_bytes():
                for row in rows:
                    row["reason"] = "no_managed_iio_buffer_setup"
                continue
            try:
                sites, binding = analyze(root, build, clang, path, rows)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                for row in rows:
                    row.update(decision="keep_original", reason=str(error))
                continue
            admitted = [r for r in rows if r["decision"] == "admit"]
            if admitted:
                selected.extend(admitted)
                contexts[path] = (sites, binding)
        if not selected:
            raise ValueError("no_supported_valid_map_calls")
        proposal = api_emit.driver_overlay(root, selected, emitter.framework_overlay(root), emitter.ENTRY)
        for path in contexts:
            relative = path.relative_to(root).as_posix()
            flags, cwd = compilation(root, build, path, clang)
            with tempfile.TemporaryDirectory() as tmp:
                checks[relative] = api_opt.check_replacement(clang, flags, cwd, path, root / api_emit.HEADER,
                    (proposal[relative], proposal[api_emit.HEADER]), sum(s["source"] == relative for s in selected),
                    Path(tmp), emitter.ENTRY)
        proof = emitter.certificate(root, proposal, args, output)
        if api_inputs.verify(root, build, args.config.resolve(), clang) != verification or read_contract(root) != contract:
            raise ValueError("regmap framework or build changed during proof")
        for path, (sites, bound) in contexts.items():
            if rebind(root, build, clang, path, sites) != bound:
                raise ValueError("driver inputs changed during proof")
        patch = proposal
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        reasons.append(str(exc))
    for row in selected:
        row["action"] = "guard_valid_read" if patch else "keep_original"
    rows = [r for group in units.values() for r in group]
    files = _publish_overlay(root, patch, output)
    if args.config.is_file():
        shutil.copyfile(args.config, output / "kernel.config")
    if args.materialize:
        dest = output / "linux"
        shutil.copytree(root, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        for name, data in patch.items():
            if digest(dest / name) != files[name]["before"]:
                raise ValueError("Source changed while materializing the overlay")
            (dest / name).write_bytes(data)
    save(output / "bindings.json", {p.relative_to(root).as_posix(): {"sites": s, "inputs": b}
                                     for p, (s, b) in contexts.items()})
    save(output / "scan.json", {"scope": args.scope, "candidates": rows})
    result = dict(kind="kconc.valid_bulk_read" if variable else "kconc.valid_sixbyte",
                  schema_version=1, status="passed", policy=args.policy,
                  decision="emit_guarded_sites" if patch else "keep_original", reasons=reasons, files=files,
                  admitted=[{k: s[k] for k in ("source","function","line","offset","arguments")} for s in selected if patch],
                  contract=contract, inputs=verification, proof=proof, preprocessed=checks,
                  scan_sha256=digest(output/"scan.json"), bindings_sha256=digest(output/"bindings.json"),
                  patch_sha256=digest(output/"linux.patch"))
    save(output/"result.json", result)
    return result

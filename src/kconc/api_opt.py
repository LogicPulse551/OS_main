"""Select private regmap reads using their actual translation units and a checked rewrite."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import api_emit, api_flow
from .cli import OperationError, REPO, digest, new_output, save
from .sixbyte import _publish_overlay
from .sixbyte_scan import _TRIVIA, _calls, _integer


def inventory(root, relative):
    scope = root / relative
    if (scope.resolve() != scope or root / "drivers" not in (scope, *scope.parents)
            or not scope.exists()):
        raise ValueError("Scan scope must be an existing path under drivers/")
    paths = sorted(scope.rglob("*.c")) if scope.is_dir() else [scope]
    result = {}
    for path in paths:
        if path.suffix != ".c" or path.resolve() != path or not path.is_file():
            continue
        raw = path.read_bytes()
        if api_emit.ORIGINAL not in raw:
            continue
        source = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), raw.decode("latin1"))
        rows = []
        for offset, end, args in _calls(source):
            rows.append(dict(source=path.relative_to(root).as_posix(), offset=offset, end_offset=end,
                             line=source.count("\n", 0, offset)+1, length=_integer(args[3], {}),
                             byte_length=None, action="keep_original", decision="keep_original",
                             reason="direct_call_not_established_in_translation_unit"))
        if rows:
            result[path] = rows
    return result


def check_replacement(clang, flags, cwd, source, header, overlay, expected, scratch, entry=api_emit.ENTRY):
    """The emitted symbol must denote the new declaration at exactly the admitted calls."""
    paths = {source: scratch / "caller.c", header: scratch / "header.h"}
    for path, data in zip(paths.values(), overlay):
        path.write_bytes(data)
    vfs = scratch / "overlay.json"
    vfs.write_text(json.dumps({"version": 0, "use-external-names": False, "roots": [
        {"type": "file", "name": str(path), "external-contents": str(temp)}
        for path, temp in paths.items()]}), encoding="utf-8")
    def preprocessed(extra):
        command = [str(clang), *flags, *extra, "-E", "-P", str(source)]
        p = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
        if p.returncode:
            raise ValueError("Preprocessing failed: " + p.stderr.decode(errors="replace")[-2000:])
        return p.stdout
    before = preprocessed([])
    after = preprocessed(["-ivfsoverlay", str(vfs)])
    prototype = (rb"\bint\s+" + entry + rb"\s*\(\s*struct\s+regmap\s*\*\s*map\s*,\s*"
                 rb"unsigned\s+int\s+reg\s*,\s*void\s*\*\s*val\s*,\s*size_t\s+val_count\s*\)\s*;")
    restored, declarations = re.subn(prototype, b"", after)
    tokens = re.compile(rb'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\w+|[^\s]''')
    old = tokens.findall(before)
    new = tokens.findall(restored)
    sites = new.count(entry)
    if (entry in before or declarations != 1 or sites != expected or
            old != [api_emit.ORIGINAL if token == entry else token for token in new]):
        raise ValueError("The preprocessed caller changed beyond the selected callee and its prototype")
    checked = subprocess.run([str(clang), *flags, "-ivfsoverlay", str(vfs), "-fsyntax-only", str(source)],
                             cwd=cwd, capture_output=True, timeout=180)
    if checked.returncode:
        raise ValueError("Rewritten caller failed Clang type checking: " + checked.stderr.decode(errors="replace")[-1500:])
    return dict(before_sha256=hashlib.sha256(before).hexdigest(),
                after_sha256=hashlib.sha256(after).hexdigest(), call_sites=sites, type_checked=True)


def certificate(root, core, args, output):
    if not args.compcert or not args.coq_bin:
        raise ValueError("proof_environment_unavailable")
    candidate = output / "candidate-regmap.c"
    candidate.write_bytes(core)
    result_dir = output / "proof"
    command = [sys.executable, "-B", str(REPO / "proofs/api-sixbyte/check.py"),
               "--original", str(root / api_emit.REGMAP), "--emitted", str(candidate),
               "--compcert", str(args.compcert), "--coq-bin", str(args.coq_bin), "--out", str(result_dir)]
    with (output / "checker.log").open("wb") as log:
        run = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    if run.returncode:
        raise ValueError("proof_check_failed")
    receipt = json.loads((result_dir / "result.json").read_bytes())
    if (receipt.get("passed") is not True or "GenericRead.any_start_six" not in receipt.get("theorems", [])
            or receipt.get("kernel_sources") != {"Original": digest(root / api_emit.REGMAP),
                                                 "Emitted": digest(candidate)}):
        raise ValueError("proof_binding_failed")
    return digest(result_dir / "result.json")


def optimize(args):
    root = args.kernel.expanduser().resolve(strict=True)
    requested = args.output.expanduser().resolve()
    if requested == root or root in requested.parents or requested in root.parents:
        raise OperationError("invalid_output", "Choose an output directory separate from the Linux source")
    output = new_output(args.output)
    directories = inventory(root, args.scope)
    reasons = []
    verification = {}
    build = args.build_dir.resolve() if args.build_dir else None
    cc = args.clang or shutil.which("clang")
    clang = Path(cc).resolve() if cc else None
    if build is None or clang is None or not args.config.is_file():
        reasons.append("verified_kbuild_context_unavailable")
    else:
        from .api_inputs import verify
        try:
            verification = verify(root, build, args.config.resolve(), clang)
        except (ValueError, OSError) as error:
            reasons.append(str(error))
    contexts = {}
    dependencies = {}
    native_inputs = {}
    native_compilations = {}
    native_framework = None
    if not reasons:
        from .api_inputs import bind_dependencies
        from .api_kbuild import compilation
        for path, rows in directories.items():
            try:
                flags, cwd = compilation(root, build, path, clang)
                bound = bind_dependencies(root, build, path, clang, flags, cwd)
                found = api_flow.analyze(path, clang, flags, cwd, root)
                by_offset = {r["offset"]: r for r in rows}
                for r in found:
                    existing = by_offset.get(r["offset"])
                    if existing is None:
                        continue
                    existing.update(r, source=path.relative_to(root).as_posix(),
                                    length=r["count"], byte_length=r["byte_count"])
                    if r["decision"] == "admit" and r["evidence"].get("byte_copy_contracts"):
                        from .api_copy import check_module_copy
                        evidence = output / "copy" / existing["source"] / str(r["offset"])
                        try:
                            existing["evidence"]["compiled_copy"] = check_module_copy(
                                root, build, path, clang, flags, cwd, r, evidence)
                        except (OSError, ValueError, subprocess.SubprocessError) as error:
                            existing.update(decision="keep_original", reason="copy_lowering_unproved",
                                            reason_detail=str(error))
                contexts[path] = flags, cwd
                dependencies[path.relative_to(root).as_posix()] = bound
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                for row in rows:
                    row.update(decision="keep_original", reason="translation_unit_unavailable", detail=str(error))
            # Shared IRQ objects have a separate proof obligation even when a driver
            # includes its own headers. These edges cannot unlock the local-map emitter.
            if (b"devm_iio_triggered_buffer_setup" in path.read_bytes() and
                    any(row["decision"] != "admit" for row in rows)):
                from . import native_contracts, native_flow
                relative = path.relative_to(root).as_posix()
                try:
                    if native_framework is None:
                        native_framework = native_contracts.framework(root)
                    edges = native_flow.analyze(root, build, clang, path)
                    native_compilations[relative] = native_flow.bind_native_inputs(root, build, clang, path, edges)
                    native_inputs[relative] = [native_contracts.assess(root, site) for site in edges]
                    by_offset = {row["offset"]: row for row in rows}
                    for site in native_inputs[relative]:
                        row = by_offset.get(site["offset"])
                        if row is None or row["decision"] == "admit":
                            continue
                        row["private_analysis"] = {k: row[k] for k in ("reason", "detail") if k in row}
                        row.update(function=site["function"], source_sha256=site["source_sha256"],
                                   length=site["count"], reason=site["reason"],
                                   reason_detail=site.get("reason_detail", site["reason"]),
                                   native_evidence={"source": relative, "offset": site["offset"]},
                                   byte_lengths_for_observed_configs=site.get("byte_lengths_for_observed_configs", []))
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    native_inputs[relative] = {"unavailable": str(error)}
    rows = [row for group in directories.values() for row in group]
    admitted = [row for row in rows if row["decision"] == "admit"]
    changes = {}
    proof = None
    bindings = {}
    if admitted:
        try:
            proposal = api_emit.emit_overlay(root, admitted)
            for path, (flags, cwd) in contexts.items():
                relative = path.relative_to(root).as_posix()
                if relative not in proposal:
                    continue
                selected = [r for r in admitted if r["source"] == relative]
                with tempfile.TemporaryDirectory() as private:
                    bindings[relative] = check_replacement(clang, flags, cwd, path, root / api_emit.HEADER,
                        (proposal[relative], proposal[api_emit.HEADER]), len(selected), Path(private))
            proof = certificate(root, proposal[api_emit.REGMAP], args, output)
            if verify(root, build, args.config.resolve(), clang) != verification:
                raise ValueError("framework_changed_during_analysis")
            for path, (flags, cwd) in contexts.items():
                relative = path.relative_to(root).as_posix()
                if relative in proposal and (compilation(root, build, path, clang) != (flags, cwd) or
                        bind_dependencies(root, build, path, clang, flags, cwd) != dependencies[relative]):
                    raise ValueError("translation_unit_changed_during_analysis")
            if any(digest(root / r["source"]) != r["source_sha256"] for r in admitted):
                raise ValueError("driver_source_changed_during_analysis")
            changes = proposal
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            reasons.append(str(error))
    if not admitted and not reasons:
        has_shared_read = any(isinstance(sites, list) and any(site.get("open_conditions") for site in sites)
                              for sites in native_inputs.values())
        reasons.append("shared_read_conditions_unproved" if has_shared_read else "no_proved_local_read")
    for row in rows:
        if row["decision"] == "admit" and changes:
            row["action"] = "guard_private_read"
        elif reasons:
            row["action_reason"] = reasons
    files = _publish_overlay(root, changes, output)
    if args.config.is_file():
        shutil.copyfile(args.config, output / "kernel.config")
    if args.materialize:
        dest = output / "linux"
        shutil.copytree(root, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        for name, data in changes.items():
            if digest(dest / name) != files[name]["before"]:
                raise ValueError("Input differs in materialized source: " + name)
            (dest / name).write_bytes(data)
    save(output / "dependencies.json", dependencies)
    if native_inputs:
        save(output / "native.json", {"framework": native_framework, "translation_units": native_inputs,
                                      "compilation_inputs": native_compilations})
    save(output / "scan.json", dict(scope=args.scope, coverage={"direct_four_argument_sites": len(rows)},
                                    candidates=rows))
    result = dict(schema_version=1, kind="kconc.api_sixbyte", status="passed", policy="private-api",
                  decision="emit_guarded_sites" if changes else "keep_original", reasons=reasons,
                  admitted=[{"source": r["source"], "function": r["function"], "offset": r["offset"]}
                            for r in admitted if changes], files=files, proof=proof, inputs=verification,
                  preprocessed=bindings, dependencies_sha256=digest(output / "dependencies.json"),
                  scan_sha256=digest(output / "scan.json"),
                  patch_sha256=digest(output / "linux.patch"), materialized=args.materialize)
    if native_inputs:
        result["native_evidence_sha256"] = digest(output / "native.json")
    save(output / "result.json", result)
    return result

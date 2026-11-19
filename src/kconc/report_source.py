"""Resolve archived DWARF locations against the source bytes recorded by Kbuild."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .replay_bundle import FILES


# Digests of the two source manifests in the accepted K10 stability ledger.
# The captured runtime binds its image but does not itself list the source hashes.
K10_SOURCE_MANIFESTS = {
    "rmw": "1bb52f5d7d66362dfd817c6856a4206699ebbf514b88f4ebbc48ed7ee07dea37",
    "mutex": "b60f3e3242e11bf0ab9d58f8eeacc4e7970163c9efa52fbe7c93a1a26f322483",
}


def _require(ok, reason):
    if not ok:
        raise ValueError(reason)


def _entry(records, path):
    entries = [item for item in records if item["path"] == path]
    _require(len(entries) == 1, "missing or ambiguous build input: " + path)
    return entries[0]


def attach_sources(report: dict, bundle: Path, source_root: Path, build_record: Path) -> dict:
    """Attach line excerpts to validated event nodes; function-only DWARF has no line."""
    bundle = Path(bundle)
    source_root = Path(source_root).resolve(strict=True)
    record_bytes = Path(build_record).read_bytes()
    build = json.loads(record_bytes)
    record_hash = hashlib.sha256(record_bytes).hexdigest()
    _require(record_hash == K10_SOURCE_MANIFESTS.get(build["family"]), "unregistered K10 source manifest")
    archive = json.loads((bundle / "bundle.json").read_bytes())

    def archived(name):
        content = (bundle / name).read_bytes()
        _require(hashlib.sha256(content).hexdigest() == archive["artifacts"][name],
                 "source binding: changed archive input " + name)
        return json.loads(content)

    identity = archived("reference/runtime-identity.json")["kernel_and_k03"]
    output = archived("reference/task.json")["runtime"]["kernel_build"]
    _require(build.get("kind") == "kconc.control-kernel.build" and build.get("task") == "K10"
             and build.get("stage") == "kernel" and build.get("passed") is True, "expected a completed K10 kernel build")
    _require(build["source_commit"] == identity["linux_commit"] and build["kernel_build"] == output,
             "source build differs from captured runtime")
    for name, field in (("vmlinux", "vmlinux"), ("arch/x86/boot/bzImage", "kernel_image"), (".config", "kernel_config")):
        _require(_entry(build["artifacts"], output + "/" + name)["sha256"] == identity[field],
                 "runtime and source build disagree on " + name)

    # Read only the component files in the recorded signature policy. When a source tree
    # has moved, its absolute filesystem prefix may differ; its bytes must still match.
    source_files = {}
    for rel in FILES:
        original = build["source"] + "/" + rel
        entry = _entry(build["regmap_sources"], original)
        path = (source_root / rel).resolve(strict=True)
        _require(path.is_relative_to(source_root), "component path escapes the supplied source tree: " + rel)
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        _require(len(content) == entry["bytes"] and digest == entry["sha256"], "source fingerprint mismatch: " + rel)
        source_files[rel] = (original, digest, content.decode("utf-8").splitlines())

    locations = {}
    sources = {}
    bindings = []
    for node in report["nodes"]:
        location = node.get("source")
        if not location:
            _require(node.get("kind") != "MEMORY", "component event has no source metadata")
            bindings.append(None)
            continue
        rel, symbol = location["file"], location["symbol"]
        _require(rel in source_files and isinstance(symbol, str) and symbol, "invalid component location")
        original, digest, text = source_files[rel]
        _require(location.get("recorded_file") == original, "debug information names a different build source: " + rel)
        line, exact, kind = location["line"], location["exact_line"], location["mapping_kind"]
        _require(type(line) is int and type(exact) is bool, "malformed DWARF line")
        _require((exact and kind == "exact_line" and 1 <= line <= len(text))
                 or (not exact and kind == "function_only" and line == 0),
                 "inconsistent DWARF position: " + rel)
        key = (rel, symbol, line)
        if key not in locations:
            source_id = "s" + str(len(sources) + 1)
            locations[key] = source_id
            lines = []
            if exact:
                for n in range(max(1, line - 3), min(len(text), line + 3) + 1):
                    lines.append({"number": n, "text": text[n - 1]})
            sources[source_id] = dict(file=rel, recorded_file=original, symbol=symbol, line=line,
                                      exact_line=exact, mapping_kind=kind, sha256=digest, lines=lines)
        bindings.append(locations[key])

    for node, source_id in zip(report["nodes"], bindings):
        node["source_id"] = source_id
    report["sources"] = sources
    report["source_build"] = dict(record_sha256=record_hash,
                                  source_commit=build["source_commit"], family=build["family"],
                                  vmlinux_sha256=identity["vmlinux"], image_sha256=identity["kernel_image"],
                                  config_sha256=identity["kernel_config"],
                                  file_sha256={rel: values[1] for rel, values in source_files.items()})
    return report

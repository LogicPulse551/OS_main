"""Discover six-byte driver reads and emit only locally certified replacements."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from .cli import REPO, OperationError, digest, new_output, save
from .sixbyte_emit import REGMAP, checked_boards, check_reviewed_overlay, emit_overlay
from .sixbyte_scan import scan


# Derived from the contents of the reviewed Linux source archive, including
# symlink targets and executable bits. This also catches new out-of-file writers.
SOURCE_TREE = "0ee9e2696580c943118f8358aaa7cf7ea380241cfbd37c23ca3ef8b8f0de32aa"
CONFIGS = {
    "97d3db10a602f10e3553d0af022dfd1052488f8b9ed3724d0639170b3e826e0b": {"bma400-spi", "kx022a-spi"},
    "2d64201a751c73468d0cff77ac2479712608f8e88c90d27973858999021f2dc1": {"kx022a-spi"},
}
CLANG = "f3765cf3cc48f6c60743fa433ddc50a5f535f892af6a2e14c9b6d1b8a5a06305"


def tree_identity(root):
    entries = {}
    def propagate(error):
        raise error
    for directory, folders, names in os.walk(root, onerror=propagate):
        parent = Path(directory)
        if parent == root:
            folders[:] = [name for name in folders if name != ".git"]
            names = [name for name in names if name != ".git"]
        for folder in folders[:]:
            if (parent / folder).is_symlink():
                folders.remove(folder)
                names.append(folder)
        for name in names:
            path = parent / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                key = b"L" + hashlib.sha256(os.fsencode(os.readlink(path))).digest()
            elif stat.S_ISREG(mode):
                key = (b"X" if mode & 0o111 else b"F") + bytes.fromhex(digest(path))
            else:
                raise ValueError(f"Unsupported source entry: {path}")
            entries[os.fsencode(path.relative_to(root).as_posix())] = key
    tree = hashlib.sha256()
    for name in sorted(entries):
        tree.update(name + b"\0" + entries[name])
    return {"files": len(entries), "sha256": tree.hexdigest()}


def proof_check(kernel, emitted, compcert, coq_bin, output):
    if compcert is None or coq_bin is None:
        return False, "proof_environment_unavailable"
    evidence = output / "proof"
    candidate = output / "candidate-regmap.c"
    candidate.write_bytes(emitted[REGMAP])
    checker = REPO / "proofs/sixbyte/check.py"
    command = [sys.executable, "-B", str(checker), "--original", str(kernel / REGMAP),
               "--emitted", str(candidate), "--compcert", str(compcert), "--coq-bin",
               str(coq_bin), "--out", str(evidence)]
    with (output / "proof.log").open("wb") as log:
        completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    receipt = evidence / "result.json"
    if completed.returncode or not receipt.is_file():
        return False, "proof_check_failed"
    actual = json.loads(receipt.read_bytes())
    if (actual.get("passed") is not True or
            actual.get("kernel_sources") != {"Original": digest(kernel / REGMAP), "Emitted": digest(candidate)} or
            "DeviceReads.both_driver_reads" not in actual.get("theorems", ())):
        return False, "proof_check_failed"
    return True, "checked"


def _publish_overlay(root, changes, output):
    patch = []
    bindings = {}
    for name, data in sorted(changes.items()):
        path = root / name
        before = path.read_bytes() if path.exists() else None
        target = output / "overlay" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        bindings[name] = {"before": None if before is None else hashlib.sha256(before).hexdigest(),
                          "after": hashlib.sha256(data).hexdigest()}
        patch.extend(difflib.diff_bytes(difflib.unified_diff, (before or b"").splitlines(True),
                     data.splitlines(True), os.fsencode("a/" + name) if before is not None else b"/dev/null",
                     os.fsencode("b/" + name)))
    (output / "linux.patch").write_bytes(b"".join(patch))
    return bindings


def optimize(args):
    """A fresh receipt owns all outputs. Proof failures always select the input."""
    source = args.kernel.expanduser().resolve(strict=True)
    requested = args.output.expanduser().resolve()
    if requested == source or source in requested.parents or requested in source.parents:
        raise OperationError("invalid_output", "Choose an output directory separate from the Linux source")
    output = new_output(args.output)
    root = source
    if args.materialize:
        root = output / ".source"
        shutil.copytree(source, root, symlinks=True,
                        ignore=lambda directory, names: {".git"} if Path(directory) == source else set())
    discovered = scan(root, args.scope)
    save(output / "scan.json", discovered)
    config = args.config
    if config.is_file():
        shutil.copyfile(config, output / "kernel.config")
    config_hash = digest(output / "kernel.config") if (output / "kernel.config").is_file() else None
    compiler = args.clang or shutil.which("clang")
    clang_hash = digest(Path(compiler)) if compiler and Path(compiler).is_file() else None
    supported = CONFIGS.get(config_hash, set())
    matches = sorted({c["profile"] for c in discovered["candidates"] if c["decision"] == "matched"})
    selected = sorted(set(matches) & supported)
    reasons = []
    if not matches:
        reasons.append("no_matching_call_site")
    if not supported:
        reasons.append("unreviewed_build_configuration")
    if clang_hash != CLANG:
        reasons.append("unreviewed_compiler")
    proof_status = "not_run"
    tree = None
    changes = {}
    board_data = {}
    diagnostics = output / "diagnostics"
    diagnostics.mkdir()
    if selected and not reasons:
        try:
            tree = tree_identity(root)
            if tree["sha256"] != SOURCE_TREE:
                reasons.append("source_tree_mismatch")
            else:
                proposed = emit_overlay(root, selected)
                check_reviewed_overlay(selected, proposed)
                for name, expected in checked_boards(REPO, selected).items():
                    data = (REPO / name).read_bytes()
                    if hashlib.sha256(data).hexdigest() != expected:
                        raise ValueError("Controller source drift: " + name)
                    board_data[name] = data
                passed, proof_status = proof_check(root, proposed, args.compcert, args.coq_bin, diagnostics)
                if passed:
                    changes = proposed
                else:
                    reasons.append(proof_status)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            (diagnostics / "error.txt").write_text(str(exc), encoding="utf-8")
            reasons.append("could_not_bind_inputs_or_proof")
    bindings = _publish_overlay(root, changes, output)
    boards = {}
    if changes:
        board_dir = output / "boards"
        board_dir.mkdir()
        for name, data in board_data.items():
            target = board_dir / Path(name).name
            target.write_bytes(data)
            boards[name] = hashlib.sha256(data).hexdigest()
    if args.materialize:
        for name, data in changes.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        root.rename(output / "linux")

    for row in discovered["candidates"]:
        row["action"] = "keep_original"
        if row["decision"] == "matched":
            if changes and row["profile"] in selected:
                row["action"] = "guard_qualified_instances"
            elif row["profile"] not in supported:
                row["action_reason"] = "unreviewed_build_configuration"
            else:
                row["action_reason"] = reasons
    save(output / "scan.json", discovered)
    receipt = {"schema_version": 1, "kind": "kconc.sixbyte", "status": "passed", "policy": "registered",
               "decision": "emit_guarded_sites" if changes else "keep_original",
               "admitted": selected if changes else [], "reasons": reasons, "proof": proof_status,
               "config_sha256": config_hash, "clang_sha256": clang_hash, "tree": tree,
               "scope": discovered["scope"], "coverage": discovered["coverage"],
               "scan_sha256": digest(output / "scan.json"), "files": bindings, "boards": boards,
               "patch_sha256": digest(output / "linux.patch"), "materialized": bool(args.materialize)}
    save(output / "result.json", receipt)
    return receipt

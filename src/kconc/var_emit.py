"""Generate a guarded read for lengths representable by Linux's signed loop index."""
import json
from pathlib import Path
import subprocess
import sys

from . import api_emit, valid_emit


ENTRY = b"kconc_valid_bulk_read"
REGMAP = api_emit.REGMAP
HEADER = api_emit.HEADER
CHECKER = Path(__file__).resolve().parents[2] / "proofs/var-regmap/check.py"
REQUIRED = {"VariableRead.actual_function", "VariableRead.execute_selector", "VariableRead.dispatch_loop",
            "VariableRead.machine_indices", "VariableRead.machine_expressions",
            "VariableRead.oversized_check", "VariableRead.api_read",
            "VariableRead.checked_read", "VarGuard.actual_guard_false"}


def framework_overlay(root):
    """Reuse the existing public header, observer and unchanged error paths."""
    shared = valid_emit.framework_overlay(root)
    for name in (REGMAP, HEADER):
        shared[name] = shared[name].replace(valid_emit.ENTRY, ENTRY)
    shared[REGMAP] = api_emit._replace_once(shared[REGMAP], b"kconc_keep_callback_entries || val_count != 6",
        b"kconc_keep_callback_entries || val_count == 0 || val_count > INT_MAX")
    return shared


def certificate(root, overlay, args, output):
    if not args.compcert or not args.coq_bin:
        raise ValueError("variable-length proof environment unavailable")
    if any(overlay.get(path) != data for path, data in framework_overlay(root).items()):
        raise ValueError("unreviewed variable-length regmap helper or declaration")
    target = output / "variable-regmap.c"
    target.write_bytes(overlay[REGMAP])
    proof = output / "proof"
    cmd = [sys.executable, "-B", str(CHECKER), "--original", str(root / REGMAP), "--emitted", str(target),
           "--compcert", str(args.compcert), "--coq-bin", str(args.coq_bin), "--out", str(proof)]
    with (output / "checker.log").open("wb") as log:
        if subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode:
            raise ValueError("variable-length proof check failed")
    path = proof / "result.json"
    result = json.loads(path.read_bytes())
    h = api_emit._digest
    evidence = result.get("inputs", {})
    sources = {"Original": h((root / REGMAP).read_bytes()), "Emitted": h(overlay[REGMAP])}
    if (result.get("passed") is not True or set(result.get("theorems", [])) != REQUIRED or
            result.get("kernel_sources") != sources or result.get("runner_sha256") != h(CHECKER.read_bytes()) or
            not all(result.get("commands", [])) or
            {r["label"] for r in result["commands"] if r["exit_code"] == 0} !=
            {"reference", "target-project", "VarTarget", "VarGuard", "VariableRead", "coqchk"} or
            any(r["exit_code"] for r in result["commands"]) or
            not {"target/Case.c","target/Case.v","reference/projection/VariableRead.v",
                 "reference/projection/VariableRead.vo","VariableRead.stdout"}.issubset(evidence) or
            any(h((proof/name).read_bytes()) != value for name,value in evidence.items()) or
            evidence["reference/projection/VariableRead.v"] != h((CHECKER.parent/"VariableRead.v").read_bytes())):
        raise ValueError("unbound variable-length proof receipt")
    return {"receipt": "proof/result.json", "sha256": h(path.read_bytes()),
            "theorems": result["theorems"], "kernel_sources": sources}

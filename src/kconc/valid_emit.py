"""Emit one guarded public helper for calls made with a live Linux regmap."""
import json
from pathlib import Path
import subprocess
import sys

from . import api_emit
from .sixbyte_emit import LOOP
from .sixbyte_scan import SHARED_INPUTS


ENTRY = b"kconc_valid_sixbyte_read"
REGMAP = api_emit.REGMAP
HEADER = api_emit.HEADER
CHECKER = Path(__file__).resolve().parents[2] / "proofs/valid-sixbyte/check.py"
OBSERVATION = api_emit.GATE.split(b"int kconc_local_sixbyte_read(", 1)[0].strip()
GUARD = b"""		if (kconc_keep_callback_entries || val_count != 6 || val_bytes != 1 ||
		    map->format.parse_inplace != regmap_parse_inplace_noop) {
			for (i = 0; i < val_count * val_bytes; i += val_bytes)
				map->format.parse_inplace(val + i);
		}"""


def framework_overlay(root):
    kernel = Path(root).resolve(strict=True)
    original = api_emit._read(kernel, REGMAP, SHARED_INPUTS[REGMAP])
    header = api_emit._read(kernel, HEADER, SHARED_INPUTS[HEADER])
    start = original.index(b"\nint " + api_emit.ORIGINAL + b"(") + 1
    public = original[start:original.index(api_emit.EXPORT, start)].rstrip()
    helper = api_emit._replace_once(public, b"int " + api_emit.ORIGINAL + b"(", b"int " + ENTRY + b"(")
    helper = api_emit._replace_once(helper, LOOP.encode(), GUARD)
    includes = b'#include "internal.h"'
    core = api_emit._replace_once(original, includes, includes + b"\n#include <linux/init.h>\n#include <linux/kstrtox.h>")
    core = api_emit._replace_once(core, api_emit.EXPORT, b"\n\n".join([api_emit.EXPORT, OBSERVATION, helper]) +
                                  b"\nEXPORT_SYMBOL_GPL(" + ENTRY + b");")
    declared = api_emit._replace_once(header, api_emit.PUBLIC_DECL,
        api_emit.PUBLIC_DECL + b"\nint " + ENTRY + api_emit.ARGUMENTS + b";")
    begin = declared.index(b"static inline int regmap_bulk_read(")
    end = declared.index(b"\n}\n", begin) + 3
    stub = (b"\nstatic inline int " + ENTRY + api_emit.ARGUMENTS +
            b"\n{\n\treturn regmap_bulk_read(map, reg, val, val_count);\n}\n")
    return {REGMAP: core, HEADER: declared[:end] + stub + declared[end:]}


def certificate(root, overlay, args, output):
    if not args.compcert or not args.coq_bin:
        raise ValueError("valid-map proof environment unavailable")
    for name, content in framework_overlay(root).items():
        if overlay.get(name) != content:
            raise ValueError("unrecognized valid-map framework output: " + name)
    target = output / "valid-regmap.c"
    target.write_bytes(overlay[REGMAP])
    cmd = [sys.executable, "-B", str(CHECKER), "--original", str(root / REGMAP),
           "--emitted", str(target), "--compcert", str(args.compcert), "--coq-bin", str(args.coq_bin),
           "--out", str(output / "proof")]
    with (output / "checker.log").open("wb") as log:
        p = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    if p.returncode:
        raise ValueError("valid-map source or proof check failed")
    result = json.loads((output / "proof/result.json").read_bytes())
    required = {"GenericRead.any_start_six", "ValidRead.actual_function", "ValidRead.execute_selector",
                "ValidRead.dispatch_loop", "ValidGuard.actual_guard_false", "ValidRead.fast_cut_step",
                "ValidRead.api_read", "ValidRead.checked_success"}
    checks = {row["label"]: row for row in result.get("commands", [])}
    bindings = {"reference/result.json", "target/Case.c", "target/Case.v", "reference/projection/ValidRead.v",
                "reference/projection/ValidRead.vo", "ValidRead.stdout"}
    handles = {"reference", "target-project", "Valid", "ValidGuard", "ValidRead", "coqchk"}
    bound = result.get("inputs", {})
    if (result.get("passed") is not True or required != set(result.get("theorems", []))
            or handles != set(checks) or any(row.get("exit_code") != 0 for row in checks.values())
            or not bindings.issubset(bound)
            or any(api_emit._digest((output/"proof"/name).read_bytes()) != bound[name] for name in bindings)
            or api_emit._digest(CHECKER.read_bytes()) != result.get("runner_sha256")
            or api_emit._digest((CHECKER.parent/"ValidRead.v").read_bytes()) != bound["reference/projection/ValidRead.v"] or
            result.get("kernel_sources") != {"Original": api_emit._digest((root / REGMAP).read_bytes()),
                                             "Emitted": api_emit._digest(overlay[REGMAP])}):
        raise ValueError("unbound valid-map proof receipt")
    return {"receipt": "proof/result.json", "sha256": api_emit._digest((output / "proof/result.json").read_bytes()),
            "theorems": result["theorems"], "kernel_sources": result["kernel_sources"]}

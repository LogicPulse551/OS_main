"""Classify a private regmap once, after its converter has been initialized."""
import json
from pathlib import Path
import subprocess
import sys

from . import api_emit, valid_emit, var_emit
from .sixbyte_scan import SHARED_INPUTS


ENTRY = b"kconc_init_bulk_read"
REGMAP, HEADER = var_emit.REGMAP, var_emit.HEADER
INTERNAL = "drivers/base/regmap/internal.h"
CHECKER = Path(__file__).resolve().parents[2] / "proofs/init-regmap/check.py"
READY = b"""static bool kconc_bulk_permitted __ro_after_init;

static int __init kconc_freeze_bulk_policy(void)
{
	WRITE_ONCE(kconc_bulk_permitted, !kconc_keep_callback_entries);
	return 0;
}
early_initcall(kconc_freeze_bulk_policy);"""
BIND = b"""static void kconc_bind_bulk_format(struct regmap *map, bool enabled)
{
	if (!enabled)
		return;
	if (map->format.val_bytes != 1)
		return;
	if (map->format.parse_inplace != regmap_parse_inplace_noop)
		return;
	map->kconc_skip_noop = 1;
}"""
ASSIGN = b"\tkconc_bind_bulk_format(map, READ_ONCE(kconc_bulk_permitted));"


def framework_overlay(root):
    root = Path(root).resolve(strict=True)
    shared = var_emit.framework_overlay(root)
    core = api_emit._replace_once(shared[REGMAP], b"\n\n"+valid_emit.OBSERVATION, b"")
    noop = b"static void regmap_parse_inplace_noop(void *buf)\n{\n}"
    core = api_emit._replace_once(core, noop, b"\n\n".join((noop,valid_emit.OBSERVATION,READY,BIND)))
    label = b"skip_format_initialization:\n"
    core = api_emit._replace_once(core, label, label+ASSIGN+b"\n")
    guard = b"kconc_keep_callback_entries || val_count == 0 || val_count > INT_MAX || val_bytes != 1 ||\n\t\t    map->format.parse_inplace != regmap_parse_inplace_noop"
    core = api_emit._replace_once(core, guard, b"!map->kconc_skip_noop || val_count == 0 || val_count > INT_MAX")
    shared[REGMAP] = core.replace(var_emit.ENTRY, ENTRY)
    shared[HEADER] = shared[HEADER].replace(var_emit.ENTRY, ENTRY)
    locks = b"\tspinlock_t async_lock;\n\twait_queue_head_t async_waitq;"
    header = api_emit._read(root, INTERNAL, SHARED_INPUTS[INTERNAL])
    shared[INTERNAL] = api_emit._replace_once(header,locks,locks.replace(b"\n", b"\n\tbool kconc_skip_noop;\n"))
    return shared


def certificate(root, overlay, args, output):
    if not args.compcert or not args.coq_bin:
        raise ValueError("initialization-class proof environment unavailable")
    expected = framework_overlay(root)
    if any(overlay.get(name) != data for name, data in expected.items()):
        raise ValueError("unreviewed initialization-class regmap overlay")
    target = output / "init-framework"
    for name, data in expected.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    proof = output / "proof"
    cmd = [sys.executable,"-B",str(CHECKER),"--kernel",str(root),"--emitted",str(target),
           "--compcert",str(args.compcert),"--coq-bin",str(args.coq_bin),"--out",str(proof)]
    with (output/"checker.log").open("wb") as log:
        if subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode:
            raise ValueError("initialization-class proof check failed")
    result = json.loads((proof/"result.json").read_bytes())
    h = api_emit._digest
    sources = {name:h(data) for name,data in expected.items()}
    evidence = result.get("inputs", {})
    if (result.get("passed") is not True or result.get("kernel_sources") != sources or
            result.get("runner_sha256") != h(CHECKER.read_bytes()) or
            set(result.get("theorems", [])) != REQUIRED or
            {r["label"] for r in result.get("commands",[]) if r["exit_code"] == 0} !=
                {"reference","target-project","InitTarget","InitGuard","InitRead","coqchk"} or
            any(r["exit_code"] for r in result["commands"]) or
            not {"target/Case.c","target/Case.v","reference/reference/projection/InitRead.v",
                 "reference/reference/projection/InitRead.vo","InitRead.stdout","lifecycle.json",
                 "reference/result.json"}.issubset(evidence) or
            any(h((proof/name).read_bytes()) != value for name,value in evidence.items()) or
            evidence["reference/reference/projection/InitRead.v"] != h((CHECKER.parent/"InitRead.v").read_bytes())):
        raise ValueError("unbound initialization-class proof receipt")
    return {"receipt":"proof/result.json","sha256":h((proof/"result.json").read_bytes()),
            "theorems":result["theorems"],"kernel_sources":sources}


REQUIRED = {"InitRead.actual_functions","InitRead.bind_format","InitRead.read_dispatch","InitRead.disabled_instance",
            "InitRead.checked_read","InitRead.initial_class_stable","VariableRead.machine_indices",
            "VariableRead.machine_expressions","InitGuard.linked_empty_callback"}

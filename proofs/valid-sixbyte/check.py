"""Check the emitted post-raw-success selector against the pinned Linux function and class proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OLDER = HERE.parent / "api-sixbyte/check.py"
ORIGINAL = "3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9"
EMITTED = "809ad96ce56ae44e3a9285c1a886f6fae76dfed0a2ecad68daa4678239032fd9"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(path, expected):
    if digest(path) != expected:
        raise ValueError("Changed proof input: " + str(path))


def constructor_evidence(data, function):
    """Locate the assignments in this locked implementation without claiming points-to closure."""
    pattern = rb"map->format\.parse_inplace\s*=\s*(regmap_\w+)\s*;"
    writes = list(re.finditer(pattern, data))
    init = function(data, b"struct regmap *__regmap_init(")
    start = data.index(init)
    publish = init.index(b"regmap_attach_dev(dev, map, config)")
    if len(writes) != 6 or any(not start <= m.start() < start+publish for m in writes):
        raise ValueError("Unrecognized initialization/publication order")
    reinit = function(data, b"int regmap_reinit_cache(")
    if re.search(rb"map->format\b", reinit):
        raise ValueError("Cache reinitialization unexpectedly modifies the formatter")
    line = lambda i: data.count(b"\n", 0, i)+1
    return {"regmap_sha256": hashlib.sha256(data).hexdigest(),
            "explicit_slot_writes": [{"line": line(m.start()), "value": m[1].decode()} for m in writes],
            "attach_device_line": line(start+publish), "cache_reinit_line": line(data.index(reinit)),
            "c_interface_contract": [
                "Each selected call supplies a live regmap and an output region valid for the original API.",
                "The call keeps the map live until completion; concurrent release and invalid aliases are excluded.",
                "Normal API users and transport callbacks respect ownership of the internal format field.",
                "No out-of-contract writes, indirect overwrites or instrumented replacement of the empty function.",
                "Callback-entry observation is requested at boot; the default observation excludes noop entries."],
            "machine_model": "Constructor store and a readable unchanged slot in the original and six observation memories.",
            "layout": "The generated Clight layout is reduced. Its concrete offset 8 does not stand for Linux's offset."}


def run(original, emitted, compcert, coq_bin, out):
    original, emitted, compcert, coq_bin, out = [p.resolve() for p in (original, emitted, compcert, coq_bin, out)]
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"passed": False, "commands": [], "theorems": [], "schema": 1}
    env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])

    def invoke(label, cmd, cwd):
        row = {"label": label, "argv": list(map(str, cmd)), "cwd": str(cwd)}
        receipt["commands"].append(row)
        so, se = out / (label+".stdout"), out / (label+".stderr")
        with so.open("wb") as stdout, se.open("wb") as stderr:
            row["exit_code"] = subprocess.run(row["argv"], cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                              timeout=900).returncode
        row.update(stdout_sha256=digest(so), stderr_sha256=digest(se))
        if row["exit_code"]:
            raise ValueError(f"{label} failed; see {se}")

    try:
        receipt["kernel_sources"] = {"Original": digest(original), "Emitted": digest(emitted)}
        require(original, ORIGINAL)
        require(emitted, EMITTED)
        require(HERE/"ValidRead.v", "958b0f3b4bc93064bdfcedfda4ffee833ac905e39d5ea2d227ec4c3c7bfc7a62")
        require(OLDER, "22b4eae6e7f352cd572b62d83524e741542da4338ce54b91137f3db4fc3edfdd")
        require(HERE.parent/"bma400-noop/check_scoped.py", "900df78cb94bfa06e674d2f3914746af69a93bccb5591f620a7afa1fa98d2ef9")
        require(HERE.parent/"bma400-noop/check.py", "c3fa60b7d18ef4eeb1eeafcc948e2956120fd8ff412b19c9ad098f595e71b7d1")
        sys.path.insert(0, str(REPO / "src"))
        from kconc import api_emit, valid_emit
        sys.path.insert(0, str(HERE.parent / "bma400-noop"))
        import check_scoped as projection
        # Rebuild the already certified reference kernel separately. Its digest is
        # pinned independently by the old checker. It is never installed in Linux.
        orig, full = original.read_bytes(), emitted.read_bytes()
        receipt["api_contract"] = constructor_evidence(orig, projection.function)
        public = projection.function(orig, projection.PUBLIC)
        noop = projection.function(orig, projection.NOOP)
        helper = projection.function(full, b"int " + valid_emit.ENTRY + b"(")
        if public != projection.function(full, projection.PUBLIC) or noop != projection.function(full, projection.NOOP):
            raise ValueError("Public original or empty converter changed")
        legacy = api_emit._replace_once(public, b"int regmap_bulk_read(", b"static int kconc_sixbyte_guarded(")
        legacy = api_emit._replace_once(legacy, api_emit.LOOP.encode(), api_emit.GUARDED_LOOP.encode())
        includes = b'#include "internal.h"'
        reference = api_emit._replace_once(orig, includes, includes + b"\n#include <linux/init.h>\n#include <linux/kstrtox.h>")
        reference = api_emit._replace_once(reference, api_emit.EXPORT,
            api_emit.EXPORT + b"\n\n" + legacy.rstrip() + b"\n" + api_emit.GATE.rstrip())
        refpath = out / "reference-regmap.c"
        refpath.write_bytes(reference)
        require(refpath, "6d2a9bab5ee6ca76d0761374937bd153fd002df916d19d00c27c0a1f8879b96a")
        legacy_out = out / "reference"
        invoke("reference", [sys.executable, "-B", OLDER, "--original", original, "--emitted", refpath,
                             "--compcert", compcert, "--coq-bin", coq_bin, "--out", legacy_out], out)
        previous = json.loads((legacy_out / "result.json").read_bytes())
        if not previous["passed"] or "GenericRead.any_start_six" not in previous["theorems"]:
            raise ValueError("GenericRead reference was not checked")
        work = legacy_out / "projection"
        old = json.loads((work / "result.json").read_bytes())
        decl = (work / "case_declarations.h").read_text()
        original_unit = projection.projection(orig.decode(), decl)
        original_fn = public.decode().replace("val + i", "(unsigned char *)val + i")
        if not original_unit.endswith(original_fn):
            raise ValueError("Public projection does not end at the actual bulk read")
        target_unit = original_unit[:-len(original_fn)] + "extern bool kconc_keep_callback_entries;\n"
        target_unit += helper.decode().replace("val + i", "(unsigned char *)val + i")
        folder = out / "target"
        folder.mkdir()
        (folder / "Case.c").write_text(target_unit)
        for name, path in [("clightgen", compcert/"clightgen"), ("coqc", coq_bin/"coqc"), ("coqchk", coq_bin/"coqchk")]:
            require(path, old["tools"][name])
        invoke("target-project", [compcert/"clightgen", "-canonical-idents", "-o", "Case.v", "Case.c"], folder)
        require(folder/"Case.v", "417d45955536d870915c22bad508a9f26fe364c5368c9d15db939cb88e42e1df")
        (work/"Valid.v").write_bytes((folder/"Case.v").read_bytes())
        (work/"ValidGuard.v").write_text((work/"ProjectedGuard.v").read_text().replace("Guarded","Valid"))
        (work/"ValidRead.v").write_bytes((HERE/"ValidRead.v").read_bytes())
        cmd = next(c["argv"][:-1] for c in old["commands"] if c["label"] == "ObjectClass")
        for name in ("Valid", "ValidGuard", "ValidRead"):
            invoke(name, [*cmd, name+".v"], work)
        invoke("coqchk", [coq_bin/"coqchk", "-silent", *cmd[2:], "Bma400.ValidGuard", "Bma400.ValidRead"], work)
        receipt.update(passed=True, scope="local Clight guard, original/enabled loop and live-map API slot contract",
            theorems=["GenericRead.any_start_six", "ValidRead.actual_function", "ValidRead.execute_selector",
                      "ValidRead.dispatch_loop", "ValidGuard.actual_guard_false", "ValidRead.fast_cut_step",
                      "ValidRead.api_read", "ValidRead.checked_success"],
            inputs={str(p.relative_to(out)):digest(p) for p in
                    (refpath,legacy_out/"result.json",folder/"Case.c",folder/"Case.v",work/"ValidGuard.v",
                     work/"ValidRead.v",work/"ValidRead.vo",out/"ValidRead.stdout")},
            runner_sha256=digest(Path(__file__)), prior_checker_sha256=digest(OLDER))
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        (out/"result.json").write_text(json.dumps(receipt, indent=2)+"\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("original", "emitted", "compcert", "coq-bin", "out"):
        p.add_argument("--"+name, type=Path, required=True)
    a = p.parse_args()
    run(a.original, a.emitted, a.compcert, a.coq_bin, a.out)

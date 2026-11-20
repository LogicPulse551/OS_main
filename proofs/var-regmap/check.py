"""Check the bulk-read body including Linux's real signed length limit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PARENT = HERE.parent / "sixbyte/check.py"
ORIGINAL = "3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9"
EMITTED = "4c83d201ef5a82dd88200bbe3bb13aa3a27abe1d746d4b5947dd8a70aeb3a298"
LIMITS = "653708a73389bd7a9ef4dd85acf45f19227ac60f2dc133d6285af29cff774544"
TARGET_AST = "4b13075d92df11588b59b53e3e037267482aa8aa034c9e0ea104159e5e995a4e"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(path, value):
    if digest(path) != value:
        raise ValueError("Changed proof input: " + str(path))


def run(original, emitted, compcert, coq_bin, out):
    original, emitted, compcert, coq_bin, out = [p.resolve() for p in (original, emitted, compcert, coq_bin, out)]
    out.mkdir(parents=True, exist_ok=False)
    result = {"passed": False, "commands": [], "theorems": [], "schema": 1}
    env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])

    def invoke(label, cmd, cwd):
        row = {"label": label, "argv": list(map(str, cmd)), "cwd": str(cwd)}
        result["commands"].append(row)
        so, se = out/(label+".stdout"), out/(label+".stderr")
        with so.open("wb") as stdout, se.open("wb") as stderr:
            row["exit_code"] = subprocess.run(row["argv"], cwd=cwd, stdout=stdout, stderr=stderr,
                                              env=env, timeout=900).returncode
        row.update(stdout_sha256=digest(so), stderr_sha256=digest(se))
        if row["exit_code"]:
            raise ValueError(f"{label} failed; see {se}")

    try:
        result["kernel_sources"] = {"Original": digest(original), "Emitted": digest(emitted)}
        require(original, ORIGINAL)
        require(emitted, EMITTED)
        require(HERE/"VariableRead.v","c69fb7f191d128ac77d98b5a32debb2c521fce823c2720eea6edc8166a8d54d2")
        require(PARENT, "c1a716ffacecf25f6587f5147f09088f9785304f2a5d4ce5d985b031b3a18487")
        legacy = HERE.parent/"bma400-noop"
        require(legacy/"check_scoped.py", "900df78cb94bfa06e674d2f3914746af69a93bccb5591f620a7afa1fa98d2ef9")
        require(legacy/"check.py", "c3fa60b7d18ef4eeb1eeafcc948e2956120fd8ff412b19c9ad098f595e71b7d1")
        sys.path.insert(0, str(legacy))
        import check_scoped as projection
        sys.path.insert(0, str(REPO/"src"))
        from kconc import api_emit, var_emit
        data, target = original.read_bytes(), emitted.read_bytes()
        public = projection.function(data, projection.PUBLIC)
        noop = projection.function(data, projection.NOOP)
        helper = projection.function(target, b"int " + var_emit.ENTRY + b"(")
        if public != projection.function(target, projection.PUBLIC) or noop != projection.function(target, projection.NOOP):
            raise ValueError("Public source or empty callback changed")
        # Regenerate the old local proof library in a separate directory. Its
        # fixed private helper provides the checked reference loop and memory model.
        ref = api_emit._replace_once(public, projection.PUBLIC, b"static int kconc_sixbyte_guarded(")
        ref = api_emit._replace_once(ref, api_emit.LOOP.encode(), api_emit.GUARDED_LOOP.encode())
        ref_path = out/"reference-regmap.c"
        ref_path.write_bytes(api_emit._replace_once(data, api_emit.EXPORT, api_emit.EXPORT+b"\n\n"+ref))
        work = out/"reference/projection"
        invoke("reference",[sys.executable,"-B",PARENT,"--original",original,"--emitted",ref_path,
                            "--compcert",compcert,"--coq-bin",coq_bin,"--out",work],out)
        previous = json.loads((work/"result.json").read_bytes())
        if not previous.get("passed"):
            raise ValueError("Local class proof or original projection failed")
        header = original.parents[3]/"include/vdso/limits.h"
        require(header, LIMITS)
        maximum, = [line for line in header.read_text().splitlines() if line.split()[:2]==["#define","INT_MAX"]]
        decl = (work/"case_declarations.h").read_text()
        unit = projection.projection(data.decode(), decl)
        normalized = public.decode().replace("val + i", "(unsigned char *)val + i")
        if not unit.endswith(normalized):
            raise ValueError("Partial function projection")
        folder = out/"target"
        folder.mkdir()
        (folder/"Case.c").write_text(unit[:-len(normalized)] + maximum + "\nextern bool kconc_keep_callback_entries;\n" +
                                     helper.decode().replace("val + i", "(unsigned char *)val + i"))
        for name, path in [("clightgen",compcert/"clightgen"), ("coqc",coq_bin/"coqc"), ("coqchk",coq_bin/"coqchk")]:
            require(path,previous["tools"][name])
        invoke("target-project",[compcert/"clightgen","-canonical-idents","-o","Case.v","Case.c"],folder)
        require(folder/"Case.v",TARGET_AST)
        (work/"VarTarget.v").write_bytes((folder/"Case.v").read_bytes())
        (work/"VarGuard.v").write_text((work/"ProjectedGuard.v").read_text().replace("Guarded","VarTarget"))
        (work/"VariableRead.v").write_bytes((HERE/"VariableRead.v").read_bytes())
        cmd = next(r["argv"][:-1] for r in previous["commands"] if r["label"]=="ObjectClass")
        for name in ("VarTarget","VarGuard","VariableRead"):
            invoke(name,[*cmd,name+".v"],work)
        invoke("coqchk",[coq_bin/"coqchk","-silent",*cmd[2:],"Bma400.VarGuard","Bma400.VariableRead"],work)
        result.update(passed=True, theorems=sorted(var_emit.REQUIRED),
            runner_sha256=digest(Path(__file__)), limits_header_sha256=LIMITS,
            arithmetic={"abi":"x86_64","int_max":2147483647,"size_t_bits":64,"minimum_fast_count":1},
            inputs={str(p.relative_to(out)):digest(p) for p in (
                ref_path,work/"result.json",folder/"Case.c",folder/"Case.v",work/"VarGuard.v",work/"VariableRead.v",
                work/"VariableRead.vo",out/"VariableRead.stdout")})
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("original","emitted","compcert","coq-bin","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    run(args.original,args.emitted,args.compcert,args.coq_bin,args.out)

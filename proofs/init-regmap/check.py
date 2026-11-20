"""Bind the constructor cut, private field and successful read cut to Linux."""
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
sys.path.insert(0,str(REPO/"src"))
sys.path.insert(0,str(HERE.parent/"bma400-noop"))
import check_scoped as pr
from kconc import init_emit as emit, var_emit

REVIEWED = {
    emit.REGMAP: "0328b4e462a825d4881c431ade46276aa888993e5b74c10ac5c160a925c34282",
    emit.HEADER: "ab2899c55d849c3c31fe90b4bc060619b9418856d6f20a82e414db760b10961e",
    emit.INTERNAL: "d4edbde619c79e5d1cc14a61ccdad6651d39ea945553082d3bcefec135484156",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lifecycle(root, emitted):
    boot = root/"init/main.c"
    cache = root/"drivers/base/regmap/regcache.c"
    if (digest(boot) != "e895a643df800a83857b88bebb6e990c17cd0890e485a48a7b972f5d2ae73516" or
            digest(cache) != "075eaa501708463495be83048ed3a6077dcfe80fd27cb3ec1b0c1c4f3bfda718"):
        raise ValueError("Unsupported boot or regcache implementation")
    data = (emitted/emit.REGMAP).read_bytes()
    ctor = pr.function(data,b"struct regmap *__regmap_init(")
    reinit = pr.function(data,b"int regmap_reinit_cache(")
    boot_data=boot.read_bytes()
    start=pr.function(boot_data,b"void start_kernel(")
    if not start.index(b'parse_args("Booting kernel"') < start.index(b"&unknown_bootoption") < start.index(b"rest_init();"):
        raise ValueError("Boot option ordering changed")
    if any(anchor not in boot_data for anchor in (b"do_pre_smp_initcalls();",b"kernel_init_freeable();",
                                                   b"__initcall_start",b"__initcall0_start")):
        raise ValueError("Early init sequence changed")
    original = (root/emit.REGMAP).read_bytes()
    if reinit != pr.function(original,b"int regmap_reinit_cache("):
        raise ValueError("Changed cache reinitialization")
    required = [b"map = kzalloc_obj(*map);",b"map->format.val_bytes =",
                b"map->format.parse_inplace = regmap_parse_inplace_noop;",
                b"skip_format_initialization:\n"+emit.ASSIGN,b"map->range_tree = RB_ROOT;",
                b"ret = regcache_init(map, config);",b"ret = regmap_attach_dev(dev, map, config);",
                b"regmap_debugfs_init(map);", b"return map;"]
    places = [ctor.index(x) for x in required]
    if (places != sorted(places) or ctor.count(b"goto skip_format_initialization;")!=2 or
            len(re.findall(rb"map->format\.(?:parse_inplace|val_bytes)\s*=(?!=)",data)) !=
            len(re.findall(rb"map->format\.(?:parse_inplace|val_bytes)\s*=(?!=)",ctor[:places[3]])) or
            b"map->format" in reinit or data.count(emit.ASSIGN)!=1 or data.count(emit.READY)!=1 or
            len(re.findall(rb"map->kconc_skip_noop\s*=(?!=)",data))!=1 or
            any(x in cache.read_bytes() for x in (b"map->kconc_skip_noop =",b"map->format.parse_inplace =",
                                                   b"map->format.val_bytes ="))):
        raise ValueError("Changed constructor, format write or cache reinitialization")
    return {"original_core_sha256":digest(root/emit.REGMAP),"boot_sha256":digest(boot),"cache_sha256":digest(cache),
            "ordered_constructor_anchors":[x.decode() for x in required],"early_format_bypasses":2,
            "policy":"BSS denies until early_initcall snapshots final boot option by WRITE_ONCE. Each new map reads one bool.",
            "reinit":"Cache reinitialization preserves the format and qualification. Its API excludes concurrent calls.",
            "lifetime":"Live, published API objects under normal regmap ownership; out-of-framework stores and access after free are outside the contract."}


def project_case(root, core, work):
    data=(root/emit.REGMAP).read_bytes()
    public = pr.function(data,pr.PUBLIC)
    if pr.function(core,pr.PUBLIC)!=public or pr.function(data,pr.NOOP)!=pr.function(core,pr.NOOP):
        raise ValueError("Original public read or known callback changed")
    decl = (work/"case_declarations.h").read_text().replace("enum regcache_type cache_type;","enum regcache_type cache_type;\n\tbool kconc_skip_noop;")
    unit=pr.projection(data.decode(),decl)
    old = public.decode().replace("val + i","(unsigned char *)val + i")
    if not unit.endswith(old): raise ValueError("Incomplete source projection")
    binder = pr.function(core,b"static void kconc_bind_bulk_format(")
    helper = pr.function(core,b"int "+emit.ENTRY+b"(")
    max_line, = [x for x in (root/"include/vdso/limits.h").read_text().splitlines()
                 if x.split()[:2]==["#define","INT_MAX"]]
    retain = "void kconc_project_bind(struct regmap *map, bool enabled) { kconc_bind_bulk_format(map, enabled); }"
    return unit[:-len(old)]+max_line+"\n"+binder.decode()+"\n"+retain+"\n"+helper.decode().replace("val + i","(unsigned char *)val + i")


def run(root, target, cc, coq, out):
    root,target,cc,coq,out = [v.resolve() for v in (root,target,cc,coq,out)]
    out.mkdir(parents=True,exist_ok=False)
    result={"schema":1,"passed":False,"commands":[]}
    env=dict(os.environ,PATH=str(coq)+os.pathsep+os.environ["PATH"])
    def invoke(name,argv,cwd):
        row={"label":name,"argv":list(map(str,argv)),"cwd":str(cwd)}
        result["commands"].append(row)
        stdout,stderr=out/(name+".stdout"),out/(name+".stderr")
        with stdout.open("wb") as so, stderr.open("wb") as se:
            row["exit_code"]=subprocess.run(row["argv"],cwd=cwd,env=env,stdout=so,stderr=se,timeout=1000).returncode
        row.update(stdout_sha256=digest(stdout),stderr_sha256=digest(stderr))
        if row["exit_code"]: raise ValueError(name+" failed; see "+str(stderr))
    try:
        for name,raw in emit.framework_overlay(root).items():
            if (target/name).read_bytes()!=raw: raise ValueError("Unbound emitted source "+name)
        result["kernel_sources"]={k:digest(target/k) for k in emit.framework_overlay(root)}
        if result["kernel_sources"] != REVIEWED:
            raise ValueError("Unreviewed constructor, public API or private field layout")
        if digest(var_emit.CHECKER)!="7b66eaa089fdab6cb51a96ae7c95d94c412e4a58eba84acda2cdb080497cdbe0":
            raise ValueError("Changed reference proof checker")
        audit=out/"lifecycle.json"
        audit.write_text(json.dumps(lifecycle(root,target),indent=2)+"\n")
        reference=out/"variable-regmap.c"
        reference.write_bytes(var_emit.framework_overlay(root)[emit.REGMAP])
        invoke("reference",[sys.executable,"-B",var_emit.CHECKER,"--original",root/emit.REGMAP,
                           "--emitted",reference,"--compcert",cc,"--coq-bin",coq,"--out",out/"reference"],out)
        previous=json.loads((out/"reference/result.json").read_bytes())
        if not previous["passed"]: raise ValueError("Variable read proof failed")
        work=out/"reference/reference/projection"
        path=out/"target"
        path.mkdir()
        (path/"Case.c").write_text(project_case(root,(target/emit.REGMAP).read_bytes(),work))
        invoke("target-project",[cc/"clightgen","-canonical-idents","-o","Case.v","Case.c"],path)
        if digest(path/"Case.v")!="ff15af9eff5995c8858bf8a66bb6ae852a39fab7fd1a066393d598f9bc020728":
            raise ValueError("Changed initialization-class Clight AST")
        (work/"InitTarget.v").write_bytes((path/"Case.v").read_bytes())
        (work/"InitGuard.v").write_text((work/"ProjectedGuard.v").read_text().replace("Guarded","InitTarget"))
        (work/"InitRead.v").write_bytes((HERE/"InitRead.v").read_bytes())
        cmd=next(row["argv"][:-1] for row in previous["commands"] if row["label"]=="VariableRead")
        for name in ("InitTarget","InitGuard","InitRead"): invoke(name,[*cmd,name+".v"],work)
        invoke("coqchk",[coq/"coqchk","-silent",*cmd[2:],"Bma400.InitGuard","Bma400.InitRead"],work)
        proof_source = (work/"InitRead.v").read_text()
        if digest(work/"InitTarget.v") != digest(path/"Case.v"):
            raise ValueError("Projected and compiled target differ")
        for theorem in emit.REQUIRED:
            printed = theorem.removeprefix("InitRead.")
            if f"Print Assumptions {printed}." not in proof_source:
                raise ValueError("Theorem assumptions were not inspected: "+theorem)
        result.update(passed=True,theorems=sorted(emit.REQUIRED),runner_sha256=digest(Path(__file__)),
                      inputs={str(p.relative_to(out)):digest(p) for p in (
                          reference,out/"reference/result.json",audit,path/"Case.c",path/"Case.v",work/"InitTarget.v",work/"InitGuard.v",
                          work/"InitRead.v",work/"InitRead.vo",out/"InitRead.stdout")})
    except Exception as exc:
        result["error"]=str(exc)
        raise
    finally:
        (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("kernel","emitted","compcert","coq-bin","out"): parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    run(args.kernel,args.emitted,args.compcert,args.coq_bin,args.out)

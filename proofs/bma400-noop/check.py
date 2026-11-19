"""Rebuild the two projected Clight units from full regmap.c files and check the local certificate."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


KERNEL_SOURCES = {
    "Original": "3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9",
    "Guarded": "08cd1f996b3871826ca3afe8c3979c6d0262e68ef5cc53fec4e627d848f03c38",
}
GENERATED = {
    "Original": "fc27a9d68d7ae2aecad5f5cd0eefb978fe0771bc248206f0944dd948b46afe82",
    "Guarded": "f00b9e32926eba0653349046604fe5d50192c50b9a1759d1ceb13f17b9d66408",
}
BINARIES = {
    "clightgen": "9348c175cc5576a7f924971107d66d72e1d513edd7591414b077cf75ca4f216b",
    "coqc": "73047a45272f679d612a388cc1168ec9caae2f1e8f1a79c2f0a5089f5efc7317",
    "coqchk": "47b0284e3259213ebd46777a2eb0a394f60ee821e3ccea92d0328f6e928512dd",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def projection(source, declarations):
    def function(signature):
        start = source.index(signature)
        return source[start:source.index("\n}\n", start) + 3]

    noop = function("static void regmap_parse_inplace_noop(void *buf)\n{")
    bulk = function("int regmap_bulk_read(struct regmap *map")
    # The GNU void-pointer addition advances bytes. Taking the static callback's
    # address in both excerpts keeps its definition in the source projection.
    anchor = "void (*const c04_callback_anchor)(void *) = regmap_parse_inplace_noop;\n"
    return declarations + "\n" + noop + "\n" + anchor + "\n" + bulk.replace("val + i", "(unsigned char *)val + i")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True, type=Path, help="locked original regmap.c")
    parser.add_argument("--guarded", required=True, type=Path, help="guarded regmap.c from the measured build")
    parser.add_argument("--compcert", required=True, type=Path)
    parser.add_argument("--coq-bin", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    work = args.out.resolve()
    work.mkdir(parents=True, exist_ok=False)
    src = Path(__file__).resolve().parent
    flags = []
    for part in ("lib", "common", "x86_64", "x86", "backend", "cfrontend",
                 "driver", "export", "cparser"):
        flags.extend(("-R", str(args.compcert.resolve() / part), "compcert." + part))
    for part, logical in (("flocq", "Flocq"), ("MenhirLib", "MenhirLib")):
        flags.extend(("-R", str(args.compcert.resolve() / part), logical))
    flags.extend(("-Q", str(work), "Bma400"))
    coq_bin = args.coq_bin.resolve()
    env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])
    receipt = {"passed": False, "inputs": {}, "kernel_sources": {}, "commands": []}

    def check(label, exe, argv, cwd=work):
        cmd = [str(exe), *argv]
        row = {"argv": cmd, "cwd": str(cwd), "binary_sha256": digest(exe)}
        receipt["commands"].append(row)
        if row["binary_sha256"] != BINARIES[exe.name]:
            raise ValueError(f"unrecognized {exe.name}")
        with (work / (label + ".out")).open("wb") as out, (work / (label + ".err")).open("wb") as err:
            row["exit_code"] = subprocess.run(cmd, cwd=cwd, env=env, stdout=out,
                                              stderr=err, timeout=360).returncode
        if row["exit_code"]:
            raise RuntimeError(f"{label} failed; see {work / (label + '.err')}")

    try:
        shutil.copyfile(__file__, work / "runner.py")
        declarations = (src / "case_declarations.h").read_text(encoding="utf-8")
        inputs = {}
        for name, path in (("Original", args.original), ("Guarded", args.guarded)):
            folder = work / name
            folder.mkdir()
            artifact = folder / "regmap.c"
            shutil.copyfile(path, artifact)
            receipt["kernel_sources"][name] = digest(artifact)
            if receipt["kernel_sources"][name] != KERNEL_SOURCES[name]:
                raise ValueError(f"unrecognized {name} regmap.c")
            (folder / "Case.c").write_text(projection(artifact.read_text(encoding="utf-8"), declarations),
                                           encoding="utf-8")
            check(name + "-project", args.compcert.resolve() / "clightgen",
                  ["-canonical-idents", "-o", "Case.v", "Case.c"], cwd=folder)
            inputs[name] = folder / "Case.v"
            if digest(inputs[name]) != GENERATED[name]:
                raise ValueError(f"{name} Clight projection differs from the reviewed unit")
        for name in ("BulkRead", "ClightBinding", "NativeNoop"):
            inputs[name] = src / (name + ".v")
        for name, path in inputs.items():
            copy = work / (name + ".v")
            shutil.copyfile(path, copy)
            receipt["inputs"][name] = digest(copy)
            check(name, coq_bin / "coqc", ["-q", *flags, copy.name])
        check("coqchk", coq_bin / "coqchk",
              ["-silent", *flags, "Bma400.ClightBinding", "Bma400.NativeNoop"])
        receipt["passed"] = True
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        (work / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

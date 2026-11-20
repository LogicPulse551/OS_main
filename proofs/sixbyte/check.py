"""Bind the generated SPI-only helper to the class rule and check both six-byte reads."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / "bma400-noop"
SOURCE_LOCKS = {
    "ObjectClass.v": "09cbb2722bb8bfdecf79955808ba509a094588748a6d4333e6785ba80aa74cb1",
    "ProjectedGuard.v": "e8e5ac96bda79514bb03d5c50dd06c79572e0969e4cd76b28945d98c45afafb4",
    "Kx022aRead.v": "34e3c014d9bfc5af3a8305a78711c95d12a9b8dbd40605d63580c90fc5ed066f",
    "DeviceReads.v": "63334960fcca2b8607c220897e0ac0187e7cfbad541269370a3c684de4a83e56",
}
PRIVATE = b"static int kconc_sixbyte_guarded("


def digest(data):
    return hashlib.sha256(data).hexdigest()


def locked(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"Changed input {path}")
    return data


def projected_units(old, original, emitted, declarations):
    """Slice the new definition itself before normalizing its symbol for comparison."""
    public = old.function(original, old.PUBLIC)
    noop = old.function(original, old.NOOP)
    private = old.function(emitted, PRIVATE)
    if public != old.function(emitted, old.PUBLIC) or noop != old.function(emitted, old.NOOP):
        raise ValueError("Public original or empty callback changed")
    if public + b"EXPORT_SYMBOL_GPL(regmap_bulk_read);\n\n" + private not in emitted:
        raise ValueError("Missing private definition after the original public export")
    public_guard = old.PUBLIC + private[len(PRIVATE):]
    reconstructed = original.replace(public, public_guard, 1)
    if digest(reconstructed) != old.KERNEL_SOURCES["Guarded"]:
        raise ValueError("Generated helper differs from the certified guarded function")
    reference_unit = old.projection(original.decode(), declarations)
    guarded_unit = old.projection(reconstructed.decode(), declarations)
    normalized = public_guard.decode().replace("val + i", "(unsigned char *)val + i")
    if not guarded_unit.endswith(normalized):
        raise ValueError("Private guard projection does not cover the entire function")
    private_unit = (guarded_unit[:-len(normalized)]
                    + private.decode().replace("val + i", "(unsigned char *)val + i")
                    + old.PRIVATE_ANCHOR.replace("kconc_bma400_bulk_read", "kconc_sixbyte_guarded"))
    units = {"Original": reference_unit, "Guarded": guarded_unit, "Private": private_unit}
    return units, {"original_public": digest(public), "emitted_public": digest(old.function(emitted, old.PUBLIC)),
                   "private": digest(private), "noop": digest(noop)}


def run(original_path, emitted_path, compcert, coq_bin, out):
    out = out.resolve()
    compcert = compcert.resolve()
    coq_bin = coq_bin.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": 1, "passed": False, "commands": [], "tools": {}, "inputs": {},
               "kernel_sources": {}, "vo_sha256": {}, "assumptions_sha256": {}}
    try:
        # These projectors and templates are executable inputs. Check them before importing.
        locked(PRIOR/"check_scoped.py", "900df78cb94bfa06e674d2f3914746af69a93bccb5591f620a7afa1fa98d2ef9")
        locked(PRIOR/"check.py", "c3fa60b7d18ef4eeb1eeafcc948e2956120fd8ff412b19c9ad098f595e71b7d1")
        sys.path.insert(0, str(PRIOR))
        old = importlib.import_module("check_scoped")
        receipt["runner_sha256"] = digest(Path(__file__).read_bytes())
        original = locked(original_path, old.KERNEL_SOURCES["Original"])
        emitted = emitted_path.read_bytes()
        receipt["kernel_sources"] = {"Original": digest(original), "Emitted": digest(emitted)}
        for folder, locks in ((PRIOR, old.CERTIFICATE), (HERE, SOURCE_LOCKS)):
            for name, expected in locks.items():
                (out/name).write_bytes(locked(folder/name, expected))
                receipt["inputs"][name] = expected
        units, binding = projected_units(old, original, emitted, (out/"case_declarations.h").read_text())
        receipt["extracted_sha256"] = binding
        runtime = json.loads(locked(old.LOCK, old.LOCK_SHA256))["runtime_files"]
        for name, expected in runtime.items():
            locked(compcert.parent/name, expected)
        receipt["environment"] = {"lock_sha256": old.LOCK_SHA256, "checked_files": len(runtime)}
        flags = []
        for part in ("lib","common","x86_64","x86","backend","cfrontend","driver","export","cparser","flocq","MenhirLib"):
            logical = {"flocq":"Flocq", "MenhirLib":"MenhirLib"}.get(part,"compcert."+part)
            flags.extend(["-R",str(compcert/part),logical])
        flags.extend(["-Q",str(out),"Bma400"])
        env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])

        def invoke(label, tool, args, cwd):
            locked(tool, old.BINARIES[tool.name])
            receipt["tools"][tool.name] = old.BINARIES[tool.name]
            row = {"label": label, "argv": [str(tool), *args], "cwd": str(cwd)}
            receipt["commands"].append(row)
            stdout, stderr = out/(label+".stdout"), out/(label+".stderr")
            with stdout.open("wb") as so, stderr.open("wb") as se:
                row["exit_code"] = subprocess.run(row["argv"], cwd=cwd, env=env, stdout=so, stderr=se,
                                                  timeout=360).returncode
            row.update(stdout_sha256=digest(stdout.read_bytes()), stderr_sha256=digest(stderr.read_bytes()))
            if row["exit_code"]:
                raise RuntimeError(f"{label} failed; see {stderr}")

        for name, source in units.items():
            folder = out/name
            folder.mkdir()
            (folder/"Case.c").write_text(source, encoding="utf8")
            invoke(name+"-project",compcert/"clightgen",["-canonical-idents","-o","Case.v","Case.c"],folder)
            if name in old.GENERATED:
                locked(folder/"Case.v",old.GENERATED[name])
            shutil.copyfile(folder/"Case.v",out/(name+".v"))
        (out/"EmittedBinding.v").write_text(
            old.PROOF.replace("kconc_bma400_bulk_read","kconc_sixbyte_guarded"), encoding="utf8")
        # Check the actual private program's function-symbol environment in addition
        # to the public guarded projection used by the frozen abstract proof.
        private_guard = (out/"ProjectedGuard.v").read_text().replace("Guarded", "Private")
        (out/"PrivateGuard.v").write_text(private_guard, encoding="utf8")
        libraries = ("Original","Guarded","Private","BulkRead","ClightBinding","NativeNoop","ObjectClass",
                     "ProjectedGuard","PrivateGuard","EmittedBinding","Kx022aRead","DeviceReads")
        for name in libraries:
            receipt["inputs"][name+".v"] = digest((out/(name+".v")).read_bytes())
            invoke(name,coq_bin/"coqc",["-q",*flags,name+".v"],out)
            receipt["vo_sha256"][name] = digest((out/(name+".vo")).read_bytes())
            if name not in units:
                receipt["assumptions_sha256"][name] = receipt["commands"][-1]["stdout_sha256"]
        invoke("coqchk",coq_bin/"coqchk",["-silent",*flags,"Bma400.ProjectedGuard","Bma400.DeviceReads"],out)
        receipt["theorems"] = ["EmittedBinding.emitted_cut", "PrivateGuard.actual_guard_false",
                               "DeviceReads.both_driver_reads", "Kx022aRead.kx022a_spi_three_axes"]
        receipt["operations"] = [["bma400-spi",4,6],["kx022a-spi",6,6]]
        receipt["passed"] = True
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        (out/"result.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("original","emitted","compcert","coq-bin","out"):
        parser.add_argument("--"+arg,type=Path,required=True)
    opts = parser.parse_args()
    run(opts.original,opts.emitted,opts.compcert,opts.coq_bin,opts.out)

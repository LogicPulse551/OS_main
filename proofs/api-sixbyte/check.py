"""Check the exact guarded kernel and the six-byte theorem at any starting register."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
PROJECTOR = HERE.parent / "sixbyte" / "check.py"
PROJECTOR_SHA256 = "c1a716ffacecf25f6587f5147f09088f9785304f2a5d4ce5d985b031b3a18487"
GENERIC_SHA256 = "0f45ecf178e7062457afa4e5fc9cba9463113e623ee7447a8fca97faa64b74b5"
# The runtime gate precedes the verified private helper. This digest also covers
# the public fallback, exact pointer comparison, value width and observer switch.
EMITTED_SHA256 = "6d2a9bab5ee6ca76d0761374937bd153fd002df916d19d00c27c0a1f8879b96a"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(path, expected):
    if digest(path) != expected:
        raise ValueError("Changed proof input: " + str(path))


def run(original, emitted, compcert, coq_bin, out):
    original, emitted, compcert, coq_bin, out = (
        path.resolve() for path in (original, emitted, compcert, coq_bin, out))
    out.mkdir(parents=True, exist_ok=False)
    projection = out / "projection"
    receipt = {"schema": 1, "passed": False, "commands": [], "theorems": [],
               "projection_receipt": "projection/result.json"}
    env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])

    def invoke(label, argv, cwd):
        row = {"label": label, "argv": list(map(str, argv)), "cwd": str(cwd)}
        receipt["commands"].append(row)
        stdout, stderr = out / (label + ".stdout"), out / (label + ".stderr")
        with stdout.open("wb") as so, stderr.open("wb") as se:
            row["exit_code"] = subprocess.run(row["argv"], cwd=cwd, env=env, stdout=so, stderr=se,
                                              timeout=900).returncode
        row.update(stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
        if row["exit_code"]:
            raise RuntimeError(f"{label} failed; see {stderr}")

    try:
        receipt["kernel_sources"] = {"Original": digest(original), "Emitted": digest(emitted)}
        require(emitted, EMITTED_SHA256)
        require(PROJECTOR, PROJECTOR_SHA256)
        source = HERE / "GenericRead.v"
        require(source, GENERIC_SHA256)
        invoke("projection", [sys.executable, "-B", PROJECTOR, "--original", original, "--emitted",
                              emitted, "--compcert", compcert, "--coq-bin", coq_bin, "--out", projection], out)
        prior = json.loads((projection / "result.json").read_text())
        if prior["passed"] is not True or prior["kernel_sources"] != receipt["kernel_sources"]:
            raise ValueError("Projection receipt does not bind both complete C sources")
        # Use the same logical CompCert and Bma400 load paths as the checked
        # projections. The new theorem imports the class rule and the emitted AST.
        args = next(row["argv"] for row in prior["commands"] if row["label"] == "ObjectClass")
        if args[:2] != [str(coq_bin / "coqc"), "-q"] or args[-1] != "ObjectClass.v":
            raise ValueError("Unexpected projector load path command")
        flags = args[2:-1]
        for name in ("coqc", "coqchk"):
            require(coq_bin / name, prior["tools"][name])
        (projection / "GenericRead.v").write_bytes(source.read_bytes())
        invoke("GenericRead", [coq_bin / "coqc", "-q", *flags, "GenericRead.v"], projection)
        invoke("coqchk", [coq_bin / "coqchk", "-silent", *flags, "Bma400.GenericRead"], projection)
        receipt.update(passed=True, generic_source_sha256=GENERIC_SHA256,
                       vo_sha256=digest(projection / "GenericRead.vo"),
                       assumptions_sha256=digest(out / "GenericRead.stdout"),
                       projection_receipt_sha256=digest(projection / "result.json"),
                       theorems=["EmittedBinding.emitted_cut", "PrivateGuard.actual_guard_false",
                                 "GenericRead.any_start_six"])
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("original", "emitted", "compcert", "coq-bin", "out"):
        parser.add_argument("--" + key, type=Path, required=True)
    opts = parser.parse_args()
    run(opts.original, opts.emitted, opts.compcert, opts.coq_bin, opts.out)

"""Generate and check the BMA400 six-byte regmap specialization in a new output directory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from bma400_entry import generate


REPO = Path(__file__).resolve().parents[2]
PROOFS = REPO / "proofs/bma400-noop"
RULE = REPO / "configs/optimization/bma400-six-byte.json"
RULE_SHA256 = "770342137eca7d96cb4be29925268424b7a397b9b784cf9750730f34e4cf5a05"
UNIT = "drivers/base/regmap/regmap.c"
FIXTURE = "kernel/c02-bulk-bench/kconc-c02-bulk.c"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        hasher = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
        return hasher.hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class OutsideContract(ValueError):
    """The original source can be returned for this input."""


def require_equal(actual, expected, label):
    if actual != expected:
        raise OutsideContract(label)


def checked_certificate(original, target, args, work):
    proof = work / "proof"
    cmd = [sys.executable, "-B", str(PROOFS / "check_scoped.py"), "--original", str(original),
           "--emitted", str(target), "--coq-bin", str(args.coq_bin.resolve()),
           "--compcert", str(args.compcert.resolve()), "--out", str(proof)]
    with (work / "proof.stdout").open("wb") as out, (work / "proof.stderr").open("wb") as err:
        rc = subprocess.run(cmd, stdout=out, stderr=err, timeout=1800).returncode
    save(work / "proof-command.json", {"argv": cmd, "exit_code": rc})
    if rc:
        raise OutsideContract("scoped proof check failed")
    report = json.loads((proof / "result.json").read_text(encoding="utf-8"))
    require_equal(report["passed"], True, "incomplete proof")
    require_equal(report["kernel_sources"], {"Original": file_hash(original), "Emitted": file_hash(target)},
                  "proof belongs to different C sources")
    names = {"Original", "Guarded", "Private", "BulkRead", "ClightBinding", "NativeNoop", "ScopedBinding"}
    for key, extension in (("inputs", ".v"), ("vo_sha256", ".vo")):
        require_equal(set(report[key]), names, "incomplete proof artifacts")
        for name, expected in report[key].items():
            require_equal(file_hash(proof / (name + extension)), expected, "proof artifact changed: " + name)
    require_equal(set(report["assumptions_sha256"]), {"BulkRead", "ClightBinding", "NativeNoop", "ScopedBinding"},
                  "missing assumptions output")
    for name, expected in report["assumptions_sha256"].items():
        require_equal(file_hash(proof / (name + ".stdout")), expected, "assumptions output changed: " + name)
    return {k: report[k] for k in ("kernel_sources", "certificate_sources", "extracted_sha256", "inputs",
                                    "vo_sha256", "assumptions_sha256", "environment", "runner_sha256")}


def prepare(args):
    root = args.output.resolve()
    tree = args.kernel_tree.resolve()
    if args.output.is_symlink() or any(root.is_relative_to(p) or p.is_relative_to(root)
           for p in (REPO, tree, args.compcert.resolve(), args.coq_bin.resolve())):
        raise ValueError("choose a new output directory outside the inputs and checkout")
    root.mkdir(parents=True, exist_ok=False)
    work = root / "work"
    work.mkdir()
    staging = root / ".pending"
    staging.mkdir()
    receipt = {"rule": "bma400-six-byte", "decision": "error", "kernel_install_allowed": False,
               "mode": args.mode, "inputs": {}, "outputs": {}}
    files = {}
    exit_code = 1
    try:
        for script in (Path(__file__), Path(__file__).with_name("bma400_entry.py")):
            (work / script.name).write_bytes(script.read_bytes())
        receipt["implementation_sha256"] = {p.name: file_hash(p) for p in work.glob("*.py")}
        raw = (tree / UNIT).read_bytes()
        original = work / "original.c"
        original.write_bytes(raw)
        receipt["inputs"][UNIT] = sha(raw)
        try:
            if args.mode != "qualified":
                raise OutsideContract("original entry requested: " + args.mode)
            rule_bytes = RULE.read_bytes()
            require_equal(sha(rule_bytes), RULE_SHA256, "rule declaration differs")
            rule = json.loads(rule_bytes)
            require_equal(receipt["inputs"][UNIT], rule["kernel_inputs"][UNIT], "original regmap.c differs")
            for path, expected in rule["kernel_inputs"].items():
                if path != UNIT:
                    receipt["inputs"][path] = file_hash(tree / path)
                    require_equal(receipt["inputs"][path], expected, "kernel input differs: " + path)
            fixture = (REPO / FIXTURE).read_bytes()
            receipt["inputs"][FIXTURE] = sha(fixture)
            require_equal(sha(fixture), rule["fixture_sha256"], "fixture differs")
            for name, path in (("config", args.config), ("clang", args.clang)):
                receipt["inputs"][name] = file_hash(path)
                require_equal(receipt["inputs"][name], rule[name + "_sha256"], name + " differs")
            reference = generate(raw, fixture, "original")
            optimized = generate(raw, fixture, "optimized")
            sources = {"reference": sha(reference), "optimized": sha(optimized)}
            require_equal(sources, rule["generated_sha256"], "generated entry differs from reviewed scope")
            target = work / "candidate.c"
            target.write_bytes(optimized)
            checked = checked_certificate(original, target, args, work)
            cert = {"schema": 1, "rule_sha256": sha(rule_bytes), "scope": rule["scope"], "inputs": receipt["inputs"],
                    "generator_sha256": file_hash(Path(__file__).with_name("bma400_entry.py")),
                    "emitted_sha256": sources, "proof": checked, "kernel_install_allowed": False}
            if args.expect_certificate:
                expected = json.loads(args.expect_certificate.read_text(encoding="utf-8"))
                require_equal(cert, expected, "certificate mismatch")
            save(work / "certificate.json", cert)
            files = {"reference": reference, "optimized": optimized}
            receipt["certificate_sha256"] = file_hash(work / "certificate.json")
            decision, exit_code = "scoped_source_verified", 0
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            files = {"original": raw}
            receipt["reason"] = str(error)
            decision, exit_code = ("original_fallback", 3) if args.mode == "qualified" else ("original_selected", 0)
        for name, content in files.items():
            relative = name + "/" + UNIT
            dest = staging / relative
            dest.parent.mkdir(parents=True)
            dest.write_bytes(content)
            require_equal(file_hash(dest), sha(content), "output write mismatch")
            receipt["outputs"][relative] = sha(content)
        if decision == "scoped_source_verified":
            (staging / "certificate.json").write_bytes((work / "certificate.json").read_bytes())
        staging.rename(root / "package")
        receipt["decision"] = decision
    except (ValueError, OSError) as error:
        receipt["reason"] = str(error)
        raise
    finally:
        save(root / "result.json", receipt)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Exit 0 writes the requested package, 3 writes only the original source after rejection, "
        "and 1 reports an error. A qualified package contains both source variants and certificate.json."))
    for name in ("kernel-tree", "config", "clang", "compcert", "coq-bin", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expect-certificate", type=Path, help="compare the new proof and source binding to a prior certificate")
    parser.add_argument("--mode", choices=("qualified", "original", "observe"), default="qualified")
    args = parser.parse_args()
    try:
        return prepare(args)
    except (ValueError, OSError, KeyError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

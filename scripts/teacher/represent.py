"""Reproduce one pre-registered sensor result into a fresh evidence directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
CASES = ("iio-kx", "iio-bma", "iio-three-kx", "iio-three-bma", "opt-ram", "quick-opt", "opt-proof")


def read(path):
    return json.loads(path.read_bytes())


def write(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(4 << 20), b""):
            digest.update(part)
    return digest.hexdigest()


def require(test, message):
    if not test:
        raise ValueError(message)


def command(out, name, argv, separate_stderr=False, **kwargs):
    args = list(map(str, argv))
    write(out / (name + ".command.json"), args)
    with (out / (name + ".log")).open("xb") as log:
        if separate_stderr:
            with (out / (name + ".stderr")).open("xb") as errors:
                rc = subprocess.run(args, stdout=log, stderr=errors, **kwargs).returncode
        else:
            rc = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, **kwargs).returncode
    write(out / (name + ".exit.json"), {"exit_code": rc})
    return rc


def iio(args, binding, result):
    require(binding["minimum"] == 19 and binding["planned"] == 20, "unexpected frozen window threshold")
    profile = read(args.bundle / "profile.json")
    package = args.output / "package"
    package.mkdir()
    profile["host_files"] = {}
    for name in ("kernel", "config", "vmlinux", "board", "disk"):
        path = args.disk if name == "disk" else args.bundle / name
        require(profile[name + "_sha256"] == (binding["disk_sha256"] if name == "disk" else binding["materials"][name]),
                f"{name} differs from the capture registration")
        stat = path.stat()
        profile["host_files"][name] = [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]
        profile[name] = str(path)
    shutil.copyfile(args.bundle / "initrd.gz", package / "initrd.gz")
    write(package / "package.json", profile)
    slots = [{"number": n, "status": "not_started"} for n in range(1, 21)]
    result.update(planned=20, minimum_matches=19, attempted=0, guest_boot_ids=[], complete_matches=0,
                  slots=slots, scope="native IIO readers and controlled software SPI transfer window")
    write(args.output / "plan.json", {"case":args.case, "slots":slots, "minimum":19,
          "files":binding["materials"], "package_sha256":sha(package / "package.json"),
          "disk_sha256":binding["disk_sha256"], "reference_kind":"archived passive discovery"})
    seen = set()
    for slot in slots:
        directory = args.output / f"boot-{slot['number']:02d}"
        slot["status"] = "started"
        result["attempted"] += 1
        write(args.output / "result.json", result)
        rc = command(args.output, directory.name, [sys.executable, "-B", SCRIPTS / "replay-iio-overlap.py",
                 "--package", package, "--reference", args.bundle / "axes.json", "--natural", args.bundle / "passive.json",
                 "--out", directory])
        receipt = directory / "result.json"
        verdict = read(receipt) if receipt.is_file() else {}
        boot = verdict.get("boot_id")
        if not boot and (directory / "capture/run.env").is_file():
            boot = dict(line.split("=", 1) for line in (directory / "capture/run.env").read_text().splitlines()).get("boot_id")
        passed = rc == 0 and verdict.get("passed") is True and bool(boot) and boot not in seen
        slot.update(status="matched" if passed else "failed", boot_id=boot, exit_code=rc,
                    evidence=directory.name, diagnostic=verdict.get("diagnostic"))
        if boot:
            seen.add(boot)
            result["guest_boot_ids"].append(boot)
        result["complete_matches"] += passed
        write(args.output / "result.json", result)
    result["passed"] = result["complete_matches"] >= 19
    result["distinct_verified_guest_boots"] = len(seen)


def proof(args, result):
    from proof_tools import prepared
    dest = args.output / "generated"
    with prepared(args.proof_runtime) as (clang, compcert, coq, env):
        rc = command(args.output, "coq-certificate", [sys.executable,"-B",SCRIPTS / "optimization/bma400.py",
                     "--kernel-tree", args.bundle / "tree", "--config",args.bundle / "config","--clang",clang,
                     "--compcert",compcert,"--coq-bin",coq,"--expect-certificate",args.bundle / "certificate.json",
                     "--output",dest], env=env)
    actual = dest / "package/certificate.json"
    receipt = read(dest / "result.json")
    result.update(planned=1, attempted=1, decision=receipt.get("decision"), exit_code=rc, evidence="generated")
    require(rc == 0 and receipt.get("decision") == "scoped_source_verified" and actual.is_file()
            and sha(actual) == sha(args.bundle / "certificate.json"), "证书生成未通过，请查看 coq-certificate.log 和 generated/result.json")
    result.update(passed=True, certificate_sha256=sha(actual))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("case", choices=CASES)
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--disk", type=Path)
    p.add_argument("--proof-runtime", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.bundle, a.output = a.bundle.resolve(), a.output.resolve()
    if a.disk:
        a.disk = a.disk.resolve()
    if a.output == a.bundle or a.bundle in a.output.parents:
        p.error("output must be outside the material bundle")
    a.output.mkdir(parents=True, exist_ok=False)
    result = {"case":a.case, "origin":"local_execution", "passed":False, "attempted":0}
    if a.case.startswith("iio"):
        result.update(planned=20, minimum_matches=19, complete_matches=0)
    elif a.case in ("opt-ram","quick-opt"):
        result.update(planned_formal=18 if a.case=="opt-ram" else 0, planned_functional=3,
                      planned_pairs=24 if a.case=="opt-ram" else 0, actual_pairs=0)
    else:
        result["planned"]=1
    try:
        binding = read(a.bundle / "case.json")
        require(binding["id"] == ("opt-ram" if a.case=="quick-opt" else a.case), "selected bundle belongs to another case")
        for name, expected in binding["materials"].items():
            f = (a.bundle / name).resolve(strict=True)
            require(a.bundle in f.parents and sha(f) == expected, f"material mismatch: {name}")
        if a.case != "opt-proof":
            require(a.disk and a.disk.is_file() and sha(a.disk) == binding["disk_sha256"], "disk contents do not match this case")
            require(sys.platform.startswith("linux") and os.access("/dev/kvm",os.R_OK | os.W_OK), "requires x86_64 Linux with KVM")
        if a.case.startswith("iio"):
            iio(a, binding, result)
        elif a.case in ("opt-ram","quick-opt"):
            from ram_timing import measure
            measure(a, binding, result)
        else:
            proof(a, result)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result.update(passed=False, diagnostic=str(exc))
    write(a.output / "result.json",result)
    print(json.dumps({k:v for k,v in result.items() if k not in ("slots","guest_boot_ids","statistics")}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

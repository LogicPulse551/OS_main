"""Cold-boot complete regmap operations and compare their intermediate worker events."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import check

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "iio-path"))
from capture import save, sha


def read(path):
    return json.loads(path.read_bytes())


def signature(observation):
    # TIDs are checked within each boot and need not retain their numbers across boots.
    return [[step[k] for k in ("step", "planned", "role", "visit", "before", "after")]
            for step in observation["steps"]]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def boot(dest, case, package_path, frozen, boots, reference=None):
    dest.mkdir()
    record = dict(case=case, started=False, passed=False)
    try:
        require(sha(package_path) == frozen["package"], "package registration changed")
        pkg = read(package_path)
        ramdisk = package_path.parent / "initrd.gz"
        require(sha(ramdisk) == pkg["initrd_sha256"] and sha(pkg["kernel"]) == pkg["kernel_sha256"],
                "boot image changed")
        require(sha(HERE / "check.py") == pkg["checker_sha256"] == frozen["checker"], "checker changed")
        ref = None
        if reference:
            require(sha(reference) == frozen[case + "_reference"], "frozen reference changed")
            ref = read(reference)
        serial = dest / "serial.log"
        argv = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-smp", "4", "-m", "3072",
                "-no-reboot", "-nodefaults", "-display", "none", "-monitor", "none", "-serial",
                "file:" + str(serial), "-kernel", pkg["kernel"], "-initrd", str(ramdisk),
                "-append", "console=ttyS0 panic=-1 loglevel=3 central.case=" + case,
                "-drive", "file=" + pkg["disk"].replace(",", ",,") + ",format=qcow2,if=virtio,readonly=on"]
        save(dest / "launch.json", dict(argv=argv, case=case, package=frozen["package"],
                                        reference=frozen.get(case + "_reference")))
        with (dest / "qemu.log").open("xb") as log:
            with subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT) as proc:
                record["started"] = True
                try:
                    record["qemu_exit"] = proc.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise
        observed = check.parse(serial, case)
        record["observed"] = observed
        raw = serial.read_text(errors="replace").replace("\r", "")
        record["boot_id_source"] = check.one(r"^BOOT_ID_SOURCE (guest_random|kernel)$", raw)
        require(check.one(r"^GUEST_RELEASE (.+)$", raw) == pkg["release"], "wrong boot release")
        require(record["qemu_exit"] == 0 and observed["integrity"], observed.get("diagnostic") or "guest failed")
        for field in ("kernel_id", "module_id", "module_sha256"):
            require(observed[field] == pkg[field], "guest identity changed: " + field)
        require(observed["boot"] not in boots, "duplicate boot identifier")
        boots.add(observed["boot"])
        expected = "ABAC" if case == "WRONG" else case
        require(observed["actual"] == expected and observed["matched"] == (case != "WRONG"),
                "unexpected intermediate route")
        if case == "ABCA":
            require("C" in observed["A_resume"]["fully_enclosed_peer_visits"],
                    "C's accesses outside original A's sleeping interval")
        if ref:
            require(ref["passed"] and ref["case"] == case and
                    ref["observed"]["boot"] != observed["boot"] and
                    signature(ref["observed"]) == signature(observed), "cold reference mismatch")
        record["passed"] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
    save(dest / "result.json", record)
    print(dest.name, "passed" if record["passed"] else record["error"], flush=True)
    return record["passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true", help="one cold confirmation per positive reference")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True)
    package_path = args.package.resolve() / "package.json"
    pkg = read(package_path)
    count, minimum = (1, 1) if args.smoke else (20, 19)
    frozen = dict(package=sha(package_path), checker=sha(HERE / "check.py"), runner=sha(__file__),
                  confirmations=count, minimum=minimum, reference_routes=["ABA", "ABCA"],
                  same_final_control="ABAC versus ABCA", disk=sha(pkg["disk"]))
    save(out / "plan.json", frozen)
    require(frozen["disk"] == pkg["disk_sha256"], "read-only disk differs from package")
    boots, groups = set(), {}
    for case in ("ABA", "ABCA", "WRONG"):
        ref_dir = out / (case + "-reference")
        passed = boot(ref_dir, case, package_path, frozen, boots)
        confirmations = []
        if passed and case != "WRONG":
            ref = ref_dir / "result.json"
            frozen[case + "_reference"] = sha(ref)
            save(out / (case + "-frozen.json"), {"sha256": frozen[case + "_reference"]})
            for i in range(1, count + 1):
                confirmations.append(boot(out / f"{case}-confirm-{i:02}", case, package_path, frozen, boots, ref))
        groups[case] = dict(reference=passed, planned_confirmations=0 if case == "WRONG" else count,
                            confirmations=confirmations)
    disk_after = sha(pkg["disk"])
    passed = (disk_after == frozen["disk"] and all(g["reference"] for g in groups.values()) and
              all(sum(groups[c]["confirmations"]) >= minimum for c in ("ABA", "ABCA")))
    save(out / "summary.json", dict(groups=groups, passed=passed, mode="smoke" if args.smoke else "formal",
                                    distinct_verified_boots=len(boots), disk_after=disk_after))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

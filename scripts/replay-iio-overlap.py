"""Run registered IIO reads on a software SPI board, or check a saved capture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


SCRIPTS = Path(__file__).resolve().parent
CAPTURE = SCRIPTS / "iio-path/capture.py"
REVIEW = SCRIPTS / "iio-path-overlap/checks/active.py"


def read(path):
    return json.loads(path.read_bytes())


def write(path, obj):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(out, name, argv):
    argv = list(map(str, argv))
    write(out / (name + ".command.json"), argv)
    with (out / (name + ".log")).open("xb") as log:
        rc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT).returncode
    write(out / (name + ".exit.json"), {"code": rc})
    return rc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="registered capture package directory")
    parser.add_argument("--reference", required=True, type=Path, help="frozen axis discovery JSON")
    parser.add_argument("--natural", required=True, type=Path, help="verified passive SPI reference JSON")
    parser.add_argument("--out", required=True, type=Path, help="new directory for all receipts")
    parser.add_argument("--check-only", type=Path, metavar="SAVED_SLOT",
                        help="read a saved capture directory or its enclosing slot; skip guest launch")
    args = parser.parse_args()
    package = args.package.resolve()
    package_file = package / "package.json"
    reference = args.reference.resolve()
    natural = args.natural.resolve()
    out = args.out.resolve()
    inputs = [package, reference, natural]
    if args.check_only:
        saved = args.check_only.resolve()
        capture = saved / "capture" if (saved / "capture").is_dir() else saved
        if not (capture / "build.json").is_file():
            parser.error("saved slot must contain capture/build.json or build.json")
        inputs.append(saved)
    else:
        capture = out / "capture"
    if any(out == f or f in out.parents for f in inputs):
        parser.error("output must be separate from the inputs")
    try:
        out.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(f"new output directory required: {exc}")

    result = {"passed": False, "operation": "verify" if args.check_only else "replay"}
    try:
        pkg = read(package_file)
        registered = read(reference)
        natural_ref = read(natural)
        triple = "triple" in pkg
        if triple:
            plan = pkg["triple"]
            order = "X{Y,Z}"
            review = REVIEW.with_name("three.py")
            hits = [row["pair"] for row in natural_ref["pairs"] if row["strict_window"]]
            if ("pair" in pkg or plan["axis_owner"] != "X" or plan["peer_axes"] != ["Y", "Z"]
                    or not hits or hits[0] != natural_ref["first_match"]
                    or natural_ref["reference_sha256"] != digest(reference)
                    or natural_ref["board_build_id"] != registered["identity"]["board_build_id"]
                    or natural_ref["kernel_build_id"] != pkg["kernel_build_id"]
                    or natural_ref["active_attempts"] != 0 or not natural_ref["passed"]):
                raise ValueError("three-reader plan differs from the observed X window")
            mode_args = ["active"]
            selector = ["--pair", hits[0]]
        else:
            plan = pkg["pair"]
            order = plan["axis_order"]
            review = REVIEW
            mode_args = []
            selector = ["--order", order]
            if order not in ("XY", "YX") or natural_ref["order"] != order or natural_ref["strict_matches"] != 1:
                raise ValueError("package and unique natural reference must identify the same axis order")
        if not plan["initrd_plan"] or plan["guest_mode"] != "natural" or natural_ref["phase"] != "passive":
            raise ValueError("missing registered software-board plan or passive reference")
        if digest(reference) != pkg["observation"]["registry_sha256"] or any(
                registered["identity"][k] != pkg[k] for k in
                ("kernel_sha256", "kernel_build_id", "config_sha256", "vmlinux_sha256")):
            raise ValueError("package and axis discovery reference have different identities")
        result["order"] = order
        write(out / "plan.json", {"operation": result["operation"], "order": order, "capture": str(capture),
                                  "files": {str(f): digest(f) for f in
                                            (package_file, reference, natural, CAPTURE,
                                             review, review.with_name("inspect_overlap.py"))}})
        if not args.check_only:
            rc = command(out, "launch", [sys.executable, "-B", CAPTURE, "boot", package,
                                          plan["guest_mode"], capture])
            if rc:
                raise ValueError(f"capture exited {rc}; see launch.log")
        verify = [sys.executable, "-B", review, *mode_args, "--capture", capture, "--package", package_file,
                  "--natural", natural, "--reference", reference, *selector]
        if command(out, "verify", [*verify, "--out", out / "verdict.json"]):
            raise ValueError("path verification failed; see verdict.json and verify.log")
        if triple:
            write(out / "negative.json", read(out / "verdict.json")["negative"])
        elif command(out, "negative", [*verify, "--negative", "--out", out / "negative.json"]):
            raise ValueError("offline rejection checks failed; see negative.json and negative.log")
        result.update(passed=True, boot_id=read(out / "verdict.json")["boot_id"])
    except (OSError, KeyError, TypeError, ValueError) as exc:
        result["diagnostic"] = str(exc)
    write(out / "result.json", result)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

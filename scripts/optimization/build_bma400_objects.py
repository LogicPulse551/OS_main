"""Recheck the scoped BMA400 certificate and compile its two Linux regmap objects."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from bma400 import REPO, RULE, RULE_SHA256, UNIT, OutsideContract, file_hash, prepare, require_equal, save, sha


ARCHIVE_SHA256 = "cdcf5373ee4a0c43c11ea3a1053d54534a8048f16057614f954f542f58990709"
OBJECT = Path(UNIT).with_suffix(".o")


def run_logged(folder, argv, env):
    folder.mkdir(parents=True, exist_ok=False)
    command = [str(x) for x in argv]
    save(folder / "command.json", {"argv": command})
    with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
        rc = subprocess.run(command, stdout=out, stderr=err, env=env).returncode
    save(folder / "exit.json", {"returncode": rc})
    if rc:
        raise RuntimeError(f"{folder.name} exited {rc}; see {folder / 'stderr'}")


def check_compilation(obj, compiler, source, log):
    cmdfile = obj.with_name("." + obj.name + ".cmd")
    with cmdfile.open(encoding="utf8") as f:
        prefix, separator, command = f.readline().partition(" := ")
    require_equal((prefix, separator), (f"savedcmd_{OBJECT.as_posix()}", " := "), "unexpected Kbuild record")
    argv = shlex.split(command)
    require_equal(argv[0], str(compiler), "object compiler differs")
    require_equal([opt for opt in argv if opt.startswith("-O")], ["-O2"], "not normal -O2")
    require_equal(argv[-4:], ["-c", "-o", OBJECT.as_posix(), str(source)], "source or output differs")
    with log.open(encoding="utf8") as f:
        require_equal(sum(line.strip() == command.strip() for line in f), 1, "fresh compile not observed")
    with obj.open("rb") as f:
        header = f.read(20)
    require_equal((header[:6], header[16:20]), (b"\x7fELF\x02\x01", b"\x01\x00\x3e\x00"), "not x86-64 ELF relocatable")
    return cmdfile


def build(args):
    out = args.output.resolve()
    archive = args.archive.resolve()
    config = args.config.resolve()
    llvm = args.llvm_bin.resolve()
    compiler = llvm / "clang"
    protected = [REPO, llvm, args.compcert.resolve(), args.coq_bin.resolve(), archive, config]
    if args.expect_certificate:
        protected.append(args.expect_certificate.resolve())
    if args.output.is_symlink() or any(out.is_relative_to(p) or p.is_relative_to(out) for p in protected):
        raise ValueError("choose a new Linux build directory outside the checkout and inputs")
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"decision": "error", "kernel_install_allowed": False, "objects": {}}
    try:
        rule_bytes = RULE.read_bytes()
        require_equal(sha(rule_bytes), RULE_SHA256, "rule declaration differs")
        rule = json.loads(rule_bytes)
        require_equal(file_hash(config), rule["config_sha256"], "config differs")
        require_equal(file_hash(compiler), rule["clang_sha256"], "compiler differs")
        archive_copy = out / "source.tar"
        shutil.copyfile(archive, archive_copy)
        archive_hash = file_hash(archive_copy)
        require_equal(archive_hash, ARCHIVE_SHA256, "archive differs")
        receipt["archive_sha256"] = archive_hash
        env = {"PATH": os.defpath, "HOME": str(out), "LC_ALL": "C"}
        inputs = out / "proof-inputs"
        inputs.mkdir()
        run_logged(out/"logs"/"extract-inputs", ["tar","-xf",archive_copy,"-C",inputs,"--",*rule["kernel_inputs"]], env)
        proof = out / "verified-source"
        rc = prepare(argparse.Namespace(kernel_tree=inputs, config=config, clang=compiler, compcert=args.compcert,
                     coq_bin=args.coq_bin, output=proof, expect_certificate=args.expect_certificate, mode="qualified"))
        source_receipt = json.loads((proof/"result.json").read_text(encoding="utf8"))
        receipt["source_decision"] = source_receipt["decision"]
        if rc or source_receipt["decision"] != "scoped_source_verified":
            raise OutsideContract(source_receipt.get("reason", "source certificate required"))
        package = proof / "package"
        certificate = package / "certificate.json"
        cert_hash = file_hash(certificate)
        require_equal(cert_hash, source_receipt["certificate_sha256"], "certificate file changed")
        cert = json.loads(certificate.read_text(encoding="utf8"))
        receipt.update(certificate_sha256=cert_hash, source_receipt_sha256=file_hash(proof/"result.json"),
                       kernel_revision=rule["kernel_revision"], llvm_revision=rule["llvm_revision"])
        tree = out / "linux"
        tree.mkdir()
        run_logged(out/"logs"/"extract-kernel", ["tar","-xf",archive_copy,"-C",tree], env)
        unit = tree / UNIT
        require_equal(unit.resolve(), unit, "unexpected source path")
        require_equal(unit.stat().st_nlink, 1, "expected private source file")
        require_equal(file_hash(unit), rule["kernel_inputs"][UNIT], "archived source differs")
        results = {}
        for label in ("reference", "optimized"):
            src_hash = cert["emitted_sha256"][label]
            input_file = package / label / UNIT
            require_equal(file_hash(input_file), src_hash, "packaged source changed")
            dest = out / label
            dest.mkdir()
            shutil.copyfile(config, dest / ".config")
            shutil.copyfile(input_file, unit)
            kbuild = ["make", "-C", tree, f"O={dest}", "ARCH=x86_64", f"LLVM={llvm}/",
                      "HOSTCC=gcc", "HOSTCXX=g++", "KCFLAGS=", "KCPPFLAGS=", "V=1"]
            run_logged(out/"logs"/(label+"-config"), [*kbuild, "olddefconfig"], env)
            require_equal(file_hash(dest/".config"), cert["inputs"]["config"], "normalized config differs")
            obj = dest / OBJECT
            if obj.exists():
                raise ValueError("unexpected preexisting object")
            log = out/"logs"/(label+"-compile")
            run_logged(log, [*kbuild, "-j4", OBJECT.as_posix()], env)
            cmd = check_compilation(obj, compiler, unit, log/"stdout")
            require_equal(file_hash(unit), src_hash, "compiled source changed")
            require_equal(file_hash(dest/".config"), cert["inputs"]["config"], "compiled config changed")
            require_equal(file_hash(compiler), cert["inputs"]["clang"], "compiler changed")
            results[label] = {"source_sha256":src_hash, "config_sha256":file_hash(dest/".config"),
                              "compiler_sha256":file_hash(compiler), "path":obj.relative_to(out).as_posix(),
                              "object_sha256":file_hash(obj), "saved_command_sha256":file_hash(cmd),
                              "compile_log_sha256":file_hash(log/"stdout")}
        require_equal(file_hash(certificate), cert_hash, "certificate changed during build")
        require_equal(len({r["object_sha256"] for r in results.values()}), 2, "object variants coincide")
        receipt.update(decision="objects_verified", objects=results)
        return 0
    except OutsideContract as error:
        receipt.update(decision="rejected", reason=str(error))
        return 3
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        receipt["reason"] = str(error)
        return 1
    finally:
        save(out / "result.json", receipt)
        print(receipt["decision"], out / "result.json", file=sys.stderr)


def verify(manifest, expected_digest):
    """Recheck a built pair against the separately retained digest of its successful receipt."""
    require_equal(file_hash(manifest), expected_digest.lower(), "untrusted object binding")
    receipt = json.loads(manifest.read_text(encoding="utf8"))
    require_equal(receipt["decision"], "objects_verified", "incomplete object build")
    require_equal(set(receipt["objects"]), {"reference", "optimized"}, "missing variant")
    root = manifest.parent
    sources = root / "verified-source"
    require_equal(file_hash(sources/"result.json"), receipt["source_receipt_sha256"], "source receipt differs")
    certfile = sources/"package/certificate.json"
    require_equal(file_hash(certfile), receipt["certificate_sha256"], "certificate differs")
    cert = json.loads(certfile.read_text(encoding="utf8"))
    for label, bound in receipt["objects"].items():
        obj = root/label/OBJECT
        require_equal(bound["path"], obj.relative_to(root).as_posix(), "unexpected object name")
        require_equal(file_hash(obj), bound["object_sha256"], f"{label} object differs")
        require_equal(file_hash(obj.with_name("." + obj.name + ".cmd")), bound["saved_command_sha256"], "compile command differs")
        require_equal(file_hash(root/"logs"/(label+"-compile")/"stdout"), bound["compile_log_sha256"], "compile log differs")
        require_equal(file_hash(root/label/".config"), bound["config_sha256"], "object config differs")
        require_equal(bound["config_sha256"], cert["inputs"]["config"], "certificate config differs")
        require_equal(bound["compiler_sha256"], cert["inputs"]["clang"], "certificate compiler differs")
        require_equal(file_hash(sources/"package"/label/UNIT), bound["source_sha256"], "generated source differs")
        require_equal(bound["source_sha256"], cert["emitted_sha256"][label], "certificate source differs")
    print("objects_verified", manifest)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    names = ("archive", "config", "llvm-bin", "compcert", "coq-bin", "output")
    for name in names:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--expect-certificate", type=Path)
    parser.add_argument("--verify", type=Path, metavar="MANIFEST", help="recheck retained objects without writing files")
    parser.add_argument("--expected-binding-sha256", help="trusted SHA-256 of the successful build result.json")
    args = parser.parse_args()
    provided = [getattr(args, name.replace("-", "_")) is not None for name in names]
    try:
        if args.verify:
            if not args.expected_binding_sha256 or any(provided) or args.expect_certificate:
                parser.error("--verify requires --expected-binding-sha256 and no build arguments")
            return verify(args.verify, args.expected_binding_sha256)
        if not all(provided) or args.expected_binding_sha256:
            parser.error("building requires " + ", ".join("--" + name for name in names))
        return build(args)
    except OutsideContract as error:
        print(error, file=sys.stderr)
        return 3
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

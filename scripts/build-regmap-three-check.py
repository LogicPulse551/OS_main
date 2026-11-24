"""Package fixed three-worker regmap fixtures for the selected local kernel builds."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts/iio-path"))
from capture import archive, elf_id, sha


def require(condition, message):
    if not condition:
        raise ValueError(message)


def logged(command, destination):
    with destination.open("xb") as stream:
        stream.write((repr([str(a) for a in command]) + "\n").encode())
        stream.flush()
        subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT)


def build(profile, name, config, clang, flags, output):
    output.mkdir()
    fixtures = REPO/"kernel/regmap-three-check"
    native = config["artifacts"]
    for key in ("vmlinux", ".config", "bzImage", "System.map"):
        file = native[key]
        require(sha(file["path"]) == file["sha256"], f"selected {key} differs from receipt")
    flavors = ("normal", "fault" if name.endswith("-base") else "fixed")
    cases = [(name.split("-")[0], v, o) for v in flavors for o in ("ABC", "ACB")]
    packages = {}
    files = {"init": Path(profile["init"]), "payload/observe.sh": fixtures/"observe.sh"}
    with tempfile.TemporaryDirectory(prefix="ram-regmap-") as tmp:
        objects = Path(tmp)/"objects"
        objects.mkdir()
        shutil.copyfile(native[".config"]["path"], objects/".config")
        make = ["make", "-C", config["source"], "O="+str(objects), "ARCH=x86_64",
                "LLVM="+str(clang.parent)+"/", "KCFLAGS="+flags, "-j4"]
        logged([*make,"olddefconfig"], output/"config.log")
        logged([*make,"modules_prepare"], output/"prepare.log")
        require(sha(objects/".config")==native[".config"]["sha256"], "configuration changed during prepare")
        require((objects/"include/config/kernel.release").read_text().strip()==config["release"], "release differs")
        exports = Path(config["build"])/"vmlinux.symvers"
        shutil.copyfile(exports, objects/"Module.symvers")
        for v in flavors:
            staged = Path(tmp)/v
            staged.mkdir()
            for file in ("Makefile","regmap_three_check.c"):
                shutil.copyfile(fixtures/file, staged/file)
            logged([*make, "M="+str(staged), "FIXTURE_VARIANT="+v, "modules"], output/(v+".log"))
            ko = output/(v+".ko")
            shutil.copyfile(staged/"regmap_three_check.ko", ko)
            shutil.copyfile(staged/".regmap_three_check.o.cmd", output/(v+".command"))
            info = subprocess.check_output(["readelf","-p",".modinfo",ko],text=True)
            require("tri_variant="+v in info and "vermagic="+config["release"] in info,"module labels differ")
            packages[v] = dict(sha256=sha(ko),elf_id=elf_id(ko))
            files["payload/"+v+".ko"] = ko
    require(len({m["elf_id"] for m in packages.values()})==len(flavors),"variants are indistinguishable")
    (output/"cases.tsv").write_text("".join(" ".join(c)+"\n" for c in cases))
    files["payload/cases.tsv"]=output/"cases.tsv"
    archive(output/"initrd.gz",files)
    receipt = dict(profile=name,kernel_id=elf_id(native["vmlinux"]["path"]),kernel=native["bzImage"],
                   config=native[".config"],release=config["release"],modules=packages,source_sha256=sha(fixtures/"regmap_three_check.c"),
                   observer_sha256=sha(fixtures/"observe.sh"),cases=cases,exports_sha256=sha(exports),
                   initrd_sha256=sha(output/"initrd.gz"),compiler_sha256=sha(clang))
    (output/"package.json").write_text(json.dumps(receipt,indent=2)+"\n")


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profiles",type=Path)
    ap.add_argument("destination",type=Path)
    ap.add_argument("--clang",type=Path,required=True)
    ap.add_argument("--clang-sha256",required=True)
    ap.add_argument("--kcflags",default="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false")
    args=ap.parse_args()
    profile=json.loads(args.profiles.read_bytes())
    require(set(profile["profiles"])=={"update-base","mutex-base","update-fix","mutex-fix"},"missing required kernel profile")
    require(not args.destination.resolve().is_relative_to(REPO),"choose an output directory outside the source tree")
    require(sha(args.clang)==args.clang_sha256 and sha(profile["init"])==profile["init_sha256"] and
            sha(profile["disk"])==profile["disk_sha256"], "compiler, guest supervisor or guest disk differs")
    args.destination.mkdir(parents=True)
    for name, config in profile["profiles"].items():
        build(profile,name,config,args.clang,args.kcflags,args.destination/name)


if __name__ == "__main__":
    main()

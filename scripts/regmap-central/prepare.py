"""Build a private RAM regmap module and bind its boot package to an Ubuntu Kbuild."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
MODULE = HERE.parents[1] / "kernel/regmap-central"
sys.path.insert(0, str(HERE.parent / "iio-path"))
from capture import archive, elf_id, save, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-build", type=Path, required=True, help="prepared Ubuntu kernel object tree")
    parser.add_argument("--disk", type=Path, required=True, help="read-only openEuler qcow2 with ext4 on /dev/vda2")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    kernel = args.kernel_build.resolve(strict=True)
    disk = args.disk.resolve(strict=True)
    release = (kernel / "include/config/kernel.release").read_text().strip()
    if release != "6.8.1-kconc-ubuntu":
        parser.error(f"expected the registered Ubuntu test kernel; found {release!r}")
    image = kernel / "arch/x86/boot/bzImage"
    vmlinux = kernel / "vmlinux"
    out = args.output.resolve()
    out.mkdir(parents=True)
    module = out / "regmap_central.ko"
    with tempfile.TemporaryDirectory(prefix="regmap-central-") as tmp:
        for name in ("Makefile", "regmap_central.c"):
            shutil.copyfile(MODULE / name, Path(tmp) / name)
        with (out / "build.log").open("x") as log:
            subprocess.run(["make", "-C", kernel, "M=" + tmp, "modules"], stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        shutil.copyfile(Path(tmp) / module.name, module)
    mod_release = subprocess.check_output(["modinfo", "-F", "vermagic", module], text=True).split()[0]
    if mod_release != release:
        raise ValueError(f"module vermagic {mod_release!r} differs from {release!r}")
    init = out / "init"
    subprocess.run(["gcc", "-static", "-Wall", "-Wextra", "-Werror", "-O2",
                    HERE.parent / "iio-path/init.c", "-o", init], check=True)
    ramdisk = out / "initrd.gz"
    archive(ramdisk, {"init": init, "payload/observe.sh": HERE / "observe.sh",
                      "payload/regmap_central.ko": module})
    save(out / "package.json", dict(release=release, kernel=str(image), kernel_sha256=sha(image),
        kernel_id=elf_id(vmlinux), vmlinux_sha256=sha(vmlinux), config_sha256=sha(kernel / ".config"),
        disk=str(disk), disk_sha256=sha(disk), module_id=elf_id(module), module_sha256=sha(module),
        initrd_sha256=sha(ramdisk), init_sha256=sha(init), observer_sha256=sha(HERE / "observe.sh"),
        checker_sha256=sha(HERE / "check.py"), module_source_sha256=sha(MODULE / "regmap_central.c")))


if __name__ == "__main__":
    main()

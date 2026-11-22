"""Package or cold-boot an offline IIO reader with a separate evidence disk."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def run(args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          check=True, text=True).stdout


def elf_id(path):
    text = run(["readelf", "-n", path])
    return re.search(r"Build ID: (\w+)", text)[1]


def guest_id(path):
    notes = path.read_bytes()
    pos = 0
    while len(notes) - pos >= 12:
        size, desc, kind = struct.unpack_from("<III", notes, pos)
        pos += 12
        name = notes[pos:pos + size]
        pos += (size + 3) & ~3
        value = notes[pos:pos + desc]
        pos += (desc + 3) & ~3
        if name == b"GNU\0" and kind == 3 and len(value) == 20:
            return value.hex()
    raise ValueError(f"missing GNU build ID in {path}")


def archive(path, files):
    entries = [(d, 0o040755, b"") for d in ("dev", "sysroot", "payload")]
    entries.extend((name, 0o100755, f.read_bytes()) for name, f in files.items())
    blob = bytearray()
    for inode, (name, mode, data) in enumerate([*entries, ("TRAILER!!!", 0, b"")], 1):
        name = name.encode() + b"\0"
        fields = (inode, mode, 0, 0, 2 if mode == 0o040755 else 1, 0, len(data),
                  0, 0, 0, 0, len(name), 0)
        blob.extend(b"070701" + "".join(f"{n:08x}" for n in fields).encode() + name)
        blob.extend(b"\0" * (-len(blob) % 4))
        blob.extend(data)
        blob.extend(b"\0" * (-len(blob) % 4))
    path.write_bytes(gzip.compress(blob, mtime=0))


def fingerprint(path):
    st = Path(path).stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]


def register(build, board, init, disk, destination):
    paths = {
        "kernel": build / "arch/x86/boot/bzImage", "config": build / ".config",
        "vmlinux": build / "vmlinux", "board": board, "init": init, "disk": disk,
    }
    profile = {}
    for name, path in paths.items():
        path = path.resolve(strict=True)
        profile[name] = str(path)
        profile[name + "_sha256"] = sha(path)
    with destination.open("x", encoding="utf-8") as out:
        json.dump(profile, out, ensure_ascii=False, indent=2)
        out.write("\n")


def prepare(profile, dest):
    dest.mkdir(parents=True)
    p = json.loads(profile.read_text())
    s = Path(__file__).resolve().parent
    for key in ("kernel", "config", "board", "init", "disk"):
        if sha(p[key]) != p[key + "_sha256"]:
            raise ValueError(f"unregistered {key} content")
    vmlinux_hash = sha(p["vmlinux"])
    if "vmlinux_sha256" in p and vmlinux_hash != p["vmlinux_sha256"]:
        raise ValueError("unregistered vmlinux content")
    if "CONFIG_KCOV_MEMORY=y" not in Path(p["config"]).read_text().splitlines():
        raise ValueError("selected kernel lacks registered coverage format")
    recipe = ["gcc", "-static", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
              "-pthread", str(s / "read_axes.c"), "-o", str(dest / "read-axes")]
    (dest / "gcc.log").write_text(run(recipe))
    files = {"init": Path(p["init"]), "payload/board.ko": Path(p["board"]),
             "payload/read-axes": dest / "read-axes", "payload/observe.sh": s / "observe.sh"}
    archive(dest / "initrd.gz", files)
    p.update(kernel_build_id=elf_id(p["vmlinux"]), board_build_id=elf_id(p["board"]),
             vmlinux_sha256=vmlinux_hash, initrd_sha256=sha(dest / "initrd.gz"),
             argv_build=recipe, actor_source_sha256=sha(s / "read_axes.c"),
             host_code_sha256=sha(__file__), guest={name: sha(f) for name, f in files.items()})
    p["host_files"] = {key: fingerprint(p[key]) for key in ("kernel", "config", "disk", "vmlinux", "board")}
    save(dest / "package.json", p)


def boot(package, mode, slot):
    slot.mkdir(parents=True)
    p = json.loads((package / "package.json").read_text())
    for key, original in p["host_files"].items():
        if fingerprint(p[key]) != original:
            raise ValueError(f"recheck registered file after metadata change: {key}")
    initrd = package / "initrd.gz"
    if sha(initrd) != p["initrd_sha256"] or sha(p["kernel"]) != p["kernel_sha256"]:
        raise ValueError("selected executable input changed")
    evidence = slot / "evidence.ext4"
    with evidence.open("xb") as img:
        img.truncate(24 << 20)
    run(["/usr/sbin/mkfs.ext4", "-q", "-F", evidence])
    argv = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
            "-no-reboot", "-nodefaults", "-display", "none", "-monitor", "none", "-serial",
            "file:" + str(slot / "serial.log"), "-kernel", p["kernel"], "-initrd", str(initrd),
            "-append", f"console=ttyS0 panic=-1 loglevel=4 iio.mode={mode}",
            "-drive", "file=" + p["disk"] + ",format=qcow2,if=virtio,readonly=on",
            "-drive", "file=" + str(evidence) + ",format=raw,if=virtio"]
    save(slot / "plan.json", {"mode": mode, "argv": argv, "package_sha256": sha(package / "package.json")})
    with (slot / "qemu.log").open("wb") as log:
        rc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode
    log = (slot / "serial.log").read_text(errors="replace").replace("\r", "")
    capture = re.search(r"^CAPTURE ([a-f0-9]{64})  capture.sha256$", log, re.M)
    # Archived capture packages used the original supervisor's completion marker.
    if rc or not capture or not re.search(r"^(?:IIO|K14)_SUPERVISOR_EXIT 0$", log, re.M):
        raise ValueError(f"guest failed, see {slot}/serial.log")
    # Only simple local names from the verified guest manifest are extracted.
    def extract(name):
        result = subprocess.run(["/usr/sbin/debugfs", "-R", f"dump /{name} {name}",
                                 evidence], cwd=slot, check=True, capture_output=True)
        with (slot / "debugfs.log").open("ab") as report:
            report.write(result.stdout + result.stderr)
    extract("capture.sha256")
    if sha(slot / "capture.sha256") != capture[1]:
        raise ValueError("transport digest mismatch")
    for line in (slot / "capture.sha256").read_text().splitlines():
        digest, name = line.split()
        if not re.fullmatch(r"[a-z][a-z0-9.-]{0,40}", name) or (slot / name).exists():
            raise ValueError("unexpected evidence file")
        extract(name)
        if sha(slot / name) != digest:
            raise ValueError(f"evidence digest mismatch: {name}")
    env = dict(line.split("=", 1) for line in (slot / "run.env").read_text().splitlines())
    identities = {k: p[k] for k in ("kernel_sha256", "config_sha256", "vmlinux", "vmlinux_sha256",
                                     "board_sha256", "initrd_sha256")}
    observed = {"kernel_build_id": guest_id(slot / "kernel.notes"),
                "board_build_id": guest_id(slot / "board.notes")}
    if any(value != p[key] for key, value in observed.items()):
        raise ValueError("guest notes differ from registered build")
    if (env["mode"] != mode or env["cleaned"] != "1" or
            re.findall(r"^BOOT ([0-9a-f-]{36})$", log, re.M) != [env["boot_id"]]):
        raise ValueError("boot, experiment or teardown identity mismatch")
    expected = {name.rsplit("/", 1)[-1]: digest for name, digest in p["guest"].items()
                if name.startswith("payload/")}
    actual = {Path(path).name: digest for digest, path in
              (line.split() for line in (slot / "guest-payload.sha256").read_text().splitlines())}
    if actual != expected:
        raise ValueError("loaded capture payload digest mismatch")
    save(slot / "build.json", identities | observed | env)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    profile = commands.add_parser("register", help="bind one kernel build, board and guest to their file hashes")
    for name in ("build", "board", "init", "disk", "destination"):
        profile.add_argument(name, type=Path)
    prep = commands.add_parser("prepare")
    prep.add_argument("profile", type=Path)
    prep.add_argument("dest", type=Path)
    capture = commands.add_parser("boot")
    capture.add_argument("package", type=Path)
    capture.add_argument("mode", choices=("train", "xy-first", "yx-first", "natural"))
    capture.add_argument("slot", type=Path)
    args = parser.parse_args()
    if args.action == "register":
        register(args.build, args.board, args.init, args.disk, args.destination)
    elif args.action == "prepare":
        prepare(args.profile.resolve(), args.dest.resolve())
    else:
        dest = args.slot.resolve()
        if dest.exists():
            parser.error("slot already exists")
        try:
            boot(args.package.resolve(), args.mode, dest)
        except Exception as error:
            if dest.exists():
                save(dest / "capture-result.json", {"passed": False, "error": repr(error)})
            raise
        save(dest / "capture-result.json", {"passed": True})

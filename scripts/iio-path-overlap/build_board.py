"""Build a sibling of a registered software board against the same kernel."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2)


def main():
    parser = argparse.ArgumentParser()
    for arg in ("parent_package", "work", "output", "llvm_bin"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    p = json.loads(args.parent_package.read_bytes())
    work, out = args.work.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    parent_board, image = Path(p["board"]), Path(p["kernel"])
    if digest(parent_board) != p["board_sha256"] or digest(image) != p["kernel_sha256"]:
        raise ValueError("parent package inputs changed")
    parent_src = parent_board.with_suffix(".c")
    original = parent_src.read_text()
    needle = r"(?m)^(\s*controller->transfer_one_message\s*=\s*\w+;)$"
    if len(re.findall(needle, original)) != 1 or "prepare_transfer_hardware" in original:
        raise ValueError("unsupported software board source")
    src = '#include "replay_ready.h"\n' + re.sub(needle, r"\1\n\tcontroller->prepare_transfer_hardware = board_prepare_once;", original)
    (work / parent_src.name).write_text(src)
    (out / "board.diff").write_text("".join(difflib.unified_diff(original.splitlines(True), src.splitlines(True),
                                                                  "registered/" + parent_src.name, "test/" + parent_src.name)))
    header = Path(__file__).resolve().parents[2] / "kernel/iio-spi-board/replay_ready.h"
    shutil.copyfile(header, work / header.name)
    shutil.copyfile(parent_board.parent / "Makefile", work / "Makefile")
    kernel_obj = Path(p["vmlinux"]).parent
    cmd = ["make", "-C", str((kernel_obj / "source").resolve(strict=True)), "O=" + str(kernel_obj),
           "ARCH=x86_64", "LLVM=" + str(args.llvm_bin.resolve()) + "/", "M=" + str(work), "modules"]
    env = os.environ.copy()
    env["KCFLAGS"] = "-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
    save(out / "command.json", cmd)
    with (out / "build.log").open("xb") as f:
        run = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
    save(out / "exit.json", {"code": run.returncode})
    run.check_returncode()
    board = work / parent_board.name
    notes = subprocess.check_output(["readelf", "-n", str(board)], text=True)
    build_id = re.search(r"Build ID: (\w+)", notes)[1]
    keys = ("kernel", "kernel_sha256", "vmlinux", "config", "config_sha256", "init", "init_sha256", "disk", "disk_sha256")
    save(out / "profile.json", {k: p[k] for k in keys} | {"board": str(board), "board_sha256": digest(board)})
    save(out / "identity.json", {"parent_package_sha256": digest(args.parent_package),
         "parent_board_source_sha256": digest(parent_src), "board_source_sha256": digest(work/parent_src.name),
         "board_header_sha256": digest(work/header.name), "parent_board_build_id": p["board_build_id"],
         "kernel_build_id": p["kernel_build_id"], "board_build_id": build_id, "board_sha256": digest(board)})


if __name__ == "__main__":
    main()

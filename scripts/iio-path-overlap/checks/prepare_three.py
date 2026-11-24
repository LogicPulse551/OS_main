"""Package three normal axis reads with a single software-controller ready window."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


SCRIPTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPTS / "iio-path"))
import capture


def read(path):
    return json.loads(path.read_bytes())


def prepare(markers, board_build, destination):
    destination.mkdir(parents=True, exist_ok=False)
    package_file = markers / "package.json"
    package = read(package_file)
    profile = read(board_build / "profile.json")
    board_id = board_build / "identity.json"
    receipt = read(board_id)
    for field in ("kernel", "config", "vmlinux", "init", "disk"):
        frozen, current = Path(package[field]).resolve(), Path(profile[field]).resolve()
        if frozen != current or capture.sha(current) != package[field + "_sha256"]:
            raise ValueError("parent input changed: " + field)
    board = Path(profile["board"])
    board_sha = capture.sha(board)
    if not (board_sha == receipt["board_sha256"] == profile["board_sha256"]
            and capture.elf_id(board) == receipt["board_build_id"]
            and capture.elf_id(Path(package["board"])) == receipt["parent_board_build_id"] == package["board_build_id"]
            and capture.sha(Path(package["board"])) == package["board_sha256"]
            and receipt["kernel_build_id"] == package["kernel_build_id"]):
        raise ValueError("board identity differs from registered pair of builds")
    reference = Path(package["observation"]["registry"])
    if (capture.sha(reference) != package["observation"]["registry_sha256"]
            or set(read(reference)["signature"]) != {"X", "Y", "Z"}):
        raise ValueError("marker package requires a frozen three-axis reference")
    base = markers / "observe.sh"
    if capture.sha(base) != package["guest"]["payload/observe.sh"]:
        raise ValueError("registered observation script changed")

    fragment = SCRIPTS / "iio-path-overlap/read-triple.sh"
    before, dispatch = base.read_text().split("capture() {", 1)
    _, after = dispatch.split("\nesac\n", 1)
    anchor = "sha256sum -- *.words probe-stats.txt"
    if after.count(anchor) != 1:
        raise ValueError("unsupported capture receipt layout")
    after = after.replace(anchor, "shopt -s nullglob\nsha256sum -- *.words control.tsv probe-stats.txt")
    script = destination / "observe.sh"
    script.write_text(before + fragment.read_text() + "\n" + after)
    subprocess.run(["bash", "-n", script], check=True)

    source = SCRIPTS / "iio-path-overlap/read_three.c"
    binary = destination / "read-axes"
    argv = ["gcc", "-static", "-O2", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(source), "-o", str(binary)]
    with (destination / "gcc.log").open("xb") as log:
        subprocess.run(argv, check=True, stdout=log, stderr=subprocess.STDOUT)
    files = {"init": Path(package["init"]), "payload/board.ko": board,
             "payload/read-axes": binary, "payload/observe.sh": script}
    archive = destination / "initrd.gz"
    capture.archive(archive, files)
    package.update(board=str(board), board_sha256=board_sha, board_build_id=receipt["board_build_id"],
                   initrd_sha256=capture.sha(archive), actor_source_sha256=capture.sha(source),
                   argv_build=argv, guest={k: capture.sha(path) for k, path in files.items()})
    package["host_files"]["board"] = capture.fingerprint(board)
    package["triple"] = {"axis_owner": "X", "peer_axes": ["Y", "Z"], "guest_mode": "natural",
                         "initrd_plan": True, "prepare_sha256": capture.sha(Path(__file__)),
                         "board_identity_sha256": capture.sha(board_id),
                         "source_markers_sha256": capture.sha(package_file),
                         "guest_fragment_sha256": capture.sha(fragment)}
    capture.save(destination / "package.json", package)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("markers", "board_build", "dest"):
        parser.add_argument(argument, type=Path)
    args = parser.parse_args()
    prepare(args.markers.resolve(), args.board_build.resolve(), args.dest.resolve())

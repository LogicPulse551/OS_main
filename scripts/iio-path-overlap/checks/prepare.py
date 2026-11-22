"""Prepare the two-axis read capture from a verified read_raw marker package."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

scripts = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("capture", scripts / "iio-path/capture.py")
cap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cap)
parser = argparse.ArgumentParser()
parser.add_argument("markers", type=Path)
parser.add_argument("board_build", type=Path)
parser.add_argument("order", choices=("XY", "YX"))
parser.add_argument("dest", type=Path)
args = parser.parse_args()
args.dest = args.dest.resolve()
args.dest.mkdir(parents=True)
p = json.loads((args.markers / "package.json").read_bytes())
profile = json.loads((args.board_build / "profile.json").read_bytes())
receipt = json.loads((args.board_build / "identity.json").read_bytes())
for key in ("kernel", "config", "vmlinux", "init", "disk"):
    if Path(p[key]).resolve() != Path(profile[key]).resolve() or cap.sha(profile[key]) != p[key + "_sha256"]:
        raise ValueError("changed parent input: " + key)
board = Path(profile["board"])
board_sha = cap.sha(board)
if not (board_sha == receipt["board_sha256"] == profile["board_sha256"] and
        cap.elf_id(board) == receipt["board_build_id"] and
        p["kernel_build_id"] == receipt["kernel_build_id"] and
        p["board_build_id"] == receipt["parent_board_build_id"]):
    raise ValueError("board build receipt mismatch")
src = scripts / "iio-path-overlap/read_one.c"
recipe = ["gcc", "-static", "-Wall", "-Wextra", "-Werror", "-std=gnu11", "-O2", "-pthread",
          str(src), "-o", str(args.dest / "read-axes")]
compiled = subprocess.run(recipe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(args.dest / "gcc.log").write_bytes(compiled.stdout)
compiled.check_returncode()
base_script = args.markers / "observe.sh"
if cap.sha(base_script) != p["guest"]["payload/observe.sh"]:
    raise ValueError("frozen markers script has changed")
before, rest = base_script.read_text().split("capture() {", 1)
_, after = rest.split("\nesac\n", 1)
fragment = scripts / "iio-path-overlap/read-pair.sh"
after = after.replace("sha256sum -- *.words probe-stats.txt",
                      "shopt -s nullglob\nsha256sum -- *.words control.tsv probe-stats.txt")
if "control.tsv" not in after:
    raise ValueError("missing receipt evidence binding")
target = args.dest / "observe.sh"
target.write_text(before + "planned_order=" + args.order + "\n" + fragment.read_text() + "\n" + after)
subprocess.run(["bash", "-n", target], check=True)
files = {"init": Path(p["init"]), "payload/board.ko": board,
         "payload/read-axes": args.dest / "read-axes", "payload/observe.sh": target}
cap.archive(args.dest / "initrd.gz", files)
p.update(board=str(board), board_sha256=board_sha, board_build_id=cap.elf_id(board),
         initrd_sha256=cap.sha(args.dest / "initrd.gz"), actor_source_sha256=cap.sha(src),
         argv_build=recipe, guest={name: cap.sha(file) for name, file in files.items()})
p["host_files"]["board"] = cap.fingerprint(board)
p["pair"] = {"axis_order": args.order, "source_markers_sha256": cap.sha(args.markers / "package.json"),
             "board_identity_sha256": cap.sha(args.board_build / "identity.json"),
             "guest_fragment_sha256": cap.sha(fragment), "prepare_sha256": cap.sha(__file__),
             "guest_mode": "natural", "initrd_plan": True}
cap.save(args.dest / "package.json", p)

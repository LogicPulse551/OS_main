"""Bind a pair of original/repair build receipts to each private RAM regmap property."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from kconc.artifacts import PIN, check_ref, read, ref, require


def kernel(path, family, kind):
    receipt = read(path)
    require(receipt.get("passed") is True and receipt.get("source_commit") == PIN
            and receipt.get("family") == family and receipt.get("kind") == kind,
            f"unexpected build receipt: {path}")
    entries = {Path(item["path"]).name: item for item in receipt["artifacts"]}
    artifacts = {name: check_ref(entries[name]) for name in ("bzImage", "vmlinux", ".config", "System.map")}
    return {"build": receipt["kernel_build"], "source": receipt["source"],
            "release": receipt["kernel_release"], "artifacts": artifacts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-repair", type=Path, required=True)
    parser.add_argument("--mutex-repair", type=Path, required=True)
    parser.add_argument("--disk", type=Path, required=True, help="read-only openEuler guest disk")
    parser.add_argument("--init", type=Path, required=True, help="static supervisor compiled from scripts/iio-path/init.c")
    parser.add_argument("--out", type=Path, required=True, help="new profile file outside the source tree")
    args = parser.parse_args()
    require(not args.out.resolve().is_relative_to(ROOT), "choose an output file outside the repository")
    profiles = {}
    for prop, family, repaired in (("update", "rmw", args.update_repair), ("mutex", "mutex", args.mutex_repair)):
        parent = check_ref(read(repaired)["accepted_parent_build_record"])
        profiles[prop + "-base"] = kernel(parent["path"], family, "kconc.control-kernel.build")
        profiles[prop + "-fix"] = kernel(repaired, family, "kconc.repaired-kernel.build")
        require(profiles[prop+"-base"]["artifacts"]["bzImage"]["sha256"] !=
                profiles[prop+"-fix"]["artifacts"]["bzImage"]["sha256"], "identical original and repair images")
    profile = {"profiles": profiles}
    for name in ("disk", "init"):
        item = ref(getattr(args, name))
        profile[name] = item["path"]
        profile[name + "_sha256"] = item["sha256"]
    with args.out.open("x", encoding="utf-8") as dest:
        json.dump(profile, dest, indent=2)
        dest.write("\n")


if __name__ == "__main__":
    main()

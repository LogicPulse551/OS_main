"""Collect a built-in BMA400 functional run from the disposable openEuler guest."""

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess

DEBUG = Path("/sys/kernel/debug")


def snapshot(path):
    if not path.exists():
        return None
    return path.read_text(encoding="utf8")


def main():
    if not os.path.ismount(DEBUG):
        subprocess.run(["mount", "-t", "debugfs", "none", DEBUG], check=True)
    files = {
        "observer": DEBUG / "kconc-c06-observer/results",
        "fixture": DEBUG / "kconc-bma400/results",
    }
    raw = {key: snapshot(path) for key, path in files.items()}
    report = {
        "schema": 1,
        "release": os.uname().release,
        "cmdline": Path("/proc/cmdline").read_text().strip(),
        "online": Path("/sys/devices/system/cpu/online").read_text().strip(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "config_sha256": hashlib.sha256(gzip.decompress(Path("/proc/config.gz").read_bytes())).hexdigest(),
        "notes_base64": base64.b64encode(Path("/sys/kernel/notes").read_bytes()).decode("ascii"),
        "os_release": Path("/etc/os-release").read_text(),
        "root_mount": next(
            line for line in Path("/proc/self/mountinfo").read_text().splitlines() if line.split()[4] == "/"
        ),
        "root_partition_device": Path("/sys/class/block/vda2/dev").read_text().strip(),
        "modules": Path("/proc/modules").read_text(),
        "debugfs": {
            str(path): {"exists": raw[key] is not None, "text": raw[key]} for key, path in files.items()
        },
        "final_regmap_entries": sorted(p.name for p in (DEBUG / "regmap").glob("*")),
        "sysfs_parameters": {
            str(p): p.read_text().strip()
            for p in Path("/sys/module").glob("*/parameters/*")
            if p.parents[1].name in ("kconc_bma400", "regmap")
            and p.name in ("mode", "calls", "warmups", "samples")
        },
        "dmesg": subprocess.run(
            ["dmesg", "--color=never"], check=True, capture_output=True, text=True
        ).stdout,
    }
    # Preserve the raw file even if its producer emitted malformed JSON.
    for key, text in raw.items():
        try:
            report[key] = json.loads(text) if text is not None else None
        except json.JSONDecodeError as error:
            report[key] = None
            report[key + "_error"] = str(error)
    print(json.dumps(report))


if __name__ == "__main__":
    main()

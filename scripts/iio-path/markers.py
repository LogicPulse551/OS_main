"""Prepare an independent passive observation package after freezing an axis reference."""
import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path

import capture

args = argparse.ArgumentParser()
args.add_argument("package", type=Path)
args.add_argument("registry", type=Path)
args.add_argument("source_root", type=Path)
args.add_argument("dest", type=Path)
args = args.parse_args()
args.dest.mkdir(parents=True)
package = json.loads((args.package / "package.json").read_bytes())
registry = json.loads(args.registry.read_bytes())
if any(package[key] != value for key, value in registry["identity"].items()):
    raise ValueError("reference and original capture identity differ")
signature = registry["signature"]
if set(signature) not in (set("XY"), set("XYZ")):
    raise ValueError("expected a reference covering the registered axes")
common = set.intersection(*(set(features["driver"]) for features in signature.values()))
found = []
for name in sorted(common):
    file, symbol = name.split("::")
    if not re.fullmatch(r"drivers/iio/[A-Za-z0-9_./-]+\.c", file) or ".." in Path(file).parts:
        raise ValueError("unexpected source path")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", symbol):
        raise ValueError("unexpected symbol")
    source = args.source_root / file
    lines = source.read_text().splitlines()
    for index, line in enumerate(lines, 1):
        if re.search(r"\.read_raw\s*=\s*&?\s*" + symbol + r"\s*,", line):
            found.append({"symbol": symbol, "source": str(source), "source_line": index,
                          "source_sha256": capture.sha(source), "registration": line.strip()})
symbols = {row["symbol"] for row in found}
if len(symbols) != 1:
    raise ValueError(f"registered signature does not identify a unique read_raw: {found}")
symbol, = symbols
# Start from the exact script that ran in the training guest (including archived guests).
archive = args.package / "initrd.gz"
if capture.sha(archive) != package["initrd_sha256"]:
    raise ValueError("original training archive has changed")
with gzip.open(archive, "rb") as packed:
    template = subprocess.run(
        ["cpio", "--quiet", "--extract", "--to-stdout", "payload/observe.sh"],
        input=packed.read(), check=True, stdout=subprocess.PIPE,
    ).stdout
if hashlib.sha256(template).hexdigest() != package["guest"]["payload/observe.sh"]:
    raise ValueError("guest template differs from original training package")
text = template.decode("utf-8")
setup = f"""printf '%s\\n' 'p:iio_learned/iio_learned_entry {symbol}' 'r:iio_learned/iio_learned_return {symbol}' >> "$T/kprobe_events"
echo 1 > "$T/events/iio_learned/enable"
"""
cleanup = '''cat "$T/kprobe_profile" > probe-stats.txt
echo > "$T/kprobe_events"
'''
for anchor in ('for group in regmap spi; do', 'echo "${sensor##*/}" >', 'sha256sum -- *.words'):
    if text.count(anchor) != 1:
        raise ValueError("unexpected observer layout")
text = text.replace("for group in regmap spi; do", setup + "for group in regmap spi; do")
text = text.replace('echo "${sensor##*/}" >', cleanup + 'echo "${sensor##*/}" >')
text = text.replace("sha256sum -- *.words", "sha256sum -- *.words probe-stats.txt")
obs = args.dest / "observe.sh"
obs.write_text(text)
files = {"init": Path(package["init"]), "payload/board.ko": Path(package["board"]),
         "payload/read-axes": args.package / "read-axes", "payload/observe.sh": obs}
for name, path in files.items():
    if name != "payload/observe.sh" and capture.sha(path) != package["guest"][name]:
        raise ValueError(name + " changed")
capture.archive(args.dest / "initrd.gz", files)
package["observation"] = {
    "parent_package_sha256": capture.sha(args.package / "package.json"),
    "registry_sha256": capture.sha(args.registry), "registry": str(args.registry.resolve()),
    "source_verification": found, "mode": "post-registration passive markers",
}
package["guest"]["payload/observe.sh"] = capture.sha(obs)
package["initrd_sha256"] = capture.sha(args.dest / "initrd.gz")
capture.save(args.dest / "package.json", package)

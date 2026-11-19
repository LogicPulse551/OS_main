"""Emit one timing translation unit from the locked, accepted BMA400 package."""
import argparse
import hashlib
import json
from pathlib import Path


UNIT = Path("drivers/base/regmap/regmap.c")
# The certificate covers the first two product variants. The cached control
# takes its input from the reference body and receives its own output digest.
CERT = "8e1d5d924c1ec34c25b7902c62058706e943f3a14ab8cc10956db1a501f596ab"


def cached(source):
    start = source.index(b"static int kconc_bma400_bulk_read(")
    stop = source.index(b"\n}", start) + 2
    body = source[start:stop]
    loop = (b"\t\tfor (i = 0; i < val_count * val_bytes; i += val_bytes)\n"
            b"\t\t\tmap->format.parse_inplace(val + i);")
    declaration = b"\t\tret = regmap_raw_read("
    if body.count(declaration) != 1 or body.count(loop) != 1:
        raise ValueError("unrecognized private read body")
    body = body.replace(declaration, b"\t\tvoid (*parse_inplace)(void *);\n\n" + declaration)
    body = body.replace(loop, b"\t\tparse_inplace = map->format.parse_inplace;\n" +
                        loop.replace(b"map->format.parse_inplace(val", b"parse_inplace(val"))
    return source[:start] + body + source[stop:]


def generate(package, variant, output):
    cert_bytes = (package / "certificate.json").read_bytes()
    if hashlib.sha256(cert_bytes).hexdigest() != CERT:
        raise ValueError("unrecognized source certificate")
    cert = json.loads(cert_bytes)
    arm = "reference" if variant == "cached" else variant
    source = (package / arm / UNIT).read_bytes()
    original = hashlib.sha256(source).hexdigest()
    if original != cert["emitted_sha256"][arm]:
        raise ValueError("source differs from certified package")
    if variant == "cached":
        source = cached(source)
    harness = Path(__file__).with_name("after-boot.c").read_bytes()
    result = source + b"\n" + harness
    output.mkdir(parents=True, exist_ok=False)
    target = output / UNIT
    target.parent.mkdir(parents=True)
    target.write_bytes(result)
    manifest = dict(variant=variant, certificate_sha256=CERT, parent_variant=arm,
                    parent_sha256=original, control_only=variant == "cached",
                    prefix_sha256=hashlib.sha256(source).hexdigest(), prefix_bytes=len(source),
                    harness_sha256=hashlib.sha256(harness).hexdigest(), source_sha256=hashlib.sha256(result).hexdigest())
    (output / "source.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=("reference","cached","optimized"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    generate(args.package, args.variant, args.output)

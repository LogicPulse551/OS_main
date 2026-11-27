"""Package the already verified teacher materials for a flat release asset directory."""
import argparse
import gzip
import hashlib
import json
import os
import tempfile
import zlib
from pathlib import Path

from materials import ROOT, digest, parts

CHUNK_BYTES = 32 << 20
SMALL_FILE_BYTES = 1 << 20
SMALL_PACK_BYTES = 8 << 20
DISK_BUNDLES = {"base-disk", "perf-disk", "official-openeuler"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, obj):
    data = (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        out.write(data)
        temporary = Path(out.name)
    os.replace(temporary, path)


class Pack:
    def __init__(self, output, previous):
        self.output = output
        self.chunks = {}
        self.files = {}
        self.by_raw_hash = {}
        self.existing = {row["raw_sha256"]:(key, row) for key, row in previous.items()}

    def chunk(self, raw):
        raw_hash = sha(raw)
        if raw_hash in self.by_raw_hash:
            return self.by_raw_hash[raw_hash]
        if raw_hash in self.existing:
            identity, row = self.existing[raw_hash]
            target = self.output / f"kconc-{identity}.gz"
            if target.is_file() and not target.is_symlink() and target.stat().st_size == row["bytes"] and digest(target) == identity:
                with gzip.open(target, "rb") as stream:
                    if stream.read(len(raw)+1) != raw:
                        raise ValueError(f"Existing chunk decodes to different bytes: {target.name}")
                self.chunks[identity] = row
                self.by_raw_hash[raw_hash] = identity
                return identity
        compressor = zlib.compressobj(3, zlib.DEFLATED, zlib.MAX_WBITS | 16)
        data = compressor.compress(raw) + compressor.flush()
        identity = sha(data)
        target = self.output / f"kconc-{identity}.gz"
        if target.exists():
            if target.is_symlink() or digest(target) != identity:
                raise ValueError(f"Existing release asset is corrupt: {target.name}")
        else:
            with tempfile.NamedTemporaryFile(dir=self.output, delete=False) as out:
                out.write(data)
                temporary = Path(out.name)
            os.replace(temporary, target)
        self.chunks[identity] = {"bytes":len(data), "raw_bytes":len(raw), "raw_sha256":raw_hash}
        self.by_raw_hash[raw_hash] = identity
        return identity

    def large(self, file, expected):
        slices, checksum = [], hashlib.sha256()
        with file.open("rb") as handle:
            for raw in iter(lambda: handle.read(CHUNK_BYTES), b""):
                checksum.update(raw)
                slices.append([self.chunk(raw), 0, len(raw)])
        if checksum.hexdigest() != expected:
            raise ValueError(f"Source file changed: {file}")
        self.files[expected] = slices

    def small(self, buffer, records):
        if not records:
            return
        identifier = self.chunk(buffer)
        for expected, offset, length in records:
            self.files[expected] = [[identifier, offset, length]]
        buffer.clear()
        records.clear()

    def bundle(self, root, inventory):
        actual = {}
        for p in root.rglob("*"):
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError(f"Unexpected special file: {p}")
            if p.is_file():
                actual[p.relative_to(root).as_posix()] = p
        if set(actual) != set(inventory):
            raise ValueError(f"Input bundle inventory mismatch: {root}")
        buffer, records = bytearray(), []
        for name, row in sorted(inventory.items()):
            file = root.joinpath(*parts(name))
            if file.suffix.lower() in {".qcow", ".qcow2", ".vhd", ".vhdx", ".vmdk", ".img", ".iso", ".raw"}:
                raise ValueError(f"Disk image cannot be packaged as a repository object: {name}")
            with file.open("rb") as source:
                if source.read(4) == b"QFI\xfb":
                    raise ValueError(f"QCOW disk cannot be packaged as a repository object: {name}")
            if file.stat().st_size != row["size"]:
                raise ValueError(f"Wrong source size: {file}")
            expected = row["sha256"]
            if expected in self.files:
                if digest(file) != expected:
                    raise ValueError(f"Wrong source digest: {file}")
            elif row["size"] > SMALL_FILE_BYTES:
                self.large(file, expected)
            else:
                data = file.read_bytes()
                if sha(data) != expected:
                    raise ValueError(f"Wrong source digest: {file}")
                if not data:
                    self.files[expected] = []
                    continue
                if len(buffer) + len(data) > SMALL_PACK_BYTES:
                    self.small(buffer, records)
                records.append((expected, len(buffer), len(data)))
                buffer.extend(data)
        self.small(buffer, records)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--materials", required=True, type=Path)
    p.add_argument("--override", type=Path, action="append", default=[],
                   help="override complete named bundle directories; first matching root wins")
    p.add_argument("--bundle", action="append", default=[],
                   help="include only this registered bundle; repeat for each desired bundle")
    p.add_argument("--output", required=True, type=Path, help="outside the checkout")
    p.add_argument("--catalog", type=Path, default=ROOT / "configs/teacher-delivery.json")
    p.add_argument("--index", type=Path, default=ROOT / "configs/teacher-release-assets.json")
    args=p.parse_args()
    outdir = args.output.resolve()
    if outdir == ROOT or ROOT in outdir.parents:
        p.error("release binaries belong outside the checkout")
    outdir.mkdir(parents=True, exist_ok=True)
    catalog = json.loads(args.catalog.read_bytes())
    prior = json.loads(args.index.read_bytes()).get("chunks", {}) if args.index.is_file() else {}
    pack = Pack(outdir, prior)
    selected = sorted(set(args.bundle or (catalog["bundles"].keys() - DISK_BUNDLES)))
    if set(selected) & DISK_BUNDLES:
        p.error("disk images must come directly from the pinned official source")
    unknown = set(selected) - catalog["bundles"].keys()
    if unknown:
        p.error(f"unknown bundles: {sorted(unknown)}")
    bundles = {}
    for key in selected:
        inventory = catalog["bundles"][key]
        print("Packing", key, flush=True)
        roots = [*args.override, args.materials]
        directory = next((root / key for root in roots if (root / key).is_dir()), None)
        if directory is None:
            raise FileNotFoundError(f"Missing registered material: {key}")
        pack.bundle(directory, inventory)
        bundles[key] = sorted({r[0] for spec in inventory.values() for r in pack.files[spec["sha256"]]})
    index = {"schema":1, "release":catalog["version"], "codec":"gzip",
             "chunks":pack.chunks, "files":pack.files, "bundles":bundles}
    write_json(args.index, index)
    asset_list = {f"kconc-{k}.gz":{"size":row["bytes"], "sha256":k} for k,row in pack.chunks.items()}
    publication = {"release":catalog["version"], "index_sha256":digest(args.index), "assets":asset_list,
                   "bundles":{k:[f"kconc-{v}.gz" for v in values] for k,values in bundles.items()}}
    write_json(outdir / "package-index.json", publication)
    print(f"Verified {len(index['files'])} unique files; {len(pack.chunks)} assets; "
          f"{sum(r['size'] for r in asset_list.values()):,} packed bytes.")


if __name__ == "__main__":
    main()

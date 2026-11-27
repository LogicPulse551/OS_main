"""Pack the teacher's pinned BMA400 verification tools on a Linux build host."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ARCHIVES = {
    "coq.8.15.0": "73466e61f229b23b4daffdd964be72bd7a110963b9d84bd4a86bb05c5dc19ef3",
    "ocaml-base-compiler.4.14.2": "c2d706432f93ba85bd3383fa451d74543c32a4e84a1afaf3e8ace18f7f097b43",
    "zarith.1.14": "5db9dcbd939153942a08581fabd846d0f3f2b8c67fe68b855127e0472d4d1859",
    "ocamlfind.1.9.8": "8967986de2ab4ec5993f437b0a4206742adf37aa7a292a3bba0a04438d78539b84d001191e60b2d5bde98a695b38cba2593b7051f7749adbdb964a0df3c4b661",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("compcert-parent", "coq-prefix", "clang", "llvm-sources", "output"):
        p.add_argument("--" + flag, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    lock = json.loads((ROOT / "proofs/bma400-noop/compcert-runtime.json").read_bytes())
    files = {}
    for name, expected in lock["runtime_files"].items():
        src = a.compcert_parent / name
        if hashlib.sha256(src.read_bytes()).hexdigest() != expected:
            raise ValueError("CompCert lock mismatch: " + name)
        files[name] = src
    for name in ("coqc", "coqtop", "coqchk"):
        files["coq/bin/" + name] = a.coq_prefix / "bin" / name
    for path in (a.coq_prefix / "lib/coq/theories").rglob("*.vo"):
        files["coq/" + path.relative_to(a.coq_prefix).as_posix()] = path
    core = a.coq_prefix / "lib/coq-core"
    for path in [core / "META", *sorted((core / "plugins").rglob("*.cmxs"))]:
        files["coq/" + path.relative_to(a.coq_prefix).as_posix()] = path
    files["llvm/bin/clang"] = a.clang
    files["licenses/Coq-LICENSE"] = a.coq_prefix / "doc/coq/coq-core/LICENSE"
    files["licenses/OCaml-LICENSE"] = a.coq_prefix / "doc/ocaml/LICENSE"
    for name in ("llvm", "clang"):
        files["licenses/" + name + "-LICENSE"] = a.llvm_sources / name / "LICENSE.TXT"
    files["sources/compcert-v3.13.tar.gz"] = a.compcert_parent / "compcert-v3.13.tar.gz"
    files["sources/menhir-20220210.tar.gz"] = a.compcert_parent / "menhir-20220210.tar.gz"
    if hashlib.sha256(files["sources/compcert-v3.13.tar.gz"].read_bytes()).hexdigest() != lock["archive_sha256"]:
        raise ValueError("CompCert source archive differs from the proof lock")
    for package, checksum in SOURCE_ARCHIVES.items():
        algo = "sha256" if len(checksum) == 64 else "sha512"
        cache = a.coq_prefix.parent / "download-cache" / algo / checksum[:2] / checksum
        if not cache.exists() and package == "ocamlfind.1.9.8":
            cache = a.coq_prefix.parent / "download-cache/md5/ca/ca770e5806032a96131b670f6e07f146"
        if hashlib.new(algo, cache.read_bytes()).hexdigest() != checksum:
            raise ValueError("Unrecognized upstream source: " + package)
        files["sources/" + package + ".tar.gz"] = cache
        files["sources/" + package + ".opam"] = a.coq_prefix / ".opam-switch/packages" / package / "opam"
    notice = a.output / "NOTICE.txt"
    notice.write_text(
        "Pinned BMA400 local proof tools for non-commercial teaching and research.\n"
        "CompCert 3.13, INRIA and AbsInt; the full INRIA Non-Commercial License, LGPL alternatives, "
        "Flocq, MenhirLib and BSD conditions are in CompCert-3.13/LICENSE.\n"
        "CompCert project https://compcert.org/ ; source archive supplied, revision "
        "920da14e4f1b184efe30a568f945bb7362da7ed4. Menhir 20220210, source supplied.\n"
        "Coq 8.15.0, https://github.com/coq/coq/tree/V8.15.0 ; "
        "OCaml 4.14.2, https://github.com/ocaml/ocaml/tree/4.14.2 ; Zarith 1.14 and Findlib 1.9.8. "
        "Their matching sources, upstream notices and opam build recipes are included under sources/.\n"
        "Clang/LLVM, https://github.com/llvm/llvm-project/tree/dc5c6d008f487eea8f5d646011f9b3dca6caebd7 ; "
        "the original scoped certificate binds the clang binary's SHA-256.\n"
        "These tools retain the original component licenses. None are installed system-wide.\n",
        encoding="utf-8")
    with tarfile.open(a.output / "runtime.tar", "x", format=tarfile.GNU_FORMAT) as tar:
        for name in ("backend", "cfrontend", "common", "cparser", "driver", "export",
                     "flocq", "lib", "MenhirLib", "x86", "x86_64"):
            entry = tarfile.TarInfo("CompCert-3.13/" + name)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(entry)
        for name, src in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name.startswith(("coq/bin/", "llvm/bin/")) or name.endswith(("/clightgen", "/menhir")) else 0o644
            entry.size = src.stat().st_size
            with src.open("rb") as stream:
                tar.addfile(entry, stream)
    print(json.dumps({"files": len(files), "runtime_bytes": (a.output / "runtime.tar").stat().st_size}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Developer tools for normal device reads, captured events and driver source."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
PREFIX = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PREFIX / "src"))


def emit(report, output):
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(output)


def verify_install(catalog):
    for name, expected in catalog["files"].items():
        path = PREFIX / name
        if path.resolve() != path or not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"installed file differs: {name}")
    print(f"Verified {len(catalog['files'])} files ({', '.join(catalog['components'])})")


def property_check(args):
    from kconc import mutex_oracle, regmap_oracle
    raw = args.input.read_bytes()
    obs = json.loads(raw)
    if args.property == "updates":
        result = regmap_oracle.evaluate(obs["initial"], obs["operations"], obs["final"])
    else:
        result = mutex_oracle.evaluate(obs["events"], obs["event_count"])
    result["input_sha256"] = sha256(raw).hexdigest()
    emit(result, args.out)
    return 0 if result["allowed"] else 1


def read_iio(args):
    if (not re.fullmatch(r"/sys/bus/iio/devices/iio:device[0-9]+", str(args.device))
            or not args.device.is_dir()):
        raise ValueError("Select a bound local IIO device under /sys/bus/iio/devices")
    if len(set(args.axes)) != len(args.axes) or len(args.axes) not in (2, 3):
        raise ValueError("Choose two or three distinct axes")
    args.out.mkdir(mode=0o700, exist_ok=False)
    reader = (args.out / "read-axes").resolve()
    subprocess.run([args.cc, "-O2", "-pthread", str(PREFIX / "share/kconc/read_axes.c"),
                    "-o", str(reader)], check=True)
    keys = [word for index, axis in enumerate(args.axes, 1) for word in (f"read{index}", axis)]
    with (args.out / "ops.tsv").open("xb") as out, (args.out / "reader.stderr").open("xb") as err:
        run = subprocess.run([str(reader), str(args.device), args.mode, *keys],
                             cwd=args.out, stdout=out, stderr=err)
    emit({"mode": args.mode, "axes": args.axes, "device": str(args.device),
          "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
          "reader_exit": run.returncode, "controlled": False,
          "scope": "Per-reader observations. Path discovery also requires a complete capture and symbols."},
         args.out / "reader.json")
    return run.returncode


def scan(args):
    from kconc.api_opt import inventory
    from kconc.api_emit import ORIGINAL
    root = args.kernel.resolve(strict=True)
    candidates = []
    for path, calls in inventory(root, args.scope).items():
        raw = path.read_bytes()
        checksum = sha256(raw).hexdigest()
        for row in calls:
            offset = row["offset"]
            if raw[offset:offset + len(ORIGINAL)] != ORIGINAL:
                raise ValueError(f"Source changed during scan: {path}")
            candidates.append({"source": row["source"], "source_sha256": checksum, "line": row["line"],
                               "offset": offset, "constant_value_count": row["length"]})
    emit({"kind": "source-inventory", "scope": args.scope, "candidates": candidates,
          "proof_checked": False, "patch_generated": False}, args.out)
    return 0


def recorded_compiler(args):
    from kconc.api_kbuild import command_location
    from kconc.api_opt import inventory
    root = args.kernel.resolve(strict=True)
    build = args.build_dir.resolve(strict=True)
    found = set()
    for source in inventory(root, args.scope):
        try:
            record, _, target, _ = command_location(root, build, source)
        except ValueError:
            continue
        with record.open(encoding="utf-8") as stream:
            head = stream.readline().rstrip()
        prefix = "savedcmd_" + target.as_posix() + " := "
        if head.startswith(prefix):
            tokens = shlex.split(head[len(prefix):].partition(";")[0])
            if tokens and Path(tokens[0]).is_absolute() and Path(tokens[0]).is_file():
                found.add(Path(tokens[0]).resolve())
    return found.pop() if len(found) == 1 else None


class WithReleaseProof:
    """Acquire tools only after the optimizer admits an actual Kbuild call site."""

    def __init__(self, args, scope):
        self._args, self._proof_stack = args, scope

    def __getattr__(self, key):
        if key not in ("compcert", "coq_bin"):
            return getattr(self._args, key)
        module_dir = str(PREFIX / "scripts/teacher")
        sys.path.insert(0, module_dir)
        self._proof_stack.callback(sys.path.remove, module_dir)
        from materials import material, read_catalog
        from proof_tools import prepared
        import release_assets
        source = json.loads((PREFIX / "configs/proof-source.json").read_bytes())
        checkout = Path(os.environ.get("KCONC_PROJECT", source["checkout"])).expanduser().resolve()
        index = checkout / "configs/teacher-release-assets.json"
        if index.is_file() and sha256(index.read_bytes()).hexdigest() == source["release_index_sha256"]:
            # Only the data files are read from this checkout. Every object is
            # checked against the proof-only index shipped with this install.
            self._proof_stack.callback(setattr, release_assets, "ROOT", release_assets.ROOT)
            release_assets.ROOT = checkout
        runtime = material("proof-runtime", read_catalog())
        _, self.compcert, self.coq_bin, env = self._proof_stack.enter_context(prepared(runtime))
        for name in ("COQLIB", "COQCORELIB", "OCAMLPATH", "COQBIN", "COQPATH", "OCAMLFIND_CONF",
                     "CAML_LD_LIBRARY_PATH", "COMPCERT_CONFIG"):
            if name in os.environ:
                self._proof_stack.callback(os.environ.__setitem__, name, os.environ[name])
            else:
                self._proof_stack.callback(os.environ.pop, name, None)
            if name in env:
                os.environ[name] = env[name]
            else:
                os.environ.pop(name, None)
        return getattr(self, key)


def main():
    catalog = json.loads((PREFIX / "install.json").read_bytes())
    components = catalog["components"]
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-install", help="verify installed files against the installation receipt")
    if "detect" in components:
        sub.add_parser("detect", add_help=False, help="discover, verify or challenge a build-bound IIO read path")
        check = sub.add_parser("property", help="check a two-caller property on your observation JSON",
            description="updates expects initial/final four uint32 registers and two operations "
                        "(role, reg, mask, value). mutex expects event_count and four event slots "
                        "(seq, role, kind, depth; kinds 1=enter, 2=exit, 3=busy; pad unused slots with zeros).")
        check.add_argument("property", choices=("updates", "mutex"))
        check.add_argument("--input", required=True, type=Path)
        check.add_argument("--out", required=True, type=Path)
        read = sub.add_parser("read-iio", help="sample two or three normal sysfs reads on your bound device",
            description="On the compatible instrumented kernel, sample normal X/Y/Z reads of your bound IIO "
                        "device. Requires the passive KCOV memory format, accessible trace_marker and a C "
                        "compiler. Start regmap tracing separately if you need a complete system trace. "
                        "Output contains ops.tsv, per-reader KCOV words, exit status and the boot identity.")
        read.add_argument("--device", required=True, type=Path)
        read.add_argument("--axes", required=True, nargs="+", choices=("X", "Y", "Z"))
        read.add_argument("--mode", required=True, choices=("seq", "parallel"))
        read.add_argument("--out", required=True, type=Path)
        read.add_argument("--cc", default="cc")
    if "optimize" in components:
        inv = sub.add_parser("scan", help="list literal regmap_bulk_read sites in your driver source")
        opt = sub.add_parser("optimize", help="check actual Kbuild, caller and Coq bindings and emit a patch")
        for cmd in (inv, opt):
            cmd.add_argument("--kernel", type=Path, required=True, help="Linux source root")
            cmd.add_argument("--scope", required=True, help="C file or directory under drivers/")
        inv.add_argument("--out", required=True, type=Path)
        opt.add_argument("--build-dir", type=Path, required=True)
        opt.add_argument("--config", type=Path, required=True)
        opt.add_argument("--policy", choices=("valid-n", "init-n"), default="init-n")
        opt.add_argument("--clang", type=Path, help="exact compiler used by Kbuild; normally read from its .o.cmd")
        opt.add_argument("--compcert", type=Path, help="matching external CompCert build")
        opt.add_argument("--coq-bin", type=Path, help="matching external Coq bin directory")
        opt.add_argument("--output", required=True, type=Path, help="new output directory")
        opt.set_defaults(materialize=False)
    if "detect" in components and sys.argv[1:2] == ["detect"]:
        from kconc.iio_path import main as iio_path
        return iio_path(sys.argv[2:])
    args = parser.parse_args()
    if args.command == "verify-install":
        verify_install(catalog)
        return 0
    if args.command == "property":
        return property_check(args)
    if args.command == "read-iio":
        return read_iio(args)
    if args.command == "scan":
        return scan(args)
    from kconc import valid_opt
    try:
        if bool(args.compcert) != bool(args.coq_bin):
            raise ValueError("供给自有证明环境时请同时指定 --compcert 和 --coq-bin；默认自动准备。")
        if not args.clang:
            args.clang = recorded_compiler(args)
        with ExitStack() as scope:
            result = valid_opt.optimize(args if args.compcert else WithReleaseProof(args, scope))
    except valid_opt.OperationError as error:
        raise ValueError(error.message) from error
    print(json.dumps({"decision": result["decision"], "reasons": result["reasons"],
                      "result": str(args.output / "result.json")}, ensure_ascii=False))
    return 0 if result["decision"] == "emit_guarded_sites" else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)

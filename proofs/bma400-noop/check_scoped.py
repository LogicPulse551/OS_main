"""Bind the C04 local proof to a private function extracted from the emitted regmap.c."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from check import BINARIES, GENERATED, KERNEL_SOURCES, projection


HERE = Path(__file__).resolve().parent
LOCK = HERE / "compcert-runtime.json"
LOCK_SHA256 = "01aabfcce994fc6f7ff645bc4d80f10e0b59db51e5caeb61cb4426fd2996b019"
CERTIFICATE = {
    "BulkRead.v": "f3437cb67909e94cbc928022a8e752085e7c74170c9fa2889be8f98758938dcf",
    "NativeNoop.v": "08a020de71d572e7dafd0c481b431b68704c827ac3d7d62de0b218d0fd027e44",
    "ClightBinding.v": "4c2881ab62da5adbef1a261c38da111161e87a682fdc4a9ef85faf1ab994ca0e",
    "case_declarations.h": "5c7a974eaa948108b8df0c318c792b69a878d6ffcd8b75dc295a07a11ea718fc",
    "check.py": "c3fa60b7d18ef4eeb1eeafcc948e2956120fd8ff412b19c9ad098f595e71b7d1",
}
PUBLIC = b"int regmap_bulk_read("
PRIVATE = b"static int kconc_bma400_bulk_read("
NOOP = b"static void regmap_parse_inplace_noop("
PRIVATE_ANCHOR = (
    "\nint (*const c05_private_anchor)(struct regmap *, unsigned int, void *, size_t)"
    " = kconc_bma400_bulk_read;\n"
)

# Compare Clight function records *after* parsing the actual private spelling.
# The additional relocation in the projection retains the static function; no
# address or offset from this small translation unit is used by Linux.
PROOF = """From Coq Require Import List.
From compcert Require Import Coqlib AST Values Events Globalenvs Smallstep Ctypes Clight.
From Bma400 Require Import Original Guarded Private ClightBinding NativeNoop.
Import ListNotations.

Lemma same_guarded_function :
  Private.f_kconc_bma400_bulk_read = Guarded.f_regmap_bulk_read.
Proof. reflexivity. Qed.

Lemma same_noop_function :
  Private.f_regmap_parse_inplace_noop = Original.f_regmap_parse_inplace_noop.
Proof. reflexivity. Qed.

Lemma emitted_cut :
  fn_body Private.f_kconc_bma400_bulk_read =
  guard_loops (fn_body Original.f_regmap_bulk_read).
Proof. rewrite same_guarded_function. apply (proj1 (proj2 actual_cuts)). Qed.

Definition private_definition (id : ident) :=
  let ge := globalenv Private.prog in
  match Genv.find_symbol ge id with
  | Some b => Genv.find_funct_ptr ge b
  | None => None
  end.

Lemma emitted_functions_bound :
  private_definition Private._kconc_bma400_bulk_read =
    Some (Internal Private.f_kconc_bma400_bulk_read) /\\
  private_definition Private._regmap_parse_inplace_noop =
    Some (Internal Private.f_regmap_parse_inplace_noop).
Proof. vm_compute. split; reflexivity. Qed.

Theorem emitted_noop_returns arg m k :
  is_call_cont k ->
  star step2 (globalenv Private.prog)
    (Callstate (Internal Private.f_regmap_parse_inplace_noop) [arg] k m) E0
    (Returnstate Vundef k m).
Proof. rewrite same_noop_function. apply callback_returns. Qed.

Print Assumptions same_guarded_function.
Print Assumptions emitted_cut.
Print Assumptions emitted_functions_bound.
Print Assumptions emitted_noop_returns.
"""


def digest(content):
    return hashlib.sha256(content).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def function(text, signature):
    marker = b"\n" + signature
    require(text.count(marker) == 1, f"expected one definition of {signature!r}")
    start = text.index(marker) + 1
    end = text.index(b"\n}\n", start) + 3
    fn = text[start:end]
    require(
        fn.count(b"{") > 0 and fn.count(b"{") == fn.count(b"}"),
        f"invalid function boundary for {signature!r}",
    )
    return fn


def prepare(original, emitted, decl, work, receipt):
    require(digest(original) == KERNEL_SOURCES["Original"], "unrecognized original regmap.c")
    public = function(original, PUBLIC)
    require(function(emitted, PUBLIC) == public, "public regmap_bulk_read changed")
    noop = function(emitted, NOOP)
    require(noop == function(original, NOOP), "noop callback changed")
    private = function(emitted, PRIVATE)
    require(public + b"EXPORT_SYMBOL_GPL(regmap_bulk_read);\n\n" + private in emitted,
            "private definition is outside its registered source position")
    renamed = PUBLIC + private[len(PRIVATE) :]
    # Reconstitution is an identity check on actual private bytes, including
    # every unmodified branch. The known guarded baseline is never a proof input.
    guarded = original.replace(public, renamed, 1)
    require(digest(guarded) == KERNEL_SOURCES["Guarded"], "private function differs from C04")
    original_unit = projection(original.decode(), decl)
    guarded_unit = projection(guarded.decode(), decl)
    # Reuse the identical declarations, noop and byte-address normalization.
    # Swap just the external spelling for the actual static spelling; compare
    # the full suffix against the independently sliced emitted definition.
    private_function = private.decode().replace("val + i", "(unsigned char *)val + i")
    pub_spelling = (
        (PUBLIC + private[len(PRIVATE) :]).decode().replace("val + i", "(unsigned char *)val + i")
    )
    require(guarded_unit.endswith(pub_spelling), "guarded projection boundary changed")
    public_unit = projection((noop + b"\n" + public).decode(), decl)
    actual_public = public.decode().replace("val + i", "(unsigned char *)val + i")
    require(
        public_unit == original_unit and public_unit.endswith(actual_public),
        "emitted public projection differs from original",
    )
    private_unit = public_unit[: -len(actual_public)] + private_function + PRIVATE_ANCHOR
    receipt["extracted_sha256"] = {
        name: digest(data)
        for name, data in (
            ("public", public),
            ("private", private),
            ("noop", noop),
            ("C04_guarded_reconstituted", guarded),
        )
    }
    for name, data in (
        ("emitted-private.c", private),
        ("emitted-public.c", public),
        ("emitted-noop.c", noop),
    ):
        (work / name).write_bytes(data)
    return {"Original": original_unit, "Guarded": guarded_unit, "Private": private_unit}


def run(original, emitted, compcert, coq_bin, out):
    work, compcert, coq_bin = [p.resolve() for p in (out, compcert, coq_bin)]
    work.mkdir(parents=True, exist_ok=False)
    receipt = dict(
        schema=1,
        passed=False,
        kernel_sources={},
        commands=[],
        inputs={},
        vo_sha256={},
        assumptions_sha256={},
        tools={},
        certificate_sources={},
    )
    flags = []
    for name in (
        "lib",
        "common",
        "x86_64",
        "x86",
        "backend",
        "cfrontend",
        "driver",
        "export",
        "cparser",
    ):
        flags.extend(("-R", str(compcert / name), "compcert." + name))
    for name, logical in (("flocq", "Flocq"), ("MenhirLib", "MenhirLib")):
        flags.extend(("-R", str(compcert / name), logical))
    flags.extend(("-Q", str(work), "Bma400"))
    env = dict(os.environ, PATH=str(coq_bin) + os.pathsep + os.environ["PATH"])

    def command(label, tool, args, cwd):
        sha = digest(tool.read_bytes())
        require(sha == BINARIES[tool.name], f"unrecognized {tool.name}")
        receipt["tools"][tool.name] = sha
        row = dict(label=label, argv=[str(tool), *args], cwd=str(cwd))
        receipt["commands"].append(row)
        stdout, stderr = work / (label + ".stdout"), work / (label + ".stderr")
        with stdout.open("wb") as so, stderr.open("wb") as se:
            row["exit_code"] = subprocess.run(
                row["argv"], cwd=cwd, env=env, stdout=so, stderr=se, timeout=360
            ).returncode
        row.update(stdout_sha256=digest(stdout.read_bytes()), stderr_sha256=digest(stderr.read_bytes()))
        require(row["exit_code"] == 0, f"{label} failed, see {stderr}")

    try:
        lock_bytes = LOCK.read_bytes()
        require(digest(lock_bytes) == LOCK_SHA256, "unrecognized CompCert environment lock")
        runtime = json.loads(lock_bytes)["runtime_files"]
        for name, expected in runtime.items():
            require(
                digest((compcert.parent / name).read_bytes()) == expected,
                f"changed CompCert runtime file: {name}",
            )
        receipt["environment"] = {"lock_sha256": LOCK_SHA256, "checked_files": len(runtime)}
        for name, path in (("Original", original), ("Emitted", emitted)):
            data = path.read_bytes()
            (work / (name + "-regmap.c")).write_bytes(data)
            receipt["kernel_sources"][name] = digest(data)
        for name, sha in CERTIFICATE.items():
            shutil.copyfile(HERE / name, work / name)
            actual = digest((work / name).read_bytes())
            receipt["certificate_sources"][name] = actual
            require(actual == sha, f"unrecognized C04 input: {name}")
        shutil.copyfile(__file__, work / "check_scoped.py")
        receipt["runner_sha256"] = digest((work / "check_scoped.py").read_bytes())
        units = prepare(
            (work / "Original-regmap.c").read_bytes(),
            (work / "Emitted-regmap.c").read_bytes(),
            (work / "case_declarations.h").read_text(encoding="utf-8"),
            work,
            receipt,
        )
        for name, code in units.items():
            folder = work / name
            folder.mkdir()
            (folder / "Case.c").write_text(code, encoding="utf-8")
            command(
                name + "-project",
                compcert / "clightgen",
                ["-canonical-idents", "-o", "Case.v", "Case.c"],
                folder,
            )
            shutil.copyfile(folder / "Case.v", work / (name + ".v"))
            if name in GENERATED:
                require(
                    digest((folder / "Case.v").read_bytes()) == GENERATED[name],
                    name + " AST differs from C04",
                )
        (work / "ScopedBinding.v").write_text(PROOF, encoding="utf-8")
        for name in (
            "Original",
            "Guarded",
            "Private",
            "BulkRead",
            "ClightBinding",
            "NativeNoop",
            "ScopedBinding",
        ):
            receipt["inputs"][name] = digest((work / (name + ".v")).read_bytes())
            command(name, coq_bin / "coqc", ["-q", *flags, name + ".v"], work)
            receipt["vo_sha256"][name] = digest((work / (name + ".vo")).read_bytes())
            if name not in units:
                receipt["assumptions_sha256"][name] = digest((work / (name + ".stdout")).read_bytes())
        command("coqchk", coq_bin / "coqchk", ["-silent", *flags, "Bma400.ScopedBinding"], work)
        receipt["passed"] = True
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        (work / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("original", "emitted", "compcert", "coq-bin", "out"):
        parser.add_argument("--" + arg, type=Path, required=True)
    opts = parser.parse_args()
    run(opts.original, opts.emitted, opts.compcert, opts.coq_bin, opts.out)

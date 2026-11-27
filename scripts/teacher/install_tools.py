"""Install a relocatable subset of the tools for a developer's own inputs."""
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OPT_MODULES = ("api_emit", "api_flow", "api_inputs", "api_kbuild", "api_opt",
               "native_contracts", "native_flow", "valid_emit", "valid_opt",
               "var_emit", "var_flow", "init_emit")
PROOFS = {
    "bma400-noop": ("BulkRead.v", "NativeNoop.v", "ClightBinding.v", "case_declarations.h",
                    "check.py", "check_scoped.py", "compcert-runtime.json"),
    "sixbyte": ("ObjectClass.v", "ProjectedGuard.v", "Kx022aRead.v", "DeviceReads.v", "check.py"),
    "var-regmap": ("VariableRead.v", "check.py"),
    "init-regmap": ("InitRead.v", "check.py"),
}


def source_subset(file, imports, names):
    """Retain original definitions without bringing the launchers or fixture tables along."""
    text = (ROOT / "src/kconc" / file).read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    expected = set(names.split())
    definitions = []
    for node in ast.parse(text).body:
        name = getattr(node, "name", None)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", None)
        if name in expected:
            expected.remove(name)
            definitions.append("".join(lines[node.lineno - 1:node.end_lineno]).rstrip())
    if expected:
        raise ValueError(f"{file}: missing definitions {sorted(expected)}")
    return (imports + "\n\n" + "\n\n\n".join(definitions) + "\n").encode("utf-8")


def populate(staging, mode):
    files = {}
    def put(name, content):
        path = staging / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files[name] = sha256(content).hexdigest()

    def copy(name):
        put(name, (ROOT / name).read_bytes())

    def subset(module, imports, names):
        put(f"src/kconc/{module}.py", source_subset(module + ".py", imports, names))

    components = ["detect", "optimize"] if mode == "all" else [mode]
    put("bin/kconc", (HERE / "own_tools.py").read_bytes())
    (staging / "bin/kconc").chmod(0o755)
    copy("src/kconc/__init__.py")
    if "detect" in components:
        copy("src/kconc/iio_path.py")
        put("share/kconc/read_axes.c", (ROOT / "scripts/iio-path/read_axes.c").read_bytes())
        subset("regmap_oracle", "", "U32 ORACLE uint vector validate_inputs apply_update evaluate")
        subset("mutex_oracle", "", "U32 ORACLE EVENT_FIELDS uint require evaluate")
    if "optimize" in components:
        for name in ("proof_tools.py", "materials.py", "release_assets.py"):
            copy("scripts/teacher/" + name)
        catalog_file = ROOT / "configs/teacher-delivery.json"
        index_file = ROOT / "configs/teacher-release-assets.json"
        delivery = json.loads(catalog_file.read_bytes())
        index = json.loads(index_file.read_bytes())
        bundle = delivery["bundles"]["proof-runtime"]
        installed_catalog = {"version": delivery["version"], "bundles": {"proof-runtime": bundle}}
        required = index["bundles"]["proof-runtime"]
        installed_index = {key: index[key] for key in ("release", "codec", "schema")}
        installed_index.update(bundles={"proof-runtime": required},
                               files={info["sha256"]: index["files"][info["sha256"]] for info in bundle.values()},
                               chunks={key: index["chunks"][key] for key in required})
        for name, obj in (("teacher-delivery", installed_catalog), ("teacher-release-assets", installed_index)):
            put("configs/" + name + ".json", json.dumps(obj, indent=2).encode("utf-8"))
        locator = {"checkout": str(ROOT), "release_index_sha256": sha256(index_file.read_bytes()).hexdigest()}
        put("configs/proof-source.json", json.dumps(locator, indent=2, ensure_ascii=False).encode("utf-8"))
        for name in OPT_MODULES:
            copy(f"src/kconc/{name}.py")
        subset("cli", "import hashlib\nimport json\nfrom pathlib import Path",
               "REPO OperationError digest new_output save")
        subset("sixbyte", "import difflib\nimport hashlib\nimport os", "CLANG _publish_overlay")
        subset("sixbyte_scan", "import re",
               "SHARED_INPUTS _TRIVIA _CALL _PUNCT _NUMBER _calls _integer")
        subset("sixbyte_emit", "", "LOOP GUARDED_LOOP")
        for folder, entries in PROOFS.items():
            for entry in entries:
                copy(f"proofs/{folder}/{entry}")
    catalog = {"schema": 1, "components": components, "files": files}
    (staging / "install.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


def install(mode, prefix):
    target = prefix.expanduser().absolute()
    if target.exists() or target.is_symlink():
        raise ValueError(f"Choose a new installation directory: {target}")
    if ROOT == target.resolve() or ROOT in target.resolve().parents:
        raise ValueError("Choose an installation directory outside the project")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the destination before copying. An interrupted install cannot replace
    # an existing tool or leave a partially installed executable at its final path.
    with tempfile.TemporaryDirectory(prefix=".kconc-stage-", dir=target.parent) as temp:
        staging = Path(temp) / "tools"
        staging.mkdir()
        populate(staging, mode)
        target.mkdir()
        try:
            os.replace(staging, target)
        except OSError:
            target.rmdir()
            raise
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("detect", "optimize", "all"))
    parser.add_argument("--prefix", required=True, type=Path, help="new installation directory")
    args = parser.parse_args()
    try:
        prefix = install(args.component, args.prefix)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Installation failed: {error}\n")
    print(f"Installed in {prefix}\nRun {prefix / 'bin/kconc'} --help")

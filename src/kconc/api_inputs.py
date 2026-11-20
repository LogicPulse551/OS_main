"""Bind the shared regmap ABI and the build's compiler include search roots."""
import hashlib
import os
from pathlib import Path
import shlex
import stat
import subprocess

from .sixbyte import CLANG


CONFIG = "97d3db10a602f10e3553d0af022dfd1052488f8b9ed3724d0639170b3e826e0b"
ARCHIVE = "cdcf5373ee4a0c43c11ea3a1053d54534a8048f16057614f954f542f58990709"
SOURCE_PATHS = ("include", "arch/x86/include", "drivers/base/regmap")
OBJECT_PATHS = ("include", "arch/x86/include")
SOURCE_LOCK = "4d5356840408192173d00b3831a329c3c87c94de18628f525b4f3fc479af96ef"
OBJECT_LOCK = "2574290358b94150b5e1ea058e46e291daa8fbd894d8cefefd0ef4f376286e3e"
# Both digests come from the same make receipt in the original authenticated build.
KCONFIG_MAKE_PORTABLE = "f52a0bb381f71a6b5becc7b016f992916cab865fa5a207040721b81e8369414b"
KCONFIG_MAKE_ORIGINAL = "c2e1ac4a18c485e1a2ce036758834862438f5c75a93dbf10917107b826a52304"
RESOURCE_LOCK = "df23b24be26a9994ffd90c28467ec108af455fa14d844f510b00e2079d484e5d"
BUILD_LABELS = {"include/generated/compile.h", "include/generated/utsversion.h"}
COMPILER_ENV = {"CPATH", "C_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
                "CCC_OVERRIDE_OPTIONS", "SDKROOT", "GCC_EXEC_PREFIX", "COMPILER_PATH",
                "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES", "CLANG_MODULE_CACHE_PATH"}


def file_hash(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest(entries):
    """Names are rooted separately so an out-of-tree build can be relocated."""
    sha = hashlib.sha256()
    for name, tag, payload in sorted(entries):
        sha.update(os.fsencode(name) + b"\0" + tag + bytes.fromhex(payload))
    return {"sha256": sha.hexdigest(), "files": len(entries)}


def kconfig_make_identity(data, source):
    """Bind the make dependency list and its unique guard against this exact srctree."""
    guard = b'ifneq "$(srctree)" "' + os.fsencode(source) + b'"\n'
    lines = data.splitlines(keepends=True)
    if lines.count(guard) != 1:
        raise ValueError("Kconfig make receipt does not name this source tree")
    lines[lines.index(guard)] = b'ifneq "$(srctree)" "$SOURCE"\n'
    if hashlib.sha256(b"".join(lines)).hexdigest() != KCONFIG_MAKE_PORTABLE:
        raise ValueError("Kconfig make dependencies differ from the locked build")
    # Use the original entry in the existing 1860-entry manifest. Only the
    # attested pathname in the guard is relocatable; all remaining bytes match.
    return KCONFIG_MAKE_ORIGINAL


def tree_inputs(base, paths, build=None):
    entries = []

    def fail(error):
        raise error

    for scope in paths:
        folder = base / scope
        if folder.resolve(strict=True) != folder or not folder.is_dir():
            raise ValueError("Redirected or missing input directory: " + str(folder))
        for directory, dirs, files in os.walk(folder, onerror=fail):
            parent = Path(directory)
            if any((parent / item).is_symlink() for item in dirs):
                raise ValueError("Redirected include directory: " + str(parent))
            for item in files:
                path = parent / item
                name = path.relative_to(base).as_posix()
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    target = path.resolve(strict=True)
                    if build is not None or not target.is_file() or not any(
                            base / scope in target.parents for scope in paths):
                        raise ValueError("Include link leaves the bound source: " + name)
                    value = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
                    tag = b"L"
                elif stat.S_ISREG(mode):
                    tag = b"F"
                    if build is not None and name in BUILD_LABELS:
                        # Retain name, type and existence. Contents are reported
                        # separately; TUs that consume them cannot be admitted.
                        value = hashlib.sha256(b"").hexdigest()
                        tag = b"M"
                    elif build is not None and name == "include/config/auto.conf.cmd":
                        value = kconfig_make_identity(path.read_bytes(), build[0])
                    elif build is not None and name.endswith(".cmd"):
                        # Kbuild embeds the current out-of-tree paths in make
                        # receipts. These files cannot serve as TU dependencies.
                        source, obj = build
                        data = path.read_bytes().replace(os.fsencode(source) + b"/", b"$SOURCE/")
                        data = data.replace(os.fsencode(obj) + b"/", b"$OBJECT/")
                        value = hashlib.sha256(data).hexdigest()
                    else:
                        value = file_hash(path)
                else:
                    raise ValueError("Unsupported include entry: " + name)
                entries.append((name, tag, value))
    return manifest(entries)


def verify(root, obj, config, clang):
    """Accept new driver files while requiring exactly the reviewed shared inputs."""
    try:
        root, obj, config, clang = (Path(p).resolve(strict=True) for p in (root, obj, config, clang))
        link = obj / "source"
        if not link.is_symlink() or link.resolve(strict=True) != root:
            raise ValueError("Build directory does not refer to this source tree")
        objconfig = obj / ".config"
        if objconfig.resolve(strict=True) != objconfig or file_hash(objconfig) != CONFIG or file_hash(config) != CONFIG:
            raise ValueError("Unreviewed kernel configuration")
        if file_hash(clang) != CLANG:
            raise ValueError("Unreviewed Clang binary")
        if COMPILER_ENV.intersection(os.environ) or any(key.startswith("CLANG_CONFIG_FILE_") for key in os.environ):
            raise ValueError("Clang search path or options overridden by environment")
        # Kbuild normally names the clang symlink; analysis may resolve it to
        # clang-23. Clang searches default config files for each invocation name.
        aliases = {clang}
        common = clang.parent / "clang"
        if common.is_file() and common.resolve() == clang:
            aliases.add(common)
        for binary in aliases:
            probe = ["--target=x86_64-linux-gnu", "-###", "-nostdinc", "-E", "-x", "c", os.devnull]
            baseline = subprocess.run([str(binary), "--no-default-config", *probe],
                                      cwd=obj, capture_output=True, timeout=20)
            current = subprocess.run([str(binary), *probe], cwd=obj, capture_output=True, timeout=20)
            if current.returncode or baseline.returncode or current.stderr != baseline.stderr:
                raise ValueError("Clang default configuration changes the compiler invocation")
        source = tree_inputs(root, SOURCE_PATHS)
        if source["sha256"] != SOURCE_LOCK:
            raise ValueError("Kernel API sources differ from the reviewed archive")
        generated = tree_inputs(obj, OBJECT_PATHS, (root, obj))
        if generated["sha256"] != OBJECT_LOCK:
            raise ValueError("Kbuild include or generated configuration differs from the pinned build")
        names = ("include/config/auto.conf", "include/config/auto.conf.cmd", "include/generated/autoconf.h",
                 "include/generated/compile.h", "include/generated/utsversion.h")
        return {"source": source, "generated": generated, "archive_sha256": ARCHIVE,
                "config_sha256": CONFIG, "clang_sha256": CLANG,
                "generated_files": {name: file_hash(obj / name) for name in names}}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise ValueError("Could not bind build inputs: " + str(exc)) from exc


def bind_dependencies(root, obj, source, clang, flags, cwd):
    """Collect what the same Clang invocation reads, without producing an object."""
    return _clang_dependencies(root, obj, source, clang, flags, cwd, observe_driver_headers=False)


def observe_driver_dependencies(root, obj, source, clang, flags, cwd):
    """Record private driver headers for provenance; their hashes describe the observed bytes."""
    return _clang_dependencies(root, obj, source, clang, flags, cwd, observe_driver_headers=True)


def _clang_dependencies(root, obj, source, clang, flags, cwd, *, observe_driver_headers):
    root, obj, source, clang, cwd = (Path(p).resolve(strict=True) for p in (root, obj, source, clang, cwd))
    if root / "drivers" not in source.parents or source.suffix != ".c" or not source.is_file():
        raise ValueError("Expected an in-tree driver translation unit")
    # A third-party header could redefine core layouts or change macro-based
    # contracts before pulling in the genuine declarations. This subset accepts
    # complete single-source drivers using only the measured shared headers.
    run = subprocess.run([str(clang), *flags, "-M", "-MT", "kconc_inputs", "-MF", "-", str(source)],
                         cwd=cwd, capture_output=True, timeout=120)
    if run.returncode:
        raise ValueError("Clang dependency scan failed: " + os.fsdecode(run.stderr)[-1000:])
    rule = os.fsdecode(run.stdout).replace("\\\n", " ").strip()
    target, sep, deps = rule.partition(": ")
    if target != "kconc_inputs" or not sep or "\n" in deps or "$" in deps:
        raise ValueError("Ambiguous Clang dependency list")
    resource = Path(subprocess.check_output([str(clang), "-print-resource-dir"], cwd=cwd,
                                           text=True, timeout=20).strip()).resolve(strict=True)
    resource_checked = False
    result = {}
    for pathstr in shlex.split(deps):
        path = Path(os.path.abspath(cwd / pathstr))
        real = path.resolve(strict=True)
        if path == real == source:
            key = "source/" + path.relative_to(root).as_posix()
        elif (observe_driver_headers and path == real and path.suffix == ".h" and
              root / "drivers" in path.parents and not any(root / name in path.parents for name in SOURCE_PATHS)):
            key = "driver/" + path.relative_to(root).as_posix()
        elif (path.suffix == ".h" and any(root / name in path.parents for name in SOURCE_PATHS)
              and any(root / name in real.parents for name in SOURCE_PATHS)):
            key = "source/" + path.relative_to(root).as_posix()
        elif (path == real and path.suffix == ".h" and any(obj / name in path.parents for name in OBJECT_PATHS)):
            rel = path.relative_to(obj).as_posix()
            if rel in BUILD_LABELS:
                raise ValueError("Build-label header is used by this translation unit: " + rel)
            key = "build/" + rel
        elif (path == real and path.suffix == ".h" and resource / "include" in path.parents):
            if not resource_checked:
                if tree_inputs(resource, ("include",))["sha256"] != RESOURCE_LOCK:
                    raise ValueError("Clang resource headers differ from the locked toolchain")
                resource_checked = True
            key = "clang/" + path.relative_to(resource).as_posix()
        else:
            raise ValueError("Header outside the reviewed API inputs: " + str(path))
        result[key] = file_hash(real)
    if "source/" + source.relative_to(root).as_posix() not in result:
        raise ValueError("Clang dependency list omitted the driver")
    return dict(sorted(result.items()))

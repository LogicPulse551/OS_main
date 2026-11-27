"""Make the release's pinned proof tools available for one certificate run."""
import os
import platform
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


@contextmanager
def prepared(runtime):
    """Unpack fresh tools so a previous verification cannot change provenance."""
    if runtime is None:
        # Existing developer invocations may provide their own pinned build.
        compcert = os.environ.get("KCONC_COMPCERT")
        clang = os.environ.get("KCONC_CLANG") or shutil.which("clang")
        coqc = shutil.which("coqc")
        coq_bin = os.environ.get("KCONC_COQ_BIN") or (Path(coqc).parent if coqc else None)
        if compcert and clang and coq_bin:
            yield Path(clang), Path(compcert), Path(coq_bin), dict(os.environ)
            return
        from materials import material, read_catalog
        runtime = material("proof-runtime", read_catalog())
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("本版证明工具需要 x86_64 Linux。")
    libc, version = platform.libc_ver()
    if libc == "glibc" and tuple(int(part) for part in version.split(".")[:2]) < (2, 38):
        raise ValueError("本版预构建证明工具需要 glibc 2.38 或更高版本。")
    if not shutil.which("gcc"):
        raise ValueError("CompCert 使用系统 gcc 预处理 C 源码，请先完成启动菜单的依赖预检。")
    runtime = runtime.resolve(strict=True)
    from materials import read_catalog, verify
    verify(runtime, read_catalog()["bundles"]["proof-runtime"])
    with tempfile.TemporaryDirectory(prefix="kconc-proof-") as temp:
        root = Path(temp)
        with tarfile.open(runtime / "runtime.tar", "r:") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or str(name) != member.name:
                    raise ValueError("证明工具材料包含无效路径。")
                dest = root.joinpath(*name.parts)
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError("证明工具材料包含非普通文件。")
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, dest.open("xb") as out:
                    shutil.copyfileobj(source, out, 1 << 20)
                dest.chmod(0o755 if member.mode & 0o111 else 0o644)
        coq = root / "coq"
        env = dict(os.environ)
        for key in ("COQPATH", "COQBIN", "OCAMLFIND_CONF", "CAML_LD_LIBRARY_PATH", "COMPCERT_CONFIG"):
            env.pop(key, None)
        env.update(COQLIB=str(coq / "lib/coq"), COQCORELIB=str(coq / "lib/coq-core"),
                   OCAMLPATH=str(coq / "lib"), PATH=str(coq / "bin") + os.pathsep + os.defpath)
        yield root / "llvm/bin/clang", root / "CompCert-3.13", coq / "bin", env

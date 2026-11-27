"""Locate a release's materials and verify their bytes before handing them to a runner."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "configs" / "teacher-delivery.json"


def read_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 << 20), b""):
            h.update(block)
    return h.hexdigest()


def parts(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or str(p) != name or "\\" in name:
        raise ValueError(f"材料路径不合法 {name}")
    return p.parts


def verify(root, expected):
    if not expected or not root.is_dir():
        raise ValueError(f"材料为空或目录不存在 {root}")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError(f"材料中包含特殊文件 {path}")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != set(expected):
        raise ValueError(f"材料清单不一致 {root}，缺少 {sorted(set(expected)-actual)[:3]}，额外 {sorted(actual-set(expected))[:3]}")
    for name, item in expected.items():
        path = root.joinpath(*parts(name))
        if path.stat().st_size != item["size"] or digest(path) != item["sha256"]:
            raise ValueError(f"材料校验失败 {path}")
    return root


def material(key, catalog, supplied=None, offline=False):
    release = catalog["version"]
    expected = catalog["bundles"].get(key)
    if not expected:
        raise ValueError(f"本版尚无可分发的 {key} 材料，详见运行说明。")
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "kconc" / release
    explicit = supplied or os.environ.get("KCONC_MATERIALS")
    if explicit:
        path = Path(explicit).expanduser().resolve() / key
        if path.is_symlink():
            raise ValueError(f"显式材料目录不能是符号链接 {path}")
        return verify(path, expected)
    if key == 'official-openeuler':
        from official_image import prepare
        return prepare(cache, expected, offline)
    from release_assets import hydrate
    return hydrate(key, catalog, cache, [], offline)

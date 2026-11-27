"""Hydrate one registered bundle into a versioned cache from pinned release assets."""
import gzip
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from materials import ROOT, digest, parts, verify

INDEX = ROOT / "configs/teacher-release-assets.json"
HEX = re.compile(r"[0-9a-f]{64}")
MAX_RAW = 32 << 20
BLOCK = 1 << 20


@contextmanager
def locked(file):
    # Kernel-owned advisory locks are released even when an interrupted launcher is killed.
    import fcntl
    descriptor = os.open(file, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as guard:
        if not stat.S_ISREG(os.fstat(guard.fileno()).st_mode):
            raise ValueError(f"材料锁路径不是普通文件 {file}")
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        yield


def supported_url(address):
    u = urlsplit(address)
    return (u.hostname and u.username is None and u.password is None
            and (u.scheme == "https" or (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1"))))


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not supported_url(newurl) or (urlsplit(req.full_url).scheme == "https" and urlsplit(newurl).scheme != "https"):
            raise ValueError("材料下载重定向未使用受支持的传输协议")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(address, temporary, expected, size):
    request = Request(address, headers={"User-Agent":"kconc-teacher/1", "Accept-Encoding":"identity"})
    checksum = hashlib.sha256()
    with build_opener(ReleaseRedirect).open(request, timeout=30) as response, temporary.open("wb") as output:
        left = size
        while left:
            data = response.read(min(BLOCK, left))
            if not data:
                raise OSError("连接在分块传输完成前关闭")
            output.write(data)
            checksum.update(data)
            left -= len(data)
        if response.read(1):
            raise ValueError("下载分块超过登记大小")
    if checksum.hexdigest() != expected:
        raise ValueError("下载分块摘要与仓库登记值不一致")


def asset(key, row, cache, bases, offline):
    local = ROOT
    for name in ("share", "kconc", "objects", f"kconc-{key}.gz"):
        local = local / name
        if local.is_symlink():
            raise ValueError(f"仓库材料路径包含符号链接 {local}")
    if local.exists():
        if not local.is_file() or local.stat().st_size != row["bytes"] or digest(local) != key:
            raise ValueError(f"仓库中的材料分块校验失败 {local.name}")
        return local
    dest = cache / (key + ".gz")
    with locked(cache / (key + ".lock")):
        if dest.is_symlink():
            raise ValueError("材料缓存中发现意外的符号链接")
        if dest.exists():
            if dest.is_file() and dest.stat().st_size == row["bytes"] and digest(dest) == key:
                return dest
            if offline:
                raise ValueError(f"离线缓存分块损坏 {dest.name}")
        if offline:
            raise ValueError(f"离线缓存中缺少分块 {dest.name}；首次使用请联网。")
        if not bases:
            raise ValueError("当前仓库未提供可识别的材料发布源。")
        errors = []
        with tempfile.TemporaryDirectory(dir=cache, prefix=".fetch-") as scratch:
            part = Path(scratch) / "part"
            for base in bases:
                address = f"{base.rstrip('/')}/kconc-{key}.gz"
                for attempt in range(3):
                    try:
                        download(address, part, key, row["bytes"])
                    except HTTPError as e:
                        retry = e.code in (408, 429) or e.code >= 500
                        errors.append(f"{urlsplit(base).netloc}: HTTP {e.code}")
                        e.close()
                    except (URLError, OSError, http.client.HTTPException) as e:
                        retry = True
                        errors.append(f"{urlsplit(base).netloc}: {type(e).__name__}")
                    else:
                        os.replace(part, dest)
                        return dest
                    if not retry or attempt == 2:
                        break
                    time.sleep(0.4 * (2 ** attempt))
        raise ValueError(f"未取得此版发布分块 kconc-{key}.gz（{', '.join(dict.fromkeys(errors))}）。"
                         "请确认发布附件已就绪、网络可达且具有读取权限，再运行同一入口。")


def read_index(catalog):
    data = json.loads(INDEX.read_bytes())
    if data.get("schema") != 1 or data.get("release") != catalog["version"] or data.get("codec") != "gzip":
        raise ValueError("发布分块清单与此版仓库不匹配")
    return data


def hydrate(key, catalog, cache, base_urls, offline=False):
    """Return a complete verified directory; cache names the directory for this release."""
    expected = catalog["bundles"].get(key)
    if not expected or len(parts(key)) != 1:
        raise ValueError(f"未登记材料 {key}")
    cache = Path(cache)
    dest = cache / key
    cache.mkdir(parents=True, exist_ok=True)
    with locked(cache / (key + ".lock")):
        if dest.is_symlink():
            raise ValueError(f"材料缓存目录是意外的符号链接 {dest}")
        repair = dest.exists()
        if repair:
            try:
                return verify(dest, expected)
            except ValueError:
                print(f"正在从已登记材料修复本地缓存 {key}…", file=sys.stderr)
        index = read_index(catalog)
        bases = tuple(base_urls or ())
        if any(not supported_url(base) or urlsplit(base).query or urlsplit(base).fragment for base in bases):
            raise ValueError("发布源须为 HTTPS 目录；本机回环测试可用 HTTP。")
        chunks = cache / ".chunks"
        if chunks.is_symlink():
            raise ValueError("材料分块缓存是意外的符号链接")
        chunks.mkdir(exist_ok=True)
        read = chunk_reader(index, chunks, bases, offline)
        with tempfile.TemporaryDirectory(dir=cache, prefix=".material-") as scratch:
            stage = Path(scratch) / key
            stage.mkdir()
            print(f"正在准备 {key} 的已登记材料…", file=sys.stderr, flush=True)
            for name, info in expected.items():
                file = stage.joinpath(*parts(name))
                file.parent.mkdir(parents=True, exist_ok=True)
                hashed = hashlib.sha256()
                ranges = index["files"].get(info["sha256"])
                if not isinstance(ranges, list):
                    raise ValueError(f"材料清单缺少 {name}")
                written = 0
                with file.open("xb") as writer:
                    for token, offset, length in ranges:
                        raw = read(token)
                        if not (0 <= offset <= len(raw) and 0 < length <= len(raw) - offset
                                and written + length <= info["size"]):
                            raise ValueError(f"材料分段大小不符 {name}")
                        view = memoryview(raw)[offset:offset+length]
                        writer.write(view)
                        hashed.update(view)
                        written += length
                if written != info["size"] or hashed.hexdigest() != info["sha256"]:
                    raise ValueError(f"还原文件校验失败 {name}")
            if repair:
                # Keep the bad copy available for diagnosis; swap only after full verification.
                previous = Path(tempfile.mkdtemp(prefix=".damaged-", dir=cache)) / key
                dest.rename(previous)
                try:
                    stage.rename(dest)
                except OSError:
                    previous.rename(dest)
                    raise
            else:
                stage.rename(dest)
        return dest


def chunk_reader(index, chunks, bases, offline):
    @lru_cache(maxsize=1)
    def read(token):
        row = index["chunks"].get(token)
        if (not HEX.fullmatch(token) or not isinstance(row, dict) or not HEX.fullmatch(row["raw_sha256"])
                or not (0 < row["raw_bytes"] <= MAX_RAW) or not (0 < row["bytes"] <= MAX_RAW + BLOCK)):
            raise ValueError("非法发布分块记录")
        path = asset(token, row, chunks, bases, offline)
        # Both sizes are capped. Check the raw digest as well before using any slice.
        with gzip.open(path, "rb") as archive:
            raw = archive.read(row["raw_bytes"] + 1)
        if len(raw) != row["raw_bytes"] or hashlib.sha256(raw).hexdigest() != row["raw_sha256"]:
            raise ValueError(f"解压后的分块数据不符 {path.name}")
        return raw
    return read

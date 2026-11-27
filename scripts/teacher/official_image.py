"""Download the distributor's original disk once, pinning transport and unpacked bytes."""
import hashlib
import http.client
import lzma
import os
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from materials import digest, verify
from release_assets import ReleaseRedirect, locked

NAME = "openEuler-24.03-LTS-SP3-x86_64.qcow2.xz"
RELATIVE = "openEuler-24.03-LTS-SP3/virtual_machine_img/x86_64/" + NAME
ORIGINS = ("https://mirrors.huaweicloud.com/openeuler/", "https://mirrors.nju.edu.cn/openeuler/", "https://repo.openeuler.org/")
COMPRESSED_SHA = "fff27c52fd7b9921d46c11215488737162a86e91819de2bf5a75743fabd1291f"
COMPRESSED_SIZE = 1035999712
CHUNK = 4 << 20
WORKERS = 6
NETWORK_ERRORS = (OSError, http.client.HTTPException, ValueError)


def report(message):
    print(message, file=sys.stderr, flush=True)


def response(url, extent=None, timeout=25):
    headers = {"User-Agent":"kconc/1", "Accept-Encoding":"identity"}
    if extent:
        first, last, total = extent
        headers['Range'] = f'bytes={first}-{last}'
    stream = build_opener(ReleaseRedirect).open(Request(url, headers=headers), timeout=timeout)
    if extent and (stream.status != 206 or stream.headers.get('Content-Range') != f'bytes {first}-{last}/{total}'):
        stream.close()
        raise ValueError('镜像站未返回所请求的字节范围')
    return stream


def supports_ranges(url, total):
    try:
        with response(url, (0,0,total), timeout=10) as stream:
            return len(stream.read(2)) == 1
    except NETWORK_ERRORS:
        return False


def segment(directory, urls, start, stop, total):
    path = directory / str(start)
    partial = directory / (str(start) + '.part')
    size = stop - start
    for item in (path, partial):
        if item.is_symlink() or (item.exists() and not item.is_file()):
            raise ValueError('系统映像分块缓存路径异常')
    if path.exists() and path.stat().st_size == size:
        return size
    errors = []
    for turn in range(2 * len(urls)):
        url = urls[(start // CHUNK + turn) % len(urls)]
        done = partial.stat().st_size if partial.exists() else 0
        if done >= size:
            partial.unlink()
            done = 0
        try:
            with response(url, (start+done, stop-1, total)) as src, partial.open('ab') as out:
                while done < size:
                    block = src.read(min(128 << 10, size-done))
                    if not block:
                        raise OSError('镜像分段响应提前结束')
                    out.write(block)
                    done += len(block)
            partial.replace(path)
            return size
        except NETWORK_ERRORS as exc:
            errors.append(str(exc))
    raise OSError(f'{start}-{stop-1}: ' + ' / '.join(errors))


def fetch_parts(archive, total):
    directory = archive.with_suffix('.ranges')
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ValueError('系统映像分块目录异常')
    directory.mkdir(mode=0o700, exist_ok=True)
    urls = [origin + RELATIVE for origin in ORIGINS]
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        probes = {pool.submit(supports_ranges, url, total):url for url in urls}
        ready = [probes[task] for task in as_completed(probes) if task.result()]
    if not ready:
        report('镜像站暂未支持分段传输，切换到单连接续传。')
        return False
    report(f'分段下载 {NAME}，已验证的镜像站：' + '，'.join(ready))
    starts = range(0,total,CHUNK)
    completed = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        pending = [pool.submit(segment, directory, ready, s, min(s+CHUNK,total), total) for s in starts]
        try:
            for task in as_completed(pending):
                size = task.result()
                completed += size
                if completed == total or completed // (32<<20) != (completed-size) // (32<<20):
                    report(f'官方盘分段已就绪 {completed >> 20}/{total >> 20} MiB')
        except BaseException:
            for task in pending:
                task.cancel()
            raise
    h = hashlib.sha256()
    with archive.open('wb') as combined:
        for s in starts:
            block = (directory / str(s)).read_bytes()
            h.update(block)
            combined.write(block)
    if h.hexdigest() != COMPRESSED_SHA:
        archive.unlink()
        # A bad mirror can serve wrong bytes with a valid range header. Discard that
        # session's untrusted segments before retrying from a single source.
        for s in starts:
            (directory / str(s)).unlink()
        report('多源压缩映像校验失败，重新从单个镜像获取。')
        return False
    for s in starts:
        (directory / str(s)).unlink()
    directory.rmdir()
    return True


def receive(url, archive, limit):
    offset = archive.stat().st_size if archive.exists() else 0
    headers = {"User-Agent": "kconc/1", "Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    with build_opener(ReleaseRedirect).open(Request(url, headers=headers), timeout=60) as response:
        append = response.status == 206
        if append and not response.headers.get("Content-Range", "").startswith(f"bytes {offset}-"):
            raise ValueError("镜像站返回了不同的续传位置")
        written = offset if append else 0
        with archive.open("ab" if append else "wb") as out:
            while chunk := response.read(CHUNK):
                written += len(chunk)
                if written > limit:
                    raise ValueError("压缩映像超过登记的大小上限")
                out.write(chunk)
                if written // (128 << 20) != (written - len(chunk)) // (128 << 20):
                    print(f"已取得 {written >> 20} MiB", file=sys.stderr, flush=True)


def prepare(cache, expected, offline=False):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / "official-openeuler"
    info = expected["disk.qcow2"]
    with locked(cache / "official-openeuler.lock"):
        if dest.is_symlink():
            raise ValueError("系统映像缓存不能是符号链接")
        if dest.exists():
            return verify(dest, expected)
        archive = cache / (NAME + ".partial")
        if archive.is_symlink():
            raise ValueError("下载缓存不能是符号链接")
        complete = archive.is_file() and digest(archive) == COMPRESSED_SHA
        if offline and not complete:
            raise ValueError("离线缓存中还没有此版官方系统映像。首次运行内核案例时需要联网。")
        if shutil.disk_usage(cache).free < info["size"] + (0 if complete else COMPRESSED_SIZE):
            raise ValueError(f"缓存空间不足，请为首次运行预留 {(2*info['size'] + (1<<30)-1) >> 30} GiB")
        errors = []
        if not complete:
            try:
                complete = fetch_parts(archive, COMPRESSED_SIZE)
            except NETWORK_ERRORS as exc:
                errors.append(str(exc))
                report('分段下载中断，已保留可续传的分块。尝试单连接下载。')
        for origin in ORIGINS * 2:
            if complete:
                break
            try:
                print(f"正在取得 openEuler 官方系统映像 · {origin}", file=sys.stderr, flush=True)
                receive(origin + RELATIVE, archive, COMPRESSED_SIZE)
                if archive.stat().st_size != COMPRESSED_SIZE or digest(archive) != COMPRESSED_SHA:
                    raise ValueError("压缩映像 SHA-256 与登记值不同")
                complete = True
            except HTTPError as exc:
                if exc.code == 416:
                    archive.unlink(missing_ok=True)
                errors.append(f"HTTP {exc.code}")
                exc.close()
            except (URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
                errors.append(str(exc))
            except ValueError as exc:
                archive.unlink(missing_ok=True)
                errors.append(str(exc))
            if not complete:
                time.sleep(0.5)
        if not complete:
            raise ValueError("获取官方系统映像失败，重新启动可重试。 " + " / ".join(errors))
        with tempfile.TemporaryDirectory(dir=cache, prefix=".openeuler-") as td:
            stage = Path(td) / "official-openeuler"
            stage.mkdir()
            disk = stage / "disk.qcow2"
            h = hashlib.sha256()
            size = 0
            with lzma.open(archive, "rb") as src, disk.open("xb") as out:
                while block := src.read(CHUNK):
                    size += len(block)
                    if size > info["size"]:
                        raise ValueError("解压映像超过登记大小")
                    h.update(block)
                    out.write(block)
            if size != info["size"] or h.hexdigest() != info["sha256"]:
                raise ValueError("官方系统映像解压后的字节与登记值不同")
            disk.chmod(0o444)
            stage.rename(dest)
        archive.unlink()
        return dest

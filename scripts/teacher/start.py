"""Teacher-facing entry for archived reports, fresh executions and standalone installation."""
import argparse
import datetime
import html
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from materials import CATALOG, ROOT, digest, material, read_catalog
from host import preflight

QUICK = {"update": "三个线程更新同一寄存器 · 更新丢失与修复", "ubuntu": "Ubuntu 三线程完整操作交接",
         "opt": "BMA400 六字节读取 · 核对数据与回调次数"}
FULL = {"properties": "三线程 regmap 更新丢失、互斥与修复对照", "iio-kx": "KX022A 双读者重放",
        "iio-bma": "BMA400 双读者重放", "opt-ram": "BMA400 六字节受控 RAM 计时",
        "opt-proof": "BMA400 局部正确性证书", "iio-three-kx": "KX022A 三读者重放",
        "iio-three-bma": "BMA400 三读者重放", "ubuntu": "Ubuntu 双／三线程操作级重放"}
INSTALL = {"detect": "仅并发检测", "optimize": "仅可信优化", "all": "整套工具"}


def choose(title, choices):
    print(title, flush=True)
    for n, (key, name) in enumerate(choices.items(), 1):
        print(f"  {n}. {name}  ({key})")
    while True:
        answer = input("请输入编号，回车选择第一项，q 退出 > ").strip()
        if answer.lower() == "q":
            raise SystemExit(0)
        if not answer:
            return next(iter(choices))
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return list(choices)[int(answer)-1]
        print("请输入菜单中的编号。")


def run_dir(path):
    if path:
        result = Path(path).expanduser().resolve()
    else:
        state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        result = state / "kconc" / f"{stamp}-{uuid.uuid4().hex[:8]}"
    result.mkdir(parents=True, exist_ok=False)
    return result


def show_page(path):
    if (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and shutil.which("xdg-open"):
        try:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass  # The terminal still shows the report's full path.


def current_install(mode, target):
    from install_tools import populate
    if target.is_symlink() or not (target / "install.json").is_file():
        return False
    with tempfile.TemporaryDirectory(prefix="kconc-check-install-") as tmp:
        ref = Path(tmp)
        populate(ref, mode)
        for item in ref.rglob("*"):
            relative = item.relative_to(ref)
            other = target / relative
            if other.is_symlink() or (item.is_file() and (not other.is_file() or digest(other) != digest(item))):
                return False
        return os.access(target / "bin/kconc", os.X_OK)


def overview(dest, name, catalog, case, rc, error):
    records = []
    for p in (dest / "run").rglob("*") if (dest / "run").is_dir() else ():
        if p.is_file() and not p.is_symlink() and p.suffix in (".json", ".log", ".md", ".html", ".txt"):
            records.append(p.relative_to(dest).as_posix())
    records.sort(key=lambda s: (s.count("/"), s))
    history = catalog.get("historical", {}).get(case, "见归档演示中的原始记录。")
    runner = Path(__file__).parent / catalog["cases"][case]["runner"]
    manifest = {"release":catalog["version"], "source_base_commit":catalog["base_commit"],
                "catalog_sha256":digest(CATALOG), "launcher_sha256":digest(Path(__file__)),
                "runner_sha256":digest(runner), "case":case, "exit_code":rc, "diagnostic":error,
                "historical":history,"local_records":records}
    (dest / "execution.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    from urllib.parse import quote
    links = "".join(f'<li><a href="{quote(p)}">{html.escape(p)}</a></li>' for p in records)
    primary = ""
    if "run/report.html" in records:
        primary = '<p><a href="run/report.html">查看逐线程读写、终值与本次串口记录</a></p>'
    for candidate in ("run/case_result.json", "run/result.json"):
        if candidate not in records:
            continue
        data = json.loads((dest / candidate).read_bytes())
        planned = data.get("boots_planned", data.get("planned"))
        actual = data.get("boots_started", data.get("attempted"))
        if planned is not None and actual is not None:
            primary += f'<p>计划 {html.escape(str(planned))}，本次尝试 {html.escape(str(actual))}。</p>'
        if "complete_matches" in data:
            primary += f'<p>已核对独立来宾 {len(set(data.get("guest_boot_ids", [])))} 次，完整路径匹配 {data["complete_matches"]} 次。</p>'
        if data.get("empty_callbacks"):
            counts = data["empty_callbacks"]
            primary += '<p>空回调次数（原版／只缓存指针／跳过已知空转换） ' + ' / '.join(html.escape(str(counts.get(k, "—"))) for k in ("original", "cached", "skip-noop")) + '。</p>'
        if candidate == "run/result.json" and "run/statistics.json" in records:
            stats = json.loads((dest / "run/statistics.json").read_bytes())
            pair = stats.get("comparisons", {}).get("primary")
            if pair:
                lo, hi = pair["reduction_95_pct_interval"]
                gate = "达到" if data.get("value_gate_passed") else "未达到"
                primary += f'<p>本机配对耗时降幅 {pair["reduction_percent"]:.2f}%（95% 区间 {lo:.2f}% 至 {hi:.2f}%），{gate}冻结的性能门槛。</p>'
        primary += f'<p><a href="{candidate}">本次判定及分母</a></p>'
        break
    status = "通过" if rc == 0 else "未通过"
    page = f"""<!doctype html><html lang="zh"><meta charset="utf-8"><title>{html.escape(name)}</title>
    <style>body{{font:17px/1.6 system-ui;max-width:55rem;margin:3rem auto;padding:0 1rem}}a{{color:#146357}}</style>
    <h1>{html.escape(name)}</h1><h2>本机本次运行 · {status}</h2><p>{html.escape(error)}</p>
    {primary}<details><summary>展开原始记录（{len(records)} 份）</summary><ul>{links}</ul></details><p><a href="execution.json">本次执行清单</a></p>
    <h2>项目历史记录</h2><p>{html.escape(history)}</p></html>"""
    (dest / "index.html").write_text(page, encoding="utf-8")
    print(f"本次报告 {dest / 'index.html'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="内核并发检错与可信优化 · 教师入口")
    parser.add_argument("action", choices=["demo", "quick", "reproduce", "tools"], nargs="?")
    parser.add_argument("case", nargs="?")
    parser.add_argument("--materials", help="本版配套材料的根目录")
    parser.add_argument("--offline", action="store_true", help="禁止下载")
    parser.add_argument("--install-deps", action="store_true", help="允许安装所选功能需要的主机软件")
    parser.add_argument("--output", help="本次报告使用的新目录")
    parser.add_argument("--prefix", help="独立工具安装位置")
    args = parser.parse_args()
    action = args.action or choose("内核并发检错与可信优化", {
        "demo":"查看已有离线演示", "quick":"在本机快速复现", "reproduce":"按冻结条件复现代表成果", "tools":"安装工具测试自己的驱动"})
    if action == "demo":
        if args.case:
            parser.error("demo 无需案例名。")
        archive = material("demo", read_catalog(), args.materials, args.offline) / "index.html"
        print(f"归档演示 · 用浏览器打开\n{archive}", flush=True)
        if not args.action:
            show_page(archive)
        return 0
    choices = {"quick":QUICK, "reproduce":FULL, "tools":INSTALL}[action]
    if action == "tools":
        print("openEuler 配套实验内核已验证双线程检错与修复回归；两款原生 SPI 驱动还验证了三读者窗口。")
        print("Ubuntu 测试内核已验证完整 regmap 操作之间的双／三线程交接。安装到本机后，检测工具使用你自己的设备或采集记录。")
    case = args.case or (next(iter(choices)) if args.action and action == "quick" else choose("选择内容", choices))
    if case not in choices:
        parser.error("可选项为 " + ", ".join(choices))
    if action == "tools":
        prefix = Path(args.prefix).expanduser().resolve() if args.prefix else Path.home() / ".local" / "share" / ("kconc-" + case)
        if platform.system() != "Linux":
            raise ValueError("纯工具入口面向 Linux。")
        if not args.prefix and current_install(case, prefix):
            print(f"已安装本版工具 {prefix}")
            code = 0
        else:
            code = subprocess.call([sys.executable, "-B", str(ROOT / "scripts/teacher/install_tools.py"), case, "--prefix", str(prefix)])
        if code == 0:
            print(f"可用子命令与输入格式：{prefix / 'bin/kconc'} --help")
        return code
    catalog = read_catalog()
    key = f"quick-{case}" if action == "quick" else {"properties":"full-properties","ubuntu":"full-ubuntu"}.get(case, case)
    dest = run_dir(args.output)
    rc, error = 2, ""
    try:
        route = catalog["cases"][key]
        preflight(key, bool(route.get("disk")), args.install_deps, args.offline)
        bundle = material(route["bundle"], catalog, args.materials, args.offline)
        cmd = [sys.executable, "-B", str(ROOT / "scripts/teacher" / route["runner"]), key, "--bundle", str(bundle)]
        if key == "opt-proof":
            cmd += ["--proof-runtime", str(material("proof-runtime", catalog, args.materials, args.offline))]
        if route.get("disk"):
            disk_bundle = material(route["disk"], catalog, args.materials, args.offline)
            cmd += ["--disk", str(disk_bundle / route["disk_file"])]
        cmd += ["--output", str(dest / "run")]
        print(f"开始本机实跑 · {choices[case]}\n记录目录 {dest}", flush=True)
        rc = subprocess.call(cmd)
        if rc:
            error = f"运行器退出码 {rc}，请查看本次记录。"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        error = str(exc)
        print(error, file=sys.stderr)
    overview(dest, choices[case], catalog, key, rc, error)
    if not args.action:
        show_page(dest / "index.html")
    return rc


if __name__ == "__main__":
    try:
        while True:
            code = main()
            if sys.argv[1:] or not sys.stdin.isatty():
                break
            if input("回车返回主菜单，q 退出 > ").strip().lower() == "q":
                break
        sys.exit(code)
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f"教师入口：{exc}", file=sys.stderr)
        sys.exit(2)

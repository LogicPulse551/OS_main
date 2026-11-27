"""Run fixed RAM-regmap teaching cases and render only observations from this invocation."""
import argparse
from datetime import datetime, timezone
import html
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from materials import ROOT, digest

SCRIPTS = ROOT / "scripts"
PROPERTIES = ("update-base", "update-fix", "mutex-base", "mutex-fix")


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write("\n")


def existing_runner():
    spec = importlib.util.spec_from_file_location("teacher_fixed_regmap", SCRIPTS / "regmap-three-run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stage_properties(inputs, bundle, disk, keys, runner):
    profiles = {}
    for key in keys:
        source = bundle / key
        dest = inputs / key
        dest.mkdir()
        package = read(source / "package.json")
        require(package["profile"] == key, f"wrong package {key}")
        for field, name in (("kernel", "bzImage"), ("config", "config")):
            require(package[field]["path"] == name, "unexpected artifact path")
            package[field]["path"] = str(source / name)
        for variant in ("normal", "fault" if key.endswith("base") else "fixed"):
            (dest / (variant + ".ko")).symlink_to(source / (variant + ".ko"))
        (dest / "initrd.gz").symlink_to(source / "initrd.gz")
        require(digest(dest / "initrd.gz") == package["initrd_sha256"], "initrd differs from registration")
        write(dest / "package.json", package)
        profile = dict(release=package["release"], artifacts={"bzImage": package["kernel"], ".config": package["config"]})
        runner.check_package(key, profile, dest)
        profiles[key] = profile
    registered = {read(bundle / key / "package.json")["disk_sha256"] for key in keys}
    require(registered == {digest(disk)}, "read-only disk differs from property-case registration")
    return profiles, registered.pop()


def invoke(command, output):
    with (output / "runner.log").open("xb") as log:
        return subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode


def run_properties(bundle, disk, output, quick):
    inputs = output / "inputs"
    inputs.mkdir()
    runner = existing_runner()
    keys = PROPERTIES[:2] if quick else PROPERTIES
    profiles, expected_disk = stage_properties(inputs, bundle, disk, keys, runner)
    # A relative symlink gives the original runner a comma-free disk argument
    # even if the directory selected by the user contains QEMU option separators.
    (inputs / "disk.qcow2").symlink_to(disk)
    rounds = output / "rounds"
    if quick:
        rounds.mkdir()
        write(rounds / "plan.json", dict(mode="quick", frozen=datetime.now(timezone.utc).isoformat(),
              profiles={key: read(inputs / key / "package.json")["cases"] for key in keys},
              boots_planned=2, confirmations_planned=0, disk_sha256=expected_disk,
              controls="fixed teaching fixture; three workers; no same-build stability claim"))
        boot_ids = set()
        groups = {}
        for key in keys:
            group = rounds / key
            group.mkdir()
            record = runner.observe(group / "reference", inputs / key, str(disk).replace(",", ",,"), boot_ids)
            groups[key] = dict(started=int(record["started"]), reference=record["passed"], confirmations_planned=0)
        after = digest(disk)
        write(rounds / "summary.json", dict(passed=all(g["reference"] for g in groups.values()) and after == expected_disk,
              groups=groups, distinct_boots=len(boot_ids), disk_after=after))
    else:
        profiles_path = inputs / "profiles.json"
        write(profiles_path, dict(profiles=profiles, disk="disk.qcow2", disk_sha256=expected_disk))
        command = [sys.executable, "-B", str(SCRIPTS / "regmap-three-run.py"), str(profiles_path), str(inputs), str(rounds)]
        with (output / "runner.log").open("xb") as log:
            subprocess.run(command, cwd=inputs, stdout=log, stderr=subprocess.STDOUT, check=False)
    summary = read(rounds / "summary.json")
    rows = []
    for key in keys:
        folder = rounds / key / "reference"
        if not (folder / "result.json").exists():
            continue
        record = read(folder / "result.json")
        for name, case in record["cases"].items():
            rows.append(dict(profile=key, tag=name, boot=record.get("boot_id"), kernel_id=record.get("kernel_id"),
                             path=case.get("matched"), violation=case.get("violation"), final=case.get("final"),
                             overwritten=case.get("update", {}).get("overwritten", []), passed=case["passed"],
                             report=str((folder / (name + ".html")).relative_to(output)), serial=str((folder / "serial.log").relative_to(output))))
    return dict(case="quick-update" if quick else "full-properties", source="fresh-local-qemu",
                scope="三线程固定 RAM regmap 教学用例，真实内核事件；用例内交接", passed=summary["passed"],
                boots_planned=2 if quick else 54, boots_started=sum(g["started"] for g in summary["groups"].values()),
                groups=summary["groups"], cases=rows)


def run_ubuntu(bundle, disk, output, quick):
    inputs = output / "inputs"
    inputs.mkdir()
    package = read(bundle / "package.json")
    require(package["kernel"] == "bzImage" and package["disk"] == "disk.qcow2", "wrong Ubuntu input names")
    require(digest(bundle / "regmap_central.ko") == package["module_sha256"], "Ubuntu module identity differs")
    require(digest(ROOT / "kernel/regmap-central/regmap_central.c") == package["module_source_sha256"], "Ubuntu module source differs")
    package.update(kernel=str(bundle / "bzImage"), disk=str(disk))
    write(inputs / "package.json", package)
    (inputs / "initrd.gz").symlink_to(bundle / "initrd.gz")
    rounds = output / "rounds"
    command = [sys.executable, "-B", str(SCRIPTS / "regmap-central/replay.py"),
               "--package", str(inputs), "--output", str(rounds)]
    if quick:
        command.append("--smoke")
    code = invoke(command, output)
    summary = read(rounds / "summary.json")
    cases = []
    for entry in sorted(rounds.glob("*/result.json")):
        result = read(entry)
        observed = result.get("observed", {})
        cases.append(dict(tag=entry.parent.name, boot=observed.get("boot"), kernel_id=observed.get("kernel_id"),
                          route=observed.get("actual"), path=observed.get("matched"), passed=result["passed"],
                          final=observed.get("final"), started=result["started"], report=str(entry.relative_to(output)),
                          serial=str((entry.parent / "serial.log").relative_to(output))))
    return dict(case="quick-ubuntu" if quick else "full-ubuntu", source="fresh-local-qemu",
                scope="Ubuntu 24.04 测试内核，两个或三个真实工作线程在完整 regmap 操作之间交接",
                passed=(code == 0 and summary["passed"]), boots_planned=5 if quick else 43,
                boots_started=sum(c["started"] for c in cases), groups=summary["groups"], cases=cases)


def render(output, result):
    esc = lambda value: html.escape(str(value))
    rows = []
    for case in result.get("cases", []):
        details = []
        for change in case.get("overwritten", []):
            details.append(f'{change["writer"]} 按先前读到的 {change["read_by_writer"]} 写入 {change["after_write"]}，覆盖了 {change["lost_role"]} 的更新')
        if "violation" in case:
            details.append("检测到违例" if case["violation"] else "性质通过" if case["passed"] else "证据不完整")
        elif case.get("tag", "").startswith("WRONG"):
            details.append("同终值错序对照被拒绝" if case["passed"] else "对照未通过")
        else:
            details.append(str(case.get("route") or "缺少运行证据"))
        witness = output / case["report"]
        links = []
        for title, path in (("逐步记录", witness), ("原始串口", output / case["serial"])):
            if path.is_file():
                links.append(f'<a href="{esc(path.relative_to(output).as_posix())}">{title}</a>')
        rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in
                    (esc(case.get("profile", "")) + " " + esc(case["tag"]), esc("；".join(details)),
                     esc(case.get("final")), " · ".join(links))) + "</tr>")
    note = (f'实际启动 {result.get("boots_started", 0)} / 计划 {result.get("boots_planned", "未知")} 次。'
            if "boots_planned" in result else esc(result.get("error", "")))
    markup = (f'<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>本机运行报告</title>'
              '<style>body{font:16px/1.6 system-ui;max-width:72rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse}'
              'td,th{border:1px solid #bbb;text-align:left;padding:.4rem}a{color:#174d78}</style><h1>本机运行报告</h1>'
              f'<p>{esc(result.get("scope", result["case"]))}</p><p>{"通过" if result["passed"] else "未通过"}。{note}</p>'
              '<p><a href="case_result.json">本次结果和计数</a> · <a href="rounds/plan.json">启动前计划</a></p>'
              '<table><tr><th>用例</th><th>实际观察</th><th>终读</th><th>证据</th></tr>' + "".join(rows) + '</table></html>')
    (output / "report.html").write_text(markup, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("quick-update", "quick-ubuntu", "full-properties", "full-ubuntu"))
    for name in ("bundle", "disk", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        method = run_ubuntu if args.case.endswith("ubuntu") else run_properties
        result = method(args.bundle.resolve(), args.disk.resolve(), output, args.case.startswith("quick"))
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as err:
        result = dict(case=args.case, source="fresh-local-qemu", passed=False, error=str(err))
    write(output / "case_result.json", result)
    render(output, result)
    print(output / "report.html", flush=True)
    if result.get("error"):
        print(result["error"], file=sys.stderr)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

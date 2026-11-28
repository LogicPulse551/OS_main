"""Run the registered default-lock, two-worker RAM regmap example on the local host."""
import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys

from represent import command, read, require, sha, write

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from kconc.native_regmap_two_prelock import BUILD_ID, IMAGE_HASHES, checked_capture
from kconc.regmap_two_prelock_check import PositionError, check_slot, in_symbol

OPERATION = "native.regmap-two-prelock"
CLOCK = (None, "pinned-vcpus", "cpu2-3")
FORMAL_COUNT = 20
# Each slot must match its entire frozen path. This counts all planned slots.
MIN_MATCHES = 17
REFERENCE_LIMIT = 3


def collect_boot(directory):
    serial = directory / "serial.log"
    if not serial.exists():
        return None
    ids = re.findall(r"^BOOT ([0-9a-f-]{36})$", serial.read_text(errors="replace"), re.M)
    return ids[0] if len(ids) == 1 else None


def run_slot(args, name, seen, reference=None):
    inputs = {"bundle": str(args.bundle), "disk": str(args.disk)}
    if reference:
        inputs["reference"] = str(reference)
    task = {"schema_version": 1, "operation": OPERATION, "inputs": inputs}
    manifest = args.output / "requests" / (name + ".json")
    write(manifest, task)
    directory = args.output / name
    rc = command(args.output, name, [sys.executable, "-B", ROOT / "kconc.py", "run", manifest,
                                      "--output", directory])
    envelope = read(directory / "result.json") if (directory / "result.json").is_file() else {}
    data = envelope.get("data", {})
    boot = collect_boot(directory)
    fresh = bool(boot) and boot not in seen
    if boot:
        seen.add(boot)
    row = {"name": name, "boot_id": boot, "exit_code": rc, "matched": False,
           "status": "failed" if boot else "not_booted", "diagnostic": (envelope.get("error") or {}).get("message")}
    if rc == 0:
        try:
            require(fresh and envelope.get("status") == "passed" and data.get("matched") is True,
                    "Missing distinct guest boot or CLI match")
            witness = checked_capture(directory, args.bundle / "plan.txt", "ba", *CLOCK)
            require(boot == data["boot_id"] == witness["boot_id"]
                    and witness == read(directory / "witness.json"), "Reference and guest evidence differ")
            row.update(matched=True, status="matched", tids=witness["tids"],
                       handoff_lines=witness["handoff_lines"], update_sequence=witness["update_sequence"],
                       final_read=witness["final_read"], call_lines=witness["call_lines"])
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            row["diagnostic"] = str(exc)
    elif (directory / "exit.json").is_file() and read(directory / "exit.json")["exit"] == 124:
        row["status"] = "timeout"
    elif envelope.get("error", {}) and envelope["error"]["code"] == "handoff_mismatch":
        row["status"] = "path_diverged"
    return row


def early_grant(reference, plan, out):
    """Make a labelled offline control. Source evidence and register traces stay intact."""
    out.mkdir()
    shutil.copytree(reference / "raw", out / "raw")
    shutil.copyfile(reference / "serial.log", out / "serial.log")
    native = out / "raw/native"
    events_path, words_path = native / "A.events.jsonl", native / "A.words"
    events = [json.loads(line) for line in events_path.read_bytes().splitlines()]
    words = words_path.read_bytes().splitlines(keepends=True)
    offsets = [event["word_index"] for event in events] + [len(words)]
    require(offsets[0] == 0 and offsets == sorted(set(offsets)), "Invalid source word offsets")
    blocks = [(event, words[left:right]) for event, left, right in zip(events, offsets, offsets[1:])]
    controls = [(event, block) for event, block in blocks if event["kind"] in ("WAKE", "WAIT")]
    simulated = [(event, block) for event, block in blocks if event["kind"] not in ("WAKE", "WAIT")]
    require([(event["kind"], event["flagidx"]) for event, _ in controls] == [("WAKE", 0), ("WAIT", 1)],
            "Unexpected source grant receipts")
    (start,) = [i for i, (event, _) in enumerate(simulated)
                if event["kind"] == "ENTRY" and in_symbol(event["ip"], "update")]
    simulated[start:start] = controls
    rewritten = []
    for event, block in simulated:
        event["word_index"] = len(rewritten)
        rewritten.extend(block)
    words_path.write_bytes(b"".join(rewritten))
    events_path.write_text("".join(json.dumps(event, separators=(",", ":")) + "\n" for event, _ in simulated),
                           encoding="utf-8")
    metadata = read(native / "run.json")
    require(metadata["A"]["adjacent_target_hits"] == 1, "Source witness lacks the expected control")
    metadata["A"]["adjacent_target_hits"] = 0
    write(native / "run.json", metadata)
    try:
        check_slot(out, plan, direction="ba")
    except PositionError as exc:
        reason = str(exc)
        require(reason == "A permitted before B entered regmap_update_bits_base", "Unexpected rejection: " + reason)
    else:
        raise ValueError("The checker accepted an early grant")
    original = read(reference / "witness.json")
    record = {"offline": True, "source": reference.name, "rejected": True, "reason": reason,
              "final_read": original["final_read"], "unchanged_trace_sha256": sha(out / "raw/system.trace"),
              "original_case_sha256": sha(reference / "raw/native/testcase.stdout.txt"),
              "unchanged_case_sha256": sha(out / "raw/native/testcase.stdout.txt")}
    require(record["original_case_sha256"] == record["unchanged_case_sha256"]
            and record["unchanged_trace_sha256"] == sha(reference / "raw/system.trace"), "Operation evidence changed")
    write(out / "result.json", record)
    return record


def report(out, summary):
    esc = html.escape
    slots = summary["references"] + summary["slots"]
    titles = {"matched": "完整匹配", "failed": "执行失败", "not_requested": "未请求",
              "not_booted": "来宾未启动", "timeout": "超时", "path_diverged": "路径偏离"}
    rows = []
    for slot in slots:
        name = slot["name"]
        link = f'<a href="{name}/result.json">{name}</a>' if (out/name/"result.json").is_file() else name
        rows.append(f'<tr><td>{link}</td><td>{esc(titles.get(slot["status"],slot["status"]))}</td>'
                    f'<td>{esc(slot.get("boot_id") or "—")}</td><td>{esc(slot.get("diagnostic") or "")}</td></tr>')
    sample = next((s for s in summary["references"] if s["matched"]), None)
    timeline = ""
    if sample:
        lines, calls, tids, name = sample["handoff_lines"], sample["call_lines"], sample["tids"], sample["name"]
        timeline = (f'<h2>本机参考的线程交接</h2><ol><li>线程 B（TID {tids["B"]}）进入寄存器更新。'
                    f'来宾系统轨迹第 {calls["B_enter"]} 行。</li><li>B 尚未取得默认锁，后端放行 A。控制回执第 '
                    f'{lines["permit_A"]} 行，默认锁入口第 {lines["default_lock_enter"]} 行。</li>'
                    f'<li>A（TID {tids["A"]}）读 0、写 1，在系统轨迹第 {calls["A_exit"]} 行返回。</li>'
                    f'<li>同一 B 继续读 1、写 3，在第 {calls["B_exit"]} 行返回。独立回读为 [3,0,0,0]。</li></ol>'
                    f'<p><a href="{name}/raw/system.trace">系统轨迹</a> · '
                    f'<a href="{name}/raw/native/A.events.jsonl">原后端控制事件（物理槽 A，逻辑线程 B）</a></p>')
    negative = '<a href="early-grant/result.json">终值相同、放行提前的离线对照</a>' if summary.get("negative") else ""
    document = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>双线程锁前重放</title>'
                '<style>body{font:16px/1.65 system-ui,sans-serif;max-width:72rem;margin:3rem auto;padding:0 1rem}'
                'table{border-collapse:collapse}td,th{padding:.3rem .7rem;border-bottom:1px solid #ccc;text-align:left}</style>'
                f'<h1>正常 RAM regmap 的双线程锁前重放</h1><p>本机正式冷启动 {summary["boots_started"]} 次，'
                f'共计划 {FORMAL_COUNT} 次，完整匹配 {summary["complete_matches"]} 次。参考尝试单列。</p>'
                + timeline + f'<p>{esc(summary.get("diagnostic",""))}</p><p>{negative}</p>'
                + '<table><thead><tr><th>槽位</th><th>结果</th><th>来宾启动身份</th><th>诊断</th></tr></thead>'
                + '<tbody>' + ''.join(rows) + '</tbody></table><p><a href="plan.json">启动前判据与材料身份</a></p></html>')
    (out / "report.html").write_text(document, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["ram-prelock"])
    for name in ("bundle", "disk", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.bundle, args.disk, args.output = [path.resolve() for path in (args.bundle,args.disk,args.output)]
    if args.output.is_relative_to(args.bundle) or args.output.is_relative_to(ROOT):
        parser.error("Output must be outside the repository and material bundle")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "requests").mkdir()
    slots = [{"name": f"ba-{i:02d}", "status": "not_requested"} for i in range(1, FORMAL_COUNT + 1)]
    result = {"case": args.case, "origin": "local_execution", "passed": False, "references": [],
              "slots": slots, "planned": FORMAL_COUNT, "attempted": 0, "boots_started": 0,
              "complete_matches": 0, "guest_boot_ids": []}
    seen = set()
    try:
        require(sys.platform.startswith("linux") and os.access("/dev/kvm", os.R_OK | os.W_OK),
                "需要 x86_64 Linux 和可用的 /dev/kvm。")
        require(all(Path("/usr/sbin", name).is_file() for name in ("mkfs.ext4", "debugfs")), "缺少 e2fsprogs。")
        allowed = os.sched_getaffinity(0)
        registered = {2, 4, 6, 8}
        require(registered <= allowed and bool(allowed - registered), "该配置需要可用的逻辑 CPU 2、4、6、8 和辅助 CPU。")
        cores = [Path(f"/sys/devices/system/cpu/cpu{cpu}/topology") for cpu in registered]
        require(len({((c/"physical_package_id").read_text(), (c/"core_id").read_text()) for c in cores}) == 4,
                "该配置需要将四个 vCPU 分别绑定到四个不同的物理核心。")
        checks = [ROOT/"kconc.py", ROOT/"src/kconc/cli.py", ROOT/"src/kconc/manifest.py",
                  ROOT/"src/kconc/regmap_two_prelock_check.py", ROOT/"src/kconc/prelock_vcpu_placement.py",
                  ROOT/"src/kconc/native_regmap_two_prelock.py", Path(__file__)]
        write(args.output/"plan.json", {"operation": OPERATION, "registered_build_id": BUILD_ID,
              "identities": IMAGE_HASHES, "source_sha256": {p.name: sha(p) for p in checks},
              "reference_limit": REFERENCE_LIMIT, "first_qualified_reference": True, "minimum": MIN_MATCHES,
              "slots": [s["name"] for s in slots], "direction": "ba", "require_adjacent_grant_wait_marker": True,
              "expected": ["B enters", "B grants A before lock", "A reads 0 and writes 1",
                           "A returns", "same B reads 1 and writes 3", "B returns", "read back [3,0,0,0]"]})
        write(args.output/"result.json", result)
        reference = None
        for i in range(1, REFERENCE_LIMIT + 1):
            row = run_slot(args, f"reference-{i:02d}", seen)
            result["references"].append(row)
            write(args.output/"result.json", result)
            if row["matched"]:
                reference = args.output / row["name"]
                break
        require(reference is not None, "参考尝试已用完，尚未取得完整交接。")
        write(args.output / "accepted-reference.json", {"directory": reference.name, "boot_id": row["boot_id"],
              "reference_sha256": sha(reference/"witness.json"), "plan_sha256": sha(args.output/"plan.json")})
        result["negative"] = early_grant(reference, args.bundle/"plan.txt", args.output/"early-grant")
        for slot in slots:
            slot.update(run_slot(args, slot["name"], seen, reference))
            result["attempted"] += 1
            if slot["boot_id"]:
                result["boots_started"] += 1
                result["guest_boot_ids"].append(slot["boot_id"])
            result["complete_matches"] += int(slot["matched"])
            write(args.output/"result.json", result)
        require(result["boots_started"] == FORMAL_COUNT and len(set(result["guest_boot_ids"])) == FORMAL_COUNT
                and result["complete_matches"] >= MIN_MATCHES, "本机正式批次未通过，逐槽原因见下表。")
        result["passed"] = True
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        result["diagnostic"] = str(exc)
    finally:
        write(args.output/"result.json", result)
        report(args.output, result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

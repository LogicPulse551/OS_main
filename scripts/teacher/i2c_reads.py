"""Run two normal sensor reads on a registered software I2C board."""
import argparse
from html import escape
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

from represent import require, sha, read, write
import i2c_window
import ina_clock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS / "iio-path"))
import capture
import i2c_verify

DEVICES = {
    "bma-i2c": ("BMA400", "X", "Y", "IIO 原生驱动"),
    "ads-i2c": ("ADS7828", "B", "A", "hwmon 原生驱动"),
    "ina-i2c": ("INA219", "A", "B", "hwmon 公共入口"),
}
WINDOWS = SCRIPTS.parent / "configs/scenarios/i2c-read-windows.json"
ERRORS = (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError)


def packages(bundle, disk, out, case):
    binding = read(bundle / "case.json")
    require(binding["id"] == case and (binding["planned"], binding["minimum"]) == (20, 19),
            "material registration does not match the selected case")
    require(sha(disk) == binding["disk_sha256"], "guest disk digest mismatch")
    for name, expected in binding["materials"].items():
        path = (bundle / name).resolve(strict=True)
        require(bundle in path.parents and sha(path) == expected, "material digest mismatch: " + name)
    runtime = {}
    for phase in ("ordered", "active"):
        pkg = read(bundle / (phase + ".json"))
        paths = {key:bundle / key for key in ("kernel", "vmlinux", "config")}
        paths.update(board=bundle / (phase + "-board"), disk=disk)
        for key in ("kernel", "vmlinux", "config", "board"):
            require(pkg[key+"_sha256"] == binding["materials"][paths[key].name],
                    key+" differs from the registered build")
        pkg.update({k:str(p) for k,p in paths.items()})
        pkg["host_files"] = {k:capture.fingerprint(p) for k,p in paths.items()}
        pkg["disk_sha256"] = binding["disk_sha256"]
        directory = out / ("package-" + phase)
        directory.mkdir()
        shutil.copyfile(bundle / (phase + "-initrd.gz"), directory / "initrd.gz")
        write(directory / "package.json", pkg)
        runtime[phase] = directory / "package.json"
    return runtime


def cold_boot(pkg_file, mode, slot):
    pkg = read(pkg_file)
    try:
        capture.boot(pkg_file.parent, mode, slot)
        if pkg.get("expected_driver"):
            observed = read(slot / "build.json")
            driver_id = capture.guest_id(slot / "driver.notes") if pkg["driver_ko"] else observed["kernel_build_id"]
            require(driver_id == pkg["driver_build_id"] and observed["bound_driver"] == pkg["expected_driver"],
                    "native driver identity mismatch")
            observed.update(driver_build_id=driver_id, driver_sha256=pkg["driver_sha256"])
            write(slot/"build.json", observed)
    except ERRORS as e:
        if slot.is_dir():
            write(slot/"capture-result.json", {"passed":False, "error":str(e)})
        raise
    write(slot/"capture-result.json", {"passed":True})


def classify(case, phase, slot, pkg, rules):
    if phase == "window":
        if case == "ina-i2c":
            result = ina_clock.check("active", slot, pkg, "A", rules)
        else:
            result = {"negative":{}, "matched":False}
            i2c_window.grade(case.split("-")[0], slot, pkg, result, rules)
        ref = read(WINDOWS)[case]
        if result["matched"]:
            projected = [result["witness"]["events"][i]["name"] for i in (1,2,4,6,7)]
            require(projected == [event["name"] for event in ref["events"]]
                    and result["boot_id"] != ref["natural_boot_id"],
                    "window differs from its independent natural observation")
        result["passed"] = bool(result["matched"] and result["negative"]["wrong_order_rejected"]
                                and result["negative"]["missing_receipt_rejected"])
        return result
    if case != "bma-i2c":
        judge = i2c_window.load_legacy("hwmon-i2c")
        mode = "train" if phase == "training" else "ordered"
        result = judge.check(mode, slot, read(pkg), rules)
        if phase == "training":
            return result
        rejected = {entry["group"] for entry in result["negative"] if entry["kind"] == "reversed_order"}
        result["directions"] = {order:result["ordered"].get(order, False) and index in rejected
                                for index,order in enumerate(("AB", "BA"), 1)}
        result["passed"] = all(result["directions"].values())
        return result
    args = SimpleNamespace(capture=slot, reference=rules, action="discover")
    if phase == "training":
        return i2c_verify.run(args)
    result = {"checks":{}, "directions":{}}
    for order in ("XY", "YX"):
        args.order = order
        args.keys = [order.lower()+n for n in ("1", "2")]
        checks = result["checks"][order] = {}
        for args.action in ("verify", "negative"):
            try:
                checks[args.action] = i2c_verify.run(args)
            except ERRORS as exc:
                checks[args.action] = {"passed":False, "error":str(exc)}
        result["directions"][order] = all(x["passed"] for x in checks.values())
    result["passed"] = all(result["directions"].values())
    return result


def report(out, result):
    device, owner, peer, scope = DEVICES[result["device"]]
    rows = []
    for slot in result["slots"]:
        name = slot["name"]
        links = []
        for fname, label in (("verdict.json","判定"),("trace.txt","线程和总线时间线"),("serial.log","来宾串口")):
            if (out/name/fname).is_file():
                links.append(f'<a href="{name}/{fname}">{label}</a>')
        diagnostic = slot.get("reason", "")
        rows.append(f'<tr><td>{name}</td><td>{escape(slot["status"])} {escape(diagnostic)}</td>'
                    f'<td>{escape(slot.get("boot_id") or "")}</td><td>{" · ".join(links)}</td></tr>')
    timeline = ""
    sample = next((s for s in result["slots"] if s["phase"]=="window" and s["status"]=="通过"), None)
    if sample:
        witness = read(out/sample["name"]/"verdict.json")["witness"]
        events = witness["events"]
        labels = {"i2c_read":"发起读取","board_enter":"进入软件适配器","board_exit":"适配器返回",
                  "i2c_reply":"收到总线应答","bma_enter":"进入 BMA400 驱动",
                  "driver_enter":"进入原生驱动","driver_exit":"退出原生驱动",
                  "core_enter":"进入 hwmon 公共入口"}
        event_rows = []
        for e in events:
            label = labels.get(e["name"],e["name"])
            if e["name"] == "defer_selected_reply":
                label = "暂缓本次应答" if "phase=pending" in e["detail"] else "结束等待，允许应答"
            event_rows.append(f'<tr><td>{escape(label)}</td><td>{e["tid"]}</td>'
                              f'<td>{e["ns"]-events[0]["ns"]:,}</td><td>{e["line"]}</td></tr>')
        timeline = ('<h2>一次匹配的读取</h2><p>下表为本机本次运行的同钟事件。'
                    f'<a href="{sample["name"]}/trace.txt">查看原始轨迹</a></p><table><tr><th>事件</th>'
                    '<th>线程号</th><th>相对时间（ns）</th><th>轨迹行</th></tr>'+''.join(event_rows)+'</table>')
    summary = "通过" if result["passed"] else "未通过"
    n_window = sum(s["phase"] == "window" for s in result["slots"])
    n_ordered = sum(s["phase"] == "ordered" for s in result["slots"])
    metrics = f'应答窗口匹配 {result.get("window_matches",0)}/{n_window} 次独立冷启动。'
    if n_ordered and "directions_matched" in result:
        directions = "、".join(f'{escape(d)} {n}/{n_ordered}' for d,n in result["directions_matched"].items())
        metrics += f'完整读取顺序为 {directions}。每个来宾分别读取两个方向。'
    page = (f'<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>{device} 读取重放</title>'
            '<style>body{font:16px system-ui;max-width:66rem;margin:3rem auto;padding:0 1rem}'
            'th,td{text-align:left;padding:.5rem;border-bottom:1px solid #ddd}</style>'
            f'<h1>{device} · 本机读取重放</h1><p>软件适配器等待应答时，线程 {peer} 进入{scope}。'
            f'检查器按同一来宾时钟核对线程 {owner} 的请求、等待回执、线程 {peer} 的入口和应答。</p>'
            f'<p>本次{summary}。{metrics}</p>'
            f'<p>{escape(result.get("diagnostic",""))}</p>'+timeline+'<h2>全部采样</h2><table><tr><th>采样</th><th>判定</th>'
            '<th>启动标识</th><th>本次记录</th></tr>'+''.join(rows)+'</table></html>')
    (out/"report.html").write_text(page,encoding="utf-8")


def run(args):
    case = args.case.removeprefix("quick-")
    quick = args.case.startswith("quick-")
    owner = DEVICES[case][1]
    slots = []
    def add(phase, mode, name):
        slots.append({"phase":phase, "mode":mode, "name":name, "status":"未启动"})
    if not quick:
        add("training", "train", "training")
        for i in range(20):
            mode = ("xy-first","yx-first")[i % 2] if case == "bma-i2c" else "ordered"
            add("ordered",mode,f"ordered-{i+1:02d}")
    for i in range(1 if quick else 20):
        add("window","active-"+owner,f"window-{i+1:02d}")
    result = {"case":args.case,"device":case,"origin":"local_execution","passed":False,
              "boots_planned":len(slots),"attempted":0,"guest_boot_ids":[],"slots":slots}
    out = args.output
    out.mkdir(parents=True,exist_ok=False)
    try:
        runtime = packages(args.bundle,args.disk,out,case)
        write(out/"plan.json",{"case":args.case, "device":DEVICES[case][0], "slots":slots,
              "natural_reference":read(WINDOWS)[case],"natural_register_sha256":sha(WINDOWS),
              "minimum_per_direction":0 if quick else 19,"minimum_windows":1 if quick else 19,
              "registered_packages":{p:sha(f) for p,f in runtime.items()},
              "window":{"owner":owner,"peer":DEVICES[case][2],"peer_entry":DEVICES[case][3],
                        "test":"pending < peer entry < done; reject reordered entry and missing receipt"}})
        rules = out/"training"/"verdict.json"
        seen = set()
        for slot in slots:
            phase = slot["phase"]
            if not quick and phase != "training" and slots[0]["status"] != "通过":
                slot["reason"] = "训练未取得可用规则"
                continue
            path = out/slot["name"]
            pkg = runtime["active" if phase == "window" else "ordered"]
            result["attempted"] += 1
            try:
                cold_boot(pkg, slot["mode"], path)
                boot = read(path/"build.json")["boot_id"]
                require(boot not in seen, "duplicate guest boot ID")
                verdict = classify(case,phase,path,pkg,rules)
                write(path/"verdict.json", verdict)
                if phase == "training":
                    require(verdict.get("seal") or verdict.get("certificate_sha256"), "unsealed discovery")
                else:
                    slot["directions"] = verdict.get("directions", {})
                    require(verdict["passed"], "path or negative check did not match")
                slot["status"] = "通过"
            except ERRORS as exc:
                slot.update(status="未通过", reason=str(exc))
            log = path/"serial.log"
            serial = log.read_text(errors="replace").replace("\r","") if log.is_file() else ""
            boot_ids = re.findall(r"^BOOT ([0-9a-f-]{36})$", serial, re.M)
            slot["boot_id"] = boot_ids[0] if len(boot_ids)==1 else None
            if slot["boot_id"]:
                seen.add(slot["boot_id"])
                result["guest_boot_ids"].append(slot["boot_id"])
            write(out/"case_result.json", result)
        both = ("XY","YX") if case == "bma-i2c" else ("AB","BA")
        result["directions_matched"] = {d:sum(bool(s.get("directions",{}).get(d)) for s in slots) for d in both}
        result["window_matches"] = sum(s["phase"]=="window" and s["status"]=="通过" for s in slots)
        result["distinct_boots"] = len(seen)
        result["passed"] = (len(seen)==len(slots) and result["window_matches"] >= (1 if quick else 19)
                            and (quick or all(n>=19 for n in result["directions_matched"].values())))
    except ERRORS as e:
        result["diagnostic"] = str(e)
    write(out/"case_result.json", result)
    report(out,result)
    print(json.dumps({k:v for k,v in result.items() if k not in ("slots","guest_boot_ids")}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=[*DEVICES, "quick-bma-i2c"])
    for name in ("bundle","disk","output"):
        parser.add_argument("--"+name, type=lambda s:Path(s).resolve(), required=True)
    args = parser.parse_args()
    if args.bundle in (args.output, *args.output.parents):
        parser.error("output must be outside the bundle")
    sys.exit(run(args))

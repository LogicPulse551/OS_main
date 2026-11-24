"""Run fixed three-thread RAM regmap candidates against pre-registered local kernel builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from kconc.regmap_three_check import parse, replay, write_html


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def one(pattern, text):
    values = re.findall(pattern, text, re.M)
    if len(values) != 1:
        raise ValueError(f"expected one {pattern}, observed {len(values)}")
    return values[0]


def check(ok, why):
    if not ok:
        raise ValueError(why)


def check_package(key, profile, directory):
    package = read(directory / "package.json")
    prop, revision = key.split("-")
    variants = ("normal", "fault" if revision == "base" else "fixed")
    cases = [[prop, variant, order] for variant in variants for order in ("ABC", "ACB")]
    check(package["profile"] == key and package["cases"] == cases, "wrong fixture profile or cases")
    for label, artifact in (("kernel", "bzImage"), ("config", ".config")):
        expected = profile["artifacts"][artifact]
        check(package[label] == expected and sha(expected["path"]) == expected["sha256"],
              f"{key} {artifact} differs from independent registration")
    for variant in variants:
        check(sha(directory / (variant + ".ko")) == package["modules"][variant]["sha256"],
              f"{key} {variant} module differs from package")
    check(package["release"] == profile["release"], "kernel release differs from registration")
    check(sha(ROOT / "kernel/regmap-three-check/regmap_three_check.c") == package["source_sha256"],
          "fixture source differs from compiled version")
    check(sha(ROOT / "kernel/regmap-three-check/observe.sh") == package["observer_sha256"],
          "guest observer differs from packaged version")


def note_id(hex_notes):
    notes = bytes.fromhex(hex_notes)
    pos = 0
    while pos + 12 <= len(notes):
        n, d, kind = struct.unpack_from("<III", notes, pos)
        pos += 12
        name = notes[pos:pos + n]
        pos += (n + 3) & ~3
        value = notes[pos:pos + d]
        pos += (d + 3) & ~3
        if name == b"GNU\0" and kind == 3 and len(value) == 20:
            return value.hex()
    raise ValueError("guest has no GNU build ID")


HEADER = r"^CASE_BEGIN (update|mutex) (normal|fault|fixed) (ABC|ACB)$"
TRACE = re.compile(r"-(\d+)\s+\[\d+\].*?regmap_reg_(read|write):\s+tri_regmap_ram\s+reg=0 val=([\da-fA-F]+)\s*$", re.M)
LOCK = re.compile(r"FIXTURE_(HELD|CONTENDED|UNLOCKED) role=([ABC]) tid=(\d+)")


def evaluate_case(text, request, package, kernel_id):
    prop, variant, order = request
    result = parse(text, *request)
    check(result["complete"], result["diagnostic"])
    m = package["modules"][variant]
    check(one(r"^([0-9a-f]{64})  "+variant+r"\.ko$", text) == m["sha256"], "loaded module hash differs")
    check(one(r"^PARAMS (.+)$", text) == " ".join(request), "accepted parameters differ")
    module_id = note_id(one(r"^MODNOTES ([0-9a-f]+)$", text))
    check(module_id == m["elf_id"], "loaded module build differs")
    bus = [(int(t), k.upper(), int(v, 16)) for t, k, v in TRACE.findall(text)]
    actual = [(e["tid"], e["kind"], e["value"]) for e in result["events"] if e["kind"] in ("READ", "WRITE")]
    expected_bus = [(result["reader_tid"], "READ", 0), *actual, (result["reader_tid"], "READ", result["final"])]
    check(bus == expected_bus, f"regmap tracepoint series mismatch: {bus!r} expected {expected_bus!r}")
    stats = re.findall(r"^BUFFER (?:overrun|commit overrun|dropped events):\s*(\d+)$", text, re.M)
    check(len(stats) == 12 and set(stats) == {"0"}, "incomplete or lossy per-CPU tracing")
    locks = LOCK.findall(text)
    expected_locks = [("HELD", "A"), ("CONTENDED", order[1]), ("CONTENDED", order[2]), ("UNLOCKED", "A")]
    if variant == "fixed":
        check([(k, r) for k, r, t in locks] == expected_locks, "shared-guard contention sequence differs")
        check(all(result["role_tids"][r] == int(t) for k, r, t in locks), "contention owner differs")
    else:
        check(not locks, "unexpected fixture lock events")
    result.update(build=[kernel_id, module_id, m["sha256"]], bus=bus, lock_receipts=locks)
    result["expected_property"] = result["violation"] == (variant == "fault")
    result["passed"] = result["matched"] and result["expected_property"]
    return result


def observe(folder, pkgdir, disk, boot_ids, reference=None):
    folder.mkdir()
    p = read(pkgdir/"package.json")
    argv = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-smp", "4", "-m", "3072",
            "-no-reboot", "-nodefaults", "-display", "none", "-monitor", "none",
            "-serial", "file:"+str(folder/"serial.log"), "-kernel", p["kernel"]["path"],
            "-initrd", str(pkgdir/"initrd.gz"), "-append", "console=ttyS0 panic=-1 loglevel=3",
            "-drive", "file="+disk+",format=qcow2,if=virtio,readonly=on"]
    save(folder/"launch.json", dict(argv=argv, package_sha256=sha(pkgdir/"package.json"),
                                   reference_sha256=sha(reference) if reference else None,
                                   started=datetime.now(timezone.utc).isoformat()))
    answer = dict(started=False, passed=False, cases={})
    try:
        check(sha(p["kernel"]["path"]) == p["kernel"]["sha256"] and
              sha(pkgdir/"initrd.gz") == p["initrd_sha256"], "prelaunch content differs")
        with (folder/"qemu.log").open("xb") as f:
            with subprocess.Popen(argv, stdout=f, stderr=subprocess.STDOUT) as qemu:
                answer["started"] = True
                try:
                    answer["exit"] = qemu.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    qemu.kill()
                    qemu.wait()
                    raise
        text = (folder/"serial.log").read_text(errors="replace").replace("\r","")
        boot = one(r"^TRIBOOT ([a-f0-9-]{36}) readonly=1$", text)
        check(boot not in boot_ids, "boot ID reused")
        boot_ids.add(boot)
        answer["boot_id"] = boot
        k = note_id(one(r"^KERNELNOTES ([0-9a-f]+)$", text))
        check(k == p["kernel_id"], "wrong live kernel")
        answer["kernel_id"] = k
        check(answer["exit"] == 0 and re.search(r"^(IIO|K14)_SUPERVISOR_EXIT 0$",text,re.M)
              and "SUITE_CLEAN" in text, "guest suite or teardown incomplete")
        headers = list(re.finditer(HEADER, text, re.M))
        check([list(h.groups()) for h in headers] == p["cases"], "different cases or sequence")
        refcases = read(reference)["cases"] if reference else None
        for idx, h in enumerate(headers):
            name = "-".join(h.groups())
            block = text[h.end():headers[idx+1].start() if idx+1 < len(headers) else len(text)]
            try:
                one(r"^(CASE_END)$", block)
                result = evaluate_case(block, h.groups(), p, k)
                if refcases is not None:
                    r = refcases[name]
                    result["comparison"] = replay(r, result, r["build"], result["build"])
                    result["passed"] &= result["comparison"]["matched"]
                if reference is None:
                    write_html(folder/(name+".html"), result)
            except Exception as err:
                result = dict(passed=False, error=repr(err))
            answer["cases"][name] = result
        answer["passed"] = all(v["passed"] for v in answer["cases"].values())
    except Exception as err:
        answer["error"] = repr(err)
    save(folder/"result.json", answer)
    return answer


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profiles", type=Path)
    ap.add_argument("packages", type=Path)
    ap.add_argument("destination", type=Path)
    ap.add_argument("--pilot", action="store_true")
    args = ap.parse_args()
    p = read(args.profiles)
    root = args.destination.resolve()
    check(not root.is_relative_to(ROOT) and not ROOT.is_relative_to(root), "results belong outside the repository")
    root.mkdir()
    profiles = list(p["profiles"])
    check(set(profiles) == {"update-base", "update-fix", "mutex-base", "mutex-fix"},
          "registered profiles must include each original and repair build")
    for key in profiles:
        check_package(key, p["profiles"][key], args.packages/key)
    disk = p["disk"]
    check(sha(disk) == p["disk_sha256"], "original read-only disk hash differs")
    def count(key):
        return 0 if args.pilot else 20 if key.endswith("-base") else 5
    plan = {key:dict(cases=read(args.packages/key/"package.json")["cases"],
                     package_sha256=sha(args.packages/key/"package.json"),
                     reference=1, confirmations=count(key), minimum=0 if args.pilot else 19 if key.endswith("-base") else 5)
            for key in profiles}
    save(root/"plan.json", dict(frozen=datetime.now(timezone.utc).isoformat(), profiles=plan,
                               matching="identity+reset+3 distinct TIDs+ordered 12 events incl values+8 native regmap bus receipts+readback+cleanup; fixed additionally checks actual contention; fresh boot per round; one reference precondition",
                               read_only_disk_sha256=p["disk_sha256"], pilot=args.pilot,
                               runner_sha256=sha(__file__), evaluator_sha256=sha(ROOT/"src/kconc/regmap_three_check.py")))
    ids, groups = set(), {}
    for key in profiles:
        group = root/key
        group.mkdir()
        pkg = (args.packages/key).resolve()
        r = observe(group/"reference", pkg, disk, ids)
        table = {("-".join(c)):0 for c in plan[key]["cases"]}
        groups[key] = dict(reference=r["passed"], started=int(r["started"]), matched=table, confirmations_planned=count(key))
        print(key, "reference", r["passed"], r.get("error") or [v.get("error") for v in r["cases"].values() if not v["passed"]], flush=True)
        if r["passed"]:
            ref = group/"reference/result.json"
            frozen = sha(ref)
            save(group/"frozen-reference.json", dict(result_sha256=frozen,boot_id=r["boot_id"],plan_sha256=sha(root/"plan.json")))
            for n in range(1, count(key)+1):
                check(sha(ref)==frozen,"frozen reference changed")
                z = observe(group/f"confirm-{n:02}", pkg, disk, ids, ref)
                groups[key]["started"] += int(z["started"])
                for name in table: table[name] += int(z["cases"].get(name,{}).get("passed",False))
                print(key,n,z["passed"],flush=True)
    after = sha(disk)
    passed = (after==p["disk_sha256"] and all(g["reference"] and all(n>=plan[k]["minimum"] for n in g["matched"].values()) for k,g in groups.items()))
    save(root/"summary.json",dict(passed=passed,groups=groups,distinct_boots=len(ids),disk_after=after))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

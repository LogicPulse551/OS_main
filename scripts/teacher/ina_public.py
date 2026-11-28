"""Check INA219 public hwmon entry against an identified, outstanding I2C request."""
import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT.parent



def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hw = load("hwmon_path_judge", SCRIPTS / "hwmon-i2c/judge.py")
clock = load("i2c_global_judge", ROOT / "i2c_window.py")


def before(a, b):
    return a.line < b.line and a.ns < b.ns


def active_chain(records, owner, peer, phases):
    req = owner["transfers"][0]["events"]
    peer_req = peer["transfers"][0]["events"]
    seen = phases["seen"]
    seq, reg, tid = [int(seen[k]) for k in ("seq", "reg", "tid")]
    hw.require((seq, reg, tid) == (1, owner["shape"][0][1], owner["tid"]), "wrong owner or transaction")
    marks = clock.identify_control(records, seq, reg, tid)
    chain = [owner["driver_enter"], req[2], req[3], marks["pending"], peer["core_enter"],
             marks["done"], req[4], req[5], owner["driver_exit"], peer["driver_enter"]]
    hw.require(all(before(a,b) for a,b in zip(chain,chain[1:])), "wrong global order")
    hw.require(before(req[5], peer_req[2]), "overlapping I2C transactions")
    return {"seq":seq,"reg":reg,"tid":tid,"events":[asdict(e) for e in chain],
            "ends":[asdict(x["end"]) for x in (owner,peer)]}


def check(mode, cap, pkgfile, role, rules):
    pkg = json.loads(pkgfile.read_bytes())
    active = mode == "active"
    base = hw.check(mode, cap, pkg, rules, role)
    meta = json.loads((cap / "build.json").read_bytes())
    hw.require(pkg["phase"] == ("active" if active else "passive"), "wrong package type")
    hw.require(meta["bound_driver"] == "ina2xx" and meta["hwmon_name"] == "ina219" and
               meta["board_module"] == "ina219_i2c_board" and meta["driver_symbol"] == "ina2xx_read" and
               meta["core_symbol"] == "hwmon_attr_show" and meta["i2c_client"] == "0-0040" and
               (meta["channel_a"], meta["channel_b"]) == ("in0_input","in1_input"), "wrong bound INA219 fixture")
    hw.require((cap/"driver.notes").is_file() and hw.guest_id(cap/"driver.notes") == pkg["driver_build_id"],
               "missing native driver identity")
    plan = json.loads((cap/"plan.json").read_bytes())
    hw.require(plan["package_sha256"] == hw.digest(pkgfile) and plan["mode"] == meta["mode"],
               "different prelaunch package or mode")
    groups = base["groups"]
    records = hw.read_trace(cap,groups)
    probes = (cap/"probes.txt").read_text()
    for k in ("core_enter","core_exit"):
        arr = re.findall(r"^\s*(?:\S+[:/])?"+k+r"\s+(\d+)\s+(\d+)\s*$",probes,re.M)
        hw.require(len(arr)==1 and int(arr[0][0])>=groups*2 and int(arr[0][1])==0,"missed core probe")
    stats = Counter()
    hits = []
    result = {"valid":True,"matched":False,"clock":"global","boot_id":base["boot_id"],"groups":groups,
              "kernel_build_id":meta["kernel_build_id"],"board_build_id":meta["board_build_id"],
              "driver_build_id":pkg["driver_build_id"],"capture_sha256":base["capture_sha256"],"hits":hits}
    for g in range(1,groups+1):
        pair = {}
        for ch in ("A","B"):
            rec = records[g,ch]
            info = hw.features(rec,meta)
            info["core_exit"] = hw.one(rec,"core_exit")
            for name in ("core_enter","core_exit"):
                e=hw.one(rec,name)
                hw.require(re.search(r"\bhwmon_attr_show\b",e.detail) and e.tid==info["tid"],"wrong hwmon frame")
            hw.require(len(info["transfers"])==1 and info["value"]==4 and
                       info["core_enter"].line<info["driver_enter"].line<info["driver_exit"].line<info["core_exit"].line,
                       "wrong core/driver nesting or voltage")
            pair[ch]=info
        for who,other in (("A","B"),("B","A")):
            if active and who!=role:
                continue
            a,b=pair[who],pair[other]
            req=a["transfers"][0]["events"]
            if before(a["driver_enter"], b["core_enter"]) and before(b["core_enter"],a["driver_exit"]):
                stats["peer_core_entry_during_owner_driver"]+=1
            if before(b["core_enter"],req[3]) and before(req[4],b["core_exit"]):
                stats["peer_already_in_core_across_board"]+=1
            if hw.matching_window(a,b,"driver_enter"):
                stats["peer_driver_entry_in_board"]+=1
            w=hw.matching_window(a,b,"core_enter")
            if w and before(a["driver_exit"],b["driver_enter"]):
                hits.append({"group":g,"owner":who,"peer":other,"owner_tid":a["tid"],"peer_tid":b["tid"],
                             "selector":a["shape"][0][1],"events":[asdict(e) for e in w],
                             "owner_driver_exit":asdict(a["driver_exit"]),"peer_driver_enter":asdict(b["driver_enter"]),
                             "returns":[a["value"],b["value"]]})
            if active:
                raw=clock.events((cap/"trace.txt").read_text().splitlines())
                phases=base["control"]
                n={}
                result["negative"]=n
                try:
                    result["witness"]=active_chain(raw,a,b,phases)
                    result["matched"]=True
                except ValueError as exc:
                    result["error"]=str(exc)
                late=b.copy()
                late["core_enter"]=replace(b["core_enter"],line=req[5].line+1,ns=req[5].ns+1)
                n["wrong_order_rejected"],n["wrong_order_reason"]=clock.rejected(
                    lambda:active_chain(raw,a,late,phases),"wrong global order")
                for phase in ("pending","done"):
                    copy=[e for e in raw if not e.detail.startswith("KCONC_I2C_CTRL phase="+phase+" ")]
                    ok,why=clock.rejected(lambda:active_chain(copy,a,b,phases),"missing "+phase)
                    n["missing_"+phase+"_rejected"]=ok and len(copy)+1==len(raw)
                    n["missing_"+phase+"_reason"]=why
                n["missing_receipt_rejected"]=n["missing_pending_rejected"] and n["missing_done_rejected"]
                n["unchanged_returns"]=[asdict(x["end"]) for x in (a,b)]
    hits.sort(key=lambda h:h["events"][2]["line"])
    result["observations"]={k:stats[k] for k in ("peer_core_entry_during_owner_driver",
                                 "peer_already_in_core_across_board","peer_driver_entry_in_board")}
    if not active:
        result["matched"]=bool(hits)
    return result

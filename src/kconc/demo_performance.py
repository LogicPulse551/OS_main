"""Recompute the paired comparison from unrounded batches in the recorded guests."""
import json

from .competition_demo import require


ARMS = {"original": "reference", "cached": "cached", "skip-noop": "optimized"}
IDENTITY_CHECKS = {"build_id", "release", "config", "cpu", "disk", "kernel", "cmdline", "no_initrd", "distribution"}


def _builds(ev, cert, functional):
    receipt = ev.json("build/result.json")
    require(receipt["passed"] is True, "Performance build audit failed")
    identities = {}
    configs, tools, harnesses = set(), set(), set()
    for label, arm in ARMS.items():
        name = "build/" + arm + ".json"
        identity = ev.json(name)
        source = ev.json("build/" + arm + "-source.json")
        parent = "optimized" if arm == "optimized" else "reference"
        expected = cert["emitted_sha256"][parent]
        require(receipt["variants"][arm]["sha256"] == ev.files[name]
                and identity["source_manifest"]["sha256"] == ev.files["build/" + arm + "-source.json"]
                and identity["source_sha256"] == source["source_sha256"] and identity["variant"] == source["variant"] == arm
                and identity["timing_build"] is True and identity["observer_enabled"] is False
                and identity["certificate_sha256"] == source["certificate_sha256"] == functional["source_certificate"]
                and identity["parent_source_sha256"] == source["parent_sha256"] == expected
                and (source["control_only"] is True if arm == "cached" else source["prefix_sha256"] == expected),
                "Unbound timing build: " + arm)
        require(identity["gnu_build_id"] not in functional["loaded_builds"].values(), "Functional observer kernel used for timing")
        configs.add(identity["config_sha256"]); tools.add((identity["compiler_sha256"],identity["source_commit"],identity["llvm_commit"]))
        harnesses.add(source["harness_sha256"])
        identities[label] = identity
    require(len(configs) == len(tools) == len(harnesses) == 1 and configs == {cert["inputs"]["config"]}
            and len({i["gnu_build_id"] for i in identities.values()}) == 3, "Three-arm comparison identity mismatch")
    return identities


def _read_timing_slot(ev, slot, identity, directory, round_id, arm):
    def attached(name):
        path = directory + name
        value = ev.json(path)
        require(ev.files[path] == slot["artifact_sha256"][name], "Changed slot artifact: " + name)
        return value
    live = attached("loaded-identity.json")
    stop = attached("last-stop.json")
    raw = attached("time.json")
    require(slot["formal"] is True and slot["variant"] == arm and slot["build_identity_sha256"] == ev.files["build/"+ARMS[arm]+".json"]
            and slot["passed"] is True and slot["clean_stop"] is True and not slot["errors"]
            and live["passed"] is True and set(live["checks"]) == IDENTITY_CHECKS and all(v is True for v in live["checks"].values())
            and live["guest_build_id"] == slot["gnu_build_id"] == identity["gnu_build_id"]
            and live["bzimage_sha256"] == identity["files"]["arch/x86/boot/bzImage"]["sha256"]
            and stop["process_exit_observed"] and stop["qmp_shutdown_confirmed"] and stop["qmp_shutdown_event"]["data"]["guest"],
            "Timing slot lacks loaded identity or shutdown")
    require(slot["modes"]["time"]["sha256"] == ev.files[directory+"time.json"] and slot["modes"]["time"]["exit_code"] == 0
            and raw["action"] == "time" and raw["passed"] is True and not raw["kernel_warnings"], "Unverified guest timing")
    for state in (raw["observers_before"],raw["observers_after"]):
        require(state["tracing_on"] == "0" and state["tracer"] == "nop" and not state["kprobe_events"].strip()
                and state["events_enabled"] == "0" and not state["perf_pids"], "Observer active during timing")
    measurement = raw["results"]
    require(json.loads(raw["results_raw"]) == measurement
            and measurement["mode"] == "bench" and (measurement["calls"],measurement["warmups"],measurement["samples"]) == (20000,2,4)
            and len(measurement["rows"]) == 6, "Unexpected measurement parameters")
    rows=[]
    for index, item in enumerate(measurement["rows"]):
        warmup = index < 2
        sample = index if warmup else index-2
        require(item["warmup"] == int(warmup) and item["sample"] == sample and item["cycles"] == 20000
                and item["result"] == 0 and item["bus_reads"] == 60000 and item["cpu_start"] == item["cpu_end"] == 2,
                "Invalid pinned six-byte timing batch")
        rows.append(dict(round=round_id, variant=arm, phase="warmup" if warmup else "measured",
                         batch=sample+1, calls=item["cycles"], elapsed_ns=item["elapsed_ns"]))
    return live["guest_boot_id"], rows


def _profiles(ev, preflight, identities):
    slots = [p.replace("\\", "/").split("/")[-2] for p in preflight["slots"]]
    require(slots == list(ARMS), "Unexpected functional preflight order")
    profiles = {}
    for arm in slots:
        prefix = f"perf/preflight/{arm}/"
        slot = ev.json(prefix + "slot.json")
        require(slot["passed"] and slot["clean_stop"] and not slot["formal"] and not slot["errors"]
                and slot["variant"] == arm and slot["protocol_sha256"] == ev.files["perf/protocol.json"]
                and slot["build_identity_sha256"] == ev.files["build/" + ARMS[arm] + ".json"], "Preflight receipt mismatch")
        live = ev.json(prefix + "loaded-identity.json")
        check = ev.json(prefix + "check.json")
        profile = ev.json(prefix + "profile.json")
        for name in ("loaded-identity.json", "check.json", "profile.json"):
            require(ev.files[prefix+name] == slot["artifact_sha256"][name], "Preflight artifact mismatch")
        cases = check["results"]["checks"]
        require(live["passed"] and live["guest_build_id"] == slot["gnu_build_id"] == identities[arm]["gnu_build_id"]
                and set(live["checks"]) == IDENTITY_CHECKS and all(live["checks"].values())
                and check["action"] == "check" and check["passed"] and len(cases) == 8
                and {(r["bits"],r["fail_at"]) for r in cases} == {(b,f) for b in (8,16) for f in range(4)}
                and all(r["result"] == 0 for r in cases), "Functional preflight mismatch")
        require(profile["action"] == "profile" and profile["passed"] and profile["bulk_calls"] == 16
                and profile["noop_calls"] == (0 if arm == "skip-noop" else 96), "Private entry or callback count mismatch")
        profiles[arm] = dict(cases=len(cases), bulk_calls=profile["bulk_calls"], noop_calls=profile["noop_calls"])
    return profiles


def measured_performance(ev, cert, functional, summarize):
    identities = _builds(ev, cert, functional)
    protocol = ev.json("perf/protocol.json")
    plan = ev.json("perf/planned.json")
    freeze = ev.json("perf/freeze.json")
    preflight = ev.json("perf/preflight.json")
    ledger = ev.json("perf/ledger.json")
    require(freeze["formal_boots"] == freeze["preflight_boots"] == 0
            and ev.files["perf/protocol.json"] in freeze["sha256"].values()
            and plan["preflight_sha256"] == ev.files["perf/preflight.json"] and preflight["passed"] is True
            and preflight["formal_samples"] == 0 and len(preflight["slots"]) == 3
            and ledger["inputs_unchanged"] is True and protocol["arm_to_identity"] == ARMS, "Measurement registration mismatch")
    order=[[r, arm] for r, arms in enumerate(protocol["boot_orders"],1) for arm in arms]
    require(order == plan["slots"] == [[s["round"],s["variant"]] for s in ledger["slots"]], "Missing or reordered launch slots")
    rows=[]; boots=set(); failed=False
    for s in ledger["slots"]:
        r, arm = s["round"], s["variant"]
        if s["status"] == "not_executed_after_failure":
            require(failed, "Slot skipped before any failure")
            continue
        require(not failed, "Additional attempts after failure")
        directory=f"perf/r{r:02}-{arm}/"
        slot=ev.json(directory+"slot.json")
        require(ev.files[directory+"slot.json"] == s["sha256"] and slot["protocol_sha256"] == ev.files["perf/protocol.json"],
                "Slot receipt or protocol mismatch")
        if s["status"] == "failed":
            require(slot["passed"] is False, "Failed slot mismatch")
            failed=True
            continue
        require(s["status"] == "valid", "Unknown slot status")
        boot, batch_rows = _read_timing_slot(ev,slot,identities[arm],directory,r,arm)
        require(boot and boot not in boots, "Duplicate or missing boot ID")
        boots.add(boot); rows.extend(batch_rows)
    require(ledger["passed"] is (not failed) and len(rows) == ledger["rows"], "Incomplete ledger")
    timing = summarize(rows,protocol["boot_orders"])
    timing["preflight"] = _profiles(ev,preflight,identities)
    return timing, {arm:v["gnu_build_id"] for arm,v in identities.items()}

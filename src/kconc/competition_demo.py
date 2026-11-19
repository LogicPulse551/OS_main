"""Connect a saved regmap run, its repair, and the separate BMA400 optimization case."""
from difflib import unified_diff
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from .bma400_performance import summarize
from .report_html import render_report


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Evidence:
    def __init__(self, bundle):
        self.root = bundle.resolve(strict=True).parent
        self.manifest = json.loads(bundle.read_bytes())
        require(self.manifest["kind"] == "kconc.regmap-demo" and self.manifest["schema"] == 1, "Unknown demo bundle")
        self.files = self.manifest["files"]
        for name, expected in self.files.items():
            path = PurePosixPath(name)
            require(path.as_posix() == name and not path.is_absolute() and ".." not in path.parts
                    and re.fullmatch(r"[a-zA-Z0-9_./-]+", name) and path.suffix in {".json",".jsonl",".c",".txt"}
                    and re.fullmatch("[0-9a-f]{64}", expected), "Invalid evidence entry")
        self.used = {}

    def raw(self, name):
        if name not in self.used:
            require(name in self.files, "Unlisted evidence: " + name)
            path = (self.root / name).resolve(strict=True)
            require(path.is_relative_to(self.root) and path.is_file(), "Evidence outside bundle: " + name)
            content = path.read_bytes()
            require(hashlib.sha256(content).hexdigest() == self.files[name], "Changed evidence: " + name)
            self.used[name] = content
        return self.used[name]

    def json(self, name):
        return json.loads(self.raw(name))


def traces_and_repair(ev):
    matrix = ev.json("history/trace-matrix.json")
    require(matrix["passed"] is True, "Trace matrix failed")
    traces = []
    for mode in ("reference", "reexecution"):
        prefix = "trace/" + mode + "/"
        name = prefix + "report.json"
        doc = ev.json(name)
        row, = [r for r in matrix["rows"] if r["case"] == "rmw-split-ab" and r["mode"] == mode]
        require(ev.files[name] == row["report_sha256"] and doc["origin"] == mode
                and doc["run_id"] == row["run_id"] and doc["property_violation"] is True, "Trace record mismatch")
        for node in doc["nodes"]:
            for key in ("evidence", "source_evidence"):
                ptr = node[key]
                require(re.fullmatch(r"events/[0-9a-f]{64}/(?:[AB]\.events|source-map)\.jsonl", ptr["href"]),
                        "Unexpected event link")
                path = prefix + ptr["href"]
                lines = ev.raw(path).splitlines()
                require(ev.files[path] == ptr["sha256"] and 1 <= ptr["line"] <= len(lines)
                        and json.loads(lines[ptr["line"]-1]) == ptr["record"], "Trace evidence line mismatch")
        traces.append(doc)
    original, replay = traces
    receipt = replay["reexecution"]
    require(original["bundle_id"] == replay["bundle_id"] and original["run_id"] == replay["reference_run_id"]
            and original["run_id"] != replay["run_id"] and receipt["full_match"] is True, "Reexecution mismatch")
    comparison_path = "trace/reexecution/" + receipt["evidence"]["href"]
    comparison = ev.json(comparison_path)
    require(ev.files[comparison_path] == receipt["evidence"]["sha256"]
            and comparison["bundle_id"] == original["bundle_id"] and comparison["full_match"] is True, "Comparison receipt mismatch")
    accepted = ev.json("repair/acceptance.json")
    case, = [r for r in accepted["cases"] if r["name"] == "rmw-split-ab"]
    cross = ev.json("repair/cross-build.json")
    result = ev.json("repair/regression.json")
    require(accepted["passed"] is True and case["passed"] is True and case["original_property_violation"] is True
            and case["regression_result"]["sha256"] == ev.files["repair/regression.json"]
            and case["cross_build"]["sha256"] == ev.files["repair/cross-build.json"], "Repair receipts do not match")
    old = cross["reference_build"]["kernel_and_k03"]["vmlinux"]
    new = cross["new_build"]["kernel_and_k03"]["vmlinux"]
    require(old == original["vmlinux_sha256"] and old != new and cross["reference_bundle_id"] == original["bundle_id"]
            and result["cross_build_sha256"] == ev.files["repair/cross-build.json"] and cross["same_high_level_input"] is True
            and cross["same_declared_property"] is True and cross["old_schedule_executed"] is False
            and result["contract"]["input"] == case["high_level_input"], "Wrong cross-build relation")
    attempts = result["attempts"]
    require(len(attempts) == result["requested_attempts"] == case["actual_attempts"] and result["passed"] is True
            and all(r["guest_started"] and r["candidate_hit"] and r["property_evaluated"] and r["cleanup_verified"]
                    and r["property_violation"] is False for r in attempts), "Incomplete selected repair regression")
    return traces, dict(case=case["name"], attempts=len(attempts), original_vmlinux_sha256=old, repaired_vmlinux_sha256=new)


def source_and_proof(ev):
    cert = ev.json("opt/certificate.json")
    qualified = ev.json("opt/qualified.json")
    fallback = ev.json("opt/fallback.json")
    proof = ev.json("opt/proof.json")
    functional = ev.json("opt/functional.json")
    digest = ev.files["opt/certificate.json"]
    require(qualified["decision"] == "scoped_source_verified" and qualified["certificate_sha256"] == digest
            and functional["verified"] is True and functional["source_certificate"] == digest
            and proof["passed"] is True and all(c["exit_code"] == 0 for c in proof["commands"])
            and cert["proof"] == {k: proof[k] for k in cert["proof"]}, "Proof or source certificate mismatch")
    for name, expected in cert["proof"]["assumptions_sha256"].items():
        receipt = "opt/assumptions/" + name + ".txt"
        ev.raw(receipt)
        require(ev.files[receipt] == expected, "Changed theorem assumptions")
    versions = []
    for arm in ("reference", "optimized"):
        path = "opt/" + arm + ".c"
        versions.append(ev.raw(path).decode().splitlines())
        require(cert["emitted_sha256"][arm] == ev.files[path] == qualified["outputs"][arm+"/drivers/base/regmap/regmap.c"],
                "C source differs from the certificate")
    ev.raw("opt/fallback.c")
    require(fallback["decision"] == "original_fallback" and ev.files["opt/fallback.c"] == cert["inputs"]["drivers/base/regmap/regmap.c"]
            and fallback["outputs"] == {"original/drivers/base/regmap/regmap.c":cert["inputs"]["drivers/base/regmap/regmap.c"]}
            and fallback["inputs"]["config"] != qualified["inputs"]["config"], "Configuration fallback mismatch")
    return cert, fallback, functional, "\n".join(unified_diff(*versions, fromfile="reference", tofile="optimized", lineterm=""))


def render_bundle(bundle, out):
    from .demo_performance import measured_performance
    from .demo_page import page
    ev = Evidence(bundle)
    traces, repair = traces_and_repair(ev)
    cert, fallback, functional, diff = source_and_proof(ev)
    timing, ids = measured_performance(ev, cert, functional, summarize)
    require(set(ev.used) == set(ev.files), "Bundle contains unreviewed evidence")
    # Publish after all checks. A report is complete when its index has been written.
    for name, content in ev.used.items():
        dest = out / "evidence" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(content)
    for trace in traces:
        path = out / "evidence/trace" / trace["origin"] / "index.html"
        path.write_bytes(render_report(trace).encode("utf8"))
    summary = dict(kind="kconc.regmap-demo-result", bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
                   trace_run_ids=[t["run_id"] for t in traces], repair=repair, certificate_sha256=ev.files["opt/certificate.json"],
                   kernel_build_ids=ids, performance=timing, new_guest_executions=0)
    (out/"summary.json").write_bytes((json.dumps(summary, ensure_ascii=False, indent=2)+"\n").encode("utf8"))
    (out/"index.html").write_bytes(page(traces, repair, cert, fallback, functional, diff, timing, ids).encode("utf8"))
    return {"index": "index.html", "summary": "summary.json", "bundle_sha256": summary["bundle_sha256"],
            "eligible": timing["eligible"], "value_gate_passed": timing["value_gate_passed"], "new_guest_executions": 0}

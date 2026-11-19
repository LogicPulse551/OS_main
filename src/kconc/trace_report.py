"""Build a portable reading copy of the event evidence used in a source report."""
import hashlib
import json
from pathlib import Path

from .report_evidence import load_evidence
from .report_html import render_report
from .report_source import attach_sources


def archive_dir(path):
    return path.parent if path.is_file() else path


def copy_event_evidence(report, roots, out):
    """Keep the exact bytes and selected records, even when the report is moved."""
    copies = {}

    def snapshot(evidence, allowed):
        root = roots[evidence["root"]].resolve()
        source = (root / evidence["file"]).resolve(strict=True)
        if not source.is_relative_to(root) or source.name not in allowed:
            raise ValueError("Unexpected evidence file in report")
        if source not in copies:
            raw = source.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            local = Path("events") / digest / source.name
            dest = out / local
            dest.parent.mkdir(parents=True, exist_ok=True)
            if digest != evidence["sha256"]:
                raise ValueError("Event evidence changed during report generation")
            with dest.open("xb") as f:
                f.write(raw)
            copies[source] = digest, local.as_posix(), raw.splitlines()
        digest, href, lines = copies[source]
        if evidence["sha256"] != digest:
            raise ValueError("Inconsistent event file identity")
        evidence["href"] = href
        return lines

    for node in report["nodes"]:
        for key, allowed in (("evidence", {"A.events.jsonl", "B.events.jsonl"}), ("source_evidence", {"source-map.jsonl"})):
            pointer = node[key]
            lines = snapshot(pointer, allowed)
            index = pointer["line"]
            if type(index) is not int or not 1 <= index <= len(lines):
                raise ValueError("Archived line number outside evidence file")
            pointer["record"] = json.loads(lines[index - 1])
    if report["reexecution"]:
        snapshot(report["reexecution"]["evidence"], {"comparison.json"})


def write_report(out, *, bundle, source_root, build_record, attempt=None):
    report = load_evidence(bundle, attempt)
    bundle_dir = archive_dir(bundle)
    attach_sources(report, bundle_dir, source_root, build_record)
    roots = {"bundle": bundle_dir}
    if attempt is not None:
        roots["attempt"] = archive_dir(attempt)
    report.update(schema_version=1, kind="kconc.trace-report", new_guest_executions=0,
                  title="regmap 并发执行记录")
    copy_event_evidence(report, roots, out)
    page = render_report(report)
    with (out/"report.json").open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write("\n")
    with (out/"index.html").open("x", encoding="utf-8", newline="\n") as f:
        f.write(page)
    return {"report": "report.json", "html": "index.html", "origin": report["origin"],
            "run_id": report["run_id"], "nodes": len(report["nodes"]), "new_guest_executions": 0,
            "source_locations": len(report["sources"]), "property_violation": report["property_violation"]}

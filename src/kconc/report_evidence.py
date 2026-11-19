"""Read the team's recorded regmap examples and attach file positions to the displayed events."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from . import legacy_reference
from .replay_bundle import FILES


# Each marker is the first recorded memory access in this function for the
# logical role. Inline symbols are kept as the recorder identified them.
STAGES = {
    FILES[0]: {"kconc_operation", "kconc_regmap_checkpoint", "kconc_observe"},
    FILES[1]: {"regmap_read", "regmap_write", "regmap_update_bits_base"},
    FILES[2]: {"regmap_ram_read", "regmap_ram_write"},
}
COMPARE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from kconc.replay_bundle import compare
print(json.dumps(compare(sys.argv[2], sys.argv[3])))
"""


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _file(root, relative):
    path = root / relative
    _need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),
          "Missing or redirected evidence: " + relative)
    return path


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path):
    return json.loads(path.read_bytes())


def _attempt_row(directory, bundle_dir, bundle, comparison):
    ledger = _json(_file(directory.parent, "replay-result.json"))
    task = _json(_file(directory, "task.json"))
    _need(ledger["kind"] == "kconc.replay" and task["operation"] == "replay.run"
          and ledger["bundle_sha256"] == _sha(bundle_dir/"bundle.json")
          and ledger["candidate_id"] == bundle["source"]["candidate_id"], "Attempt batch belongs to another witness")
    rows = [r for r in ledger["attempts"] if r["attempt_id"] == task["attempt_id"]]
    _need(len(rows) == 1, "Missing or ambiguous batch receipt for attempt")
    row = rows[0]
    _need(row["ordinal"] == task["ordinal"] and directory.name == f"attempt-{task['ordinal']:03d}"
          and row["guest_started"] is True and row["attempt_result_sha256"] == _sha(_file(directory,"attempt-result.json"))
          and row["comparison_sha256"] == _sha(_file(directory,"comparison.json"))
          and row["comparison_classification"] == comparison["classification"]
          and row["matched"] is comparison["full_match"] and row["property_reproduced"] is comparison["property_reproduced"],
          "Attempt receipt differs from the archived batch")
    return row


def _pointer(root_name, relative, digest, **position):
    return dict(root=root_name, file=relative, sha256=digest, **position)


def _events(root, root_name, prefix, analysis):
    path = _file(root, prefix+"source-map.jsonl")
    raw = path.read_bytes()
    map_hash = hashlib.sha256(raw).hexdigest()
    mapping = {}
    for line, text in enumerate(raw.splitlines(), 1):
        if text.strip():
            row = json.loads(text)
            _need(row["raw_ip"] not in mapping, "Duplicate source mapping")
            mapping[row["raw_ip"]] = (row, line)
    canonical = json.dumps({ip:row for ip,(row,_) in mapping.items()}, sort_keys=True, separators=(",",":"))
    _need(hashlib.sha256(canonical.encode()).hexdigest() == analysis["artifacts"]["source_map"]["canonical_sha256"],
          "Source lines differ from the analyzed mapping")
    metadata_bytes = _file(root,prefix+"guest/trace/run.json").read_bytes()
    _need(hashlib.sha256(metadata_bytes).hexdigest() == analysis["artifacts"]["run.json"], "Role assignment changed")
    metadata = json.loads(metadata_bytes)
    roles = metadata["slot_to_logical_role"]
    _need(set(roles) == {"A","B"} and set(roles.values()) == {"A","B"}, "Unrecognized logical roles")
    nodes, edges = [], []
    for slot, role in sorted(roles.items(), key=lambda kv: kv[1]):
        filename = f"{slot}.events.jsonl"
        relative = prefix+"guest/trace/"+filename
        events = _file(root, relative).read_bytes()
        digest = hashlib.sha256(events).hexdigest()
        _need(analysis["artifacts"][filename] == digest, "Event file differs from its analyzed bytes")
        seen = set()
        previous = None
        for line, text in enumerate(events.splitlines(), 1):
            event = json.loads(text)
            if event["kind"] != "MEMORY":
                continue
            origin, map_line = mapping[event["ip"]]
            recorded_file = origin["file"].replace("\\","/")
            file = next((f for f in FILES if recorded_file == f or recorded_file.endswith("/"+f)),None)
            symbol = origin["symbol"]
            if file is None or symbol not in STAGES[file] or (file,symbol) in seen:
                continue
            seen.add((file,symbol))
            source = {k:origin[k] for k in ("symbol","line","exact_line","mapping_kind")}
            source.update(file=file,recorded_file=recorded_file)
            ident = f"{role}-{line}"
            node = dict(id=ident, role=role, kind=event["kind"], word_index=event["word_index"],
                        label=symbol, source=source, slot=slot,
                        evidence=_pointer(root_name,relative,digest,locator=f"line:{line}",line=line),
                        source_evidence=_pointer(root_name,prefix+"source-map.jsonl",map_hash,
                                                 locator=f"line:{map_line}",line=map_line))
            nodes.append(node)
            if previous is not None:
                edges.append({"from":previous,"to":ident,"kind":"role_order"})
            previous = ident
    return nodes, edges


def load_evidence(bundle: Path, attempt: Path | None = None) -> dict:
    """Validate a K10 reference and optionally select an existing, independently compared attempt."""
    p = Path(bundle).resolve(strict=True)
    _need(p.is_dir() or p.name == "bundle.json", "Expected a K10 bundle directory or bundle.json")
    bundle_dir = p if p.is_dir() else p.parent
    attempt_dir = None
    if attempt is not None:
        p = Path(attempt).resolve(strict=True)
        _need(p.is_dir() or p.name == "comparison.json", "Expected an attempt directory or comparison.json")
        attempt_dir = p if p.is_dir() else p.parent
    reexecution = None
    with tempfile.TemporaryDirectory(prefix="kconc-report-") as tmp:
        temp = Path(tmp)
        verified = legacy_reference.load_reference(bundle_dir,temp)
        if attempt_dir is not None:
            # The K10 analyzer hashes its own source. Recompute with the accepted revision.
            result = subprocess.run([sys.executable,"-I","-B","-c",COMPARE,str(temp/"reference-code/src"),
                                     str(bundle_dir),str(attempt_dir)],capture_output=True,timeout=180)
            _need(result.returncode == 0, "Offline attempt comparison failed: "+result.stderr.decode(errors="replace")[-600:])
            comparison = json.loads(result.stdout)
            _need(not comparison["errors"] and comparison == _json(_file(attempt_dir,"comparison.json")),
                  "Saved comparison does not reproduce from this attempt")
            _need(all(comparison["checks"].get(k) is True for k in (
                "original_candidate","original_complete_build","new_run_id","new_time_after_reference")),
                "Attempt is not a later execution of the same scenario and build")
            _attempt_row(attempt_dir,bundle_dir,verified,comparison)
            guest = _json(_file(attempt_dir,"guest/guest-result.json"))
            reexecution = dict(run_id=guest["run_id"],classification=comparison["classification"],
                               full_match=comparison["full_match"], property_reproduced=comparison["property_reproduced"],
                               evidence=_pointer("attempt","comparison.json",_sha(attempt_dir/"comparison.json"),locator="/classification"))
    root, root_name, prefix = (attempt_dir,"attempt","") if attempt_dir else (bundle_dir,"bundle","reference/")
    analysis_path = _file(root,prefix+"analysis.json")
    analysis = _json(analysis_path)
    nodes, edges = _events(root,root_name,prefix,analysis)
    candidate = verified["candidate"]["identity"]
    kernel = verified["runtime_identity"]["kernel_and_k03"]
    case = candidate["input"]
    observed = analysis.get("observed_property") or {}
    property_keys = ("oracle","allowed","error_type","observed","legal_results","max_depth","final_depth","busy_roles",
                     "observed_registers","expected_registers")
    observation = {k:observed[k] for k in property_keys if k in observed}
    if "events" in observed:
        observation["events"] = [{k:event[k] for k in ("seq","role","kind","depth")} for event in observed["events"]]
    return dict(case=case["input_id"]+":"+candidate["baseline_order"],family=case["family"], mode=case["mode"],
                run_id=reexecution["run_id"] if reexecution else verified["source"]["run_id"],
                reference_run_id=verified["source"]["run_id"], bundle_id=verified["bundle_id"],
                origin="reexecution" if reexecution else "reference", reexecution=reexecution,
                build_id=kernel["vmlinux"], vmlinux_sha256=kernel["vmlinux"],linux_commit=kernel["linux_commit"],
                runtime_identity_sha256=_sha(_file(root,prefix+"runtime-identity.json")),
                property_violation=analysis["property_violation"] if analysis["property_evaluated"] else None,
                property_evaluated=analysis["property_evaluated"], property=observation,
                property_evidence=_pointer(root_name,prefix+"analysis.json",_sha(analysis_path),locator="/observed_property"),
                selection="每个逻辑线程在夹具、regmap 公共调用和 RAM 总线指定函数中的首次已记录访存",
                nodes=nodes, edges=edges)

"""Exact provenance for a separately built K10 controller, never a K09 alias."""
from .candidates import fingerprint


def native_checks(record, observed, parent, parent_hashes, patch_sha, script_sha):
    """The caller separately verifies the full original K09/K08 identity chain."""
    inputs=record.get('inputs',{}); origin=inputs.get('accepted_k09',{})
    rows=record.get('binaries',[]); binaries={r.get('name'):r.get('sha256') for r in rows}
    actual=observed.get('current_hashes',{})
    source_rows=observed.get('sources',[])
    source_manifest={r.get('path'):r.get('sha256') for r in source_rows}
    same=lambda a,b:fingerprint(a)==fingerprint(b)
    scenarios={n:h for n,h in parent_hashes.items() if n.endswith('.so')}
    return dict(
        control_build_passed=record.get('passed') is True and record.get('task')=='K10'
            and record.get('kind')=='kconc.executor.control-build',
        control_parent_record=same(origin.get('record'),parent),
        control_parent_record_hash=origin.get('result_sha256')==observed.get('parent_result_sha256'),
        control_parent_manifest_hash=origin.get('effective_manifest_sha256')==observed.get('parent_manifest_sha256'),
        control_parent_sources=same(origin.get('effective_sources'),observed.get('parent_sources')),
        control_parent_sources_intact=observed.get('parent_sources_intact') is True,
        control_original_sampler_bridge=same(inputs.get('accepted_k08'),parent.get('inputs',{}).get('accepted_k08')),
        control_copied_scenario_provenance=same(inputs.get('copied_scenarios'),parent.get('inputs',{}).get('copied_scenarios')),
        control_original_scenario_bytes=len(scenarios)==14 and {n:actual.get(n) for n in scenarios}==scenarios,
        control_expected_binary_set=len(rows)==16 and len(binaries)==16 and set(actual)==set(parent_hashes)==set(binaries),
        control_recorded_binary_bytes=actual==binaries,
        control_executor_aliases=bool(actual.get('kcov-execute-k09-ab'))
            and actual.get('kcov-execute-k09-ab')==actual.get('kcov-execute-k09-ba'),
        control_patch=inputs.get('control_patch_sha256')==patch_sha
            and source_manifest.get('k10-control.patch')==patch_sha,
        control_build_script=inputs.get('build_script_sha256')==script_sha,
        control_effective_manifest=record.get('effective_manifest_sha256')==observed.get('manifest_sha256'),
        control_effective_sources=bool(source_rows) and len(source_rows)==len(source_manifest)
            and source_manifest==observed.get('source_hashes'),
    )

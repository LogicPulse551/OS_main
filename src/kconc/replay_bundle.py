"""Portable K09 witnesses and K10 original-build critical-path comparison.

Hashes bind local evidence; they are integrity checks, not authentication. The
pinned recorder, DWARF mapping and accepted K09 analyzer remain trusted. A match
is a match of the declared component path, not equality of the entire machine.
"""
from __future__ import annotations

import collections
import copy
import datetime
import importlib.util
from pathlib import Path, PurePosixPath
import shutil

from . import candidates, search_queue

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('k10_k09_analysis', REPO/'adapters/maccconc/k09_analysis.py')
k09 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(k09)
FILES = ('drivers/base/regmap/kconc-regmap.c', 'drivers/base/regmap/regmap.c',
         'drivers/base/regmap/regmap-ram.c')
APIS = ('regmap_read', 'regmap_write', 'regmap_update_bits_base')
PID_FIELDS = ('pid', 'caller_tid', 'kernel_pid')
MATCH_POLICY = dict(
    id='kconc.k10.original-build-critical-path-v1', schema_version=1,
    original_candidate_gate=k09.MATCH_POLICY,
    build='Exact complete K09 runtime identity, including executor, copied libraries, kernel and original sampler bridge',
    new_execution='Different supervisor run_id and start time after the reference finished; every attempt retained',
    logical_roles='Fixed callbacks and slot-to-logical mapping, with live caller/kernel TIDs independently verified by K09',
    path_files=list(FILES),
    path_selection='All MEMORY events with validated source-map file in the three declared component files; no unmapped MEMORY event is silently discarded',
    path_fields=['kind', 'record_type', 'ip', 'size', 'flags', 'stack', 'source',
                 'access_ordinal', 'same_ip_occurrence', 'full_stack_occurrence'],
    path_source_fields=['file', 'symbol', 'line', 'exact_line', 'mapping_kind'],
    path_exclusions=['address', 'value', 'timestamp', 'global raw word_index', 'physical thread label'],
    path_exclusion_reason='Addresses, pre-access payload and clocks are dynamic; whole-trace offsets include unrelated kernel activity. Logical role and component-local ordinal are retained. The complete K09 prefix still includes raw word offsets.',
    API_occurrences='For each public API source symbol in regmap.c, count distinct full stack[:-1] invocation identities; preserve ordered identities, not just totals',
    api_symbols=list(APIS),
    source_basis=['kernel/k06/kconc-regmap.c: split calls regmap_read then regmap_write; update-bits calls regmap_update_bits',
                  'kernel/k07/kconc-regmap.c: admitted operation calls regmap_update_bits once; BUSY calls none'],
    control='Per-logical-role ordered WAKE/WAIT flags and timeout bits, plus accepted K09 target and handoff checks',
    phase_comparison='Compare all five phase objects, replacing only pid/caller_tid/kernel_pid that equal a live slot TID with its logical role token; retain all other values, epochs, FDs, inputs, return codes and mutex events',
    variable_semantics='Phase before/after/final and boundary observations are values checked; KCOV MEMORY.value is a pre-access snapshot and is not interpreted as a stored RHS',
    property='Compare the full independently recalculated declared property verdict, including error type',
    stability=dict(minimum_attempts=20, minimum_full_matches=19, failures_in_denominator=True,
                   scope='Only this fixed batch; no probability guarantee'),
    nonclaims=['Not whole-kernel-state equality', 'No inferred reads-from or timestamp total order',
               'No cross-build repair regression', 'No original-source correctness proof'])
POLICY_SHA256 = candidates.fingerprint(MATCH_POLICY)
REFERENCE_FILES = (
    'candidate.json', 'runtime-identity.json', 'analysis.json', 'attempt-result.json',
    'task.json', 'guest-request.json', 'input-plan.txt', 'source-map.jsonl',
    'guest/guest-result.json',
    *('guest/trace/'+name for name in k09.TRACE_FILES))
_BUNDLE_FIELDS = {'schema_version', 'kind', 'bundle_id', 'policy', 'policy_sha256',
                  'source', 'artifacts', 'signature_sha256', 'scope'}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _read(path):
    return candidates._read_json(Path(path))


def _sha(path):
    return k09.k06.digest(Path(path))


def _same(left, right):
    return candidates.fingerprint(left) == candidates.fingerprint(right)


def _write(path, value):
    import json
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def _path(root, name):
    p = PurePosixPath(name)
    _require(isinstance(name, str) and str(p) == name and not p.is_absolute()
             and '..' not in p.parts and '\\' not in name, 'Invalid bundle-relative path')
    root = Path(root).resolve()
    target = root.joinpath(*p.parts)
    _require(not target.is_symlink() and target.resolve().is_relative_to(root), 'Bundle link escapes its directory')
    _require(all(not parent.is_symlink() for parent in target.parents if parent != root and parent.is_relative_to(root)),
             'Symlinked bundle directory is not accepted')
    return target


def _mapping(path):
    mapping, _ = k09.k06.read_mapping(path)
    return mapping


def _recomputed(directory):
    """Recompute the original analyzer and host binding; no VM is contacted."""
    directory = Path(directory)
    candidate = _read(directory/'candidate.json')
    candidates.validate_candidate(candidate)
    runtime = _read(directory/'runtime-identity.json')
    _require(search_queue.eligibility(candidate, runtime)['supported'], 'Reference runtime no longer binds the K08 candidate')
    trace = directory/'guest/trace'
    guest = _read(directory/'guest/guest-result.json')
    request = _read(directory/'guest-request.json')
    task = _read(directory/'task.json')
    _require(task.get('operation') in ('kernel.check', 'replay.run'), 'Not a K09 execution or a K10 replay attempt')
    _require(task.get('candidate_id') == candidate['candidate_id'], 'Task is not bound to the candidate')
    order = candidate['identity']['baseline_order']
    entry = candidate['identity']['input']
    build = task['runtime']['search_guest_build']
    _require(request['executable'] == build+'/bin/kcov-execute-k09-'+order
             and request['scenario_library'] == build+'/bin/'+entry['native_so']
             and request['fault'] == 'none', 'Unexpected submitted executor, scenario or fault')
    remote = '/home/lab/k09/run-'+request['run_id']
    command = [request['executable'], request['scenario_library'], '--k09-execute', order,
               request['plan_path'], remote+'/trace']
    _require(request['plan_path'] == remote+'/plan.txt' and guest['run_id'] == request['run_id']
             and guest['command'] == command and guest['fault'] == 'none', 'Guest execution is not the submitted saved-plan attempt')
    mapping = _mapping(directory/'source-map.jsonl')
    result = k09.analyze(trace, mapping, guest, candidate)
    plan_matches = (directory/'input-plan.txt').read_bytes() == (trace/'plan.txt').read_bytes() == search_queue.make_plan(candidate)
    result['checks']['executed_plan_matches_submitted'] = plan_matches
    _require(plan_matches, 'Executed and original candidate plans differ')
    result.update(runtime_identity_bound=True, runtime_identity_sha256=_sha(directory/'runtime-identity.json'),
        candidate_file_sha256=_sha(directory/'candidate.json'), plan_sha256=_sha(directory/'input-plan.txt'))
    _require(_same(result, _read(directory/'analysis.json')), 'Saved K09 analysis does not reproduce from its evidence')
    attempt = _read(directory/'attempt-result.json')
    _require(attempt.get('kind') == 'kconc.candidate-attempt' and attempt.get('candidate_id') == candidate['candidate_id']
             and attempt.get('guest_started') is True and _same(attempt.get('guest'), guest)
             and _same(attempt.get('analysis'), result) and attempt.get('classification') == result['classification']
             and attempt.get('passed') is result['passed'] and attempt.get('recovery_required') is result['recovery_required'],
             'Attempt envelope disagrees with its actual evidence')
    return dict(candidate=candidate, runtime_identity=runtime, analysis=result, guest=guest,
                task=task, mapping=mapping, trace=trace)


def _source(source, ip):
    _require(isinstance(source, dict) and source.get('found') is True
             and source.get('raw_ip') == ip and int(source.get('lookup_ip', '0'), 16) == int(ip, 16)-1,
             'Missing or invalid memory source mapping')
    filename = str(source.get('file', '')).replace('\\', '/')
    match = next((name for name in FILES if filename == name or filename.endswith('/'+name)), None)
    if match is None:
        return None
    _require(isinstance(source.get('symbol'), str) and bool(source['symbol'])
             and type(source.get('line')) is int and source['line'] >= 0
             and type(source.get('exact_line')) is bool and isinstance(source.get('mapping_kind'), str),
             'Selected memory event has incomplete source metadata')
    return dict(file=match, **{key:source[key] for key in ('symbol', 'line', 'exact_line', 'mapping_kind')})


def _normalize_pids(value, tids):
    if isinstance(value, list):
        return [_normalize_pids(v, tids) for v in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in PID_FIELDS and type(item) is int and item in tids:
            result[key] = 'logical-thread:'+tids[item]
        else:
            result[key] = _normalize_pids(item, tids)
    return result


def signature(directory, evidence=None):
    """Build the declared path signature, without asserting a new execution."""
    directory = Path(directory)
    evidence = evidence if evidence is not None else _recomputed(directory)
    candidate, report = evidence['candidate'], evidence['analysis']
    _require(report['execution_valid'] and report['cleanup_verified'], 'Signature needs valid, clean execution evidence')
    metadata = _read(evidence['trace']/'run.json')
    phases = k09.k06.read_phases(evidence['trace'])
    paths, api_calls, controls = {}, {}, {}
    for slot, role in metadata['slot_to_logical_role'].items():
        counts, stacks = collections.Counter(), collections.Counter()
        projected, observed_calls, control = [], {name:[] for name in APIS}, []
        for event in k09.k03.read_events(evidence['trace'], slot):
            if event['kind'] in ('WAIT', 'WAKE'):
                control.append({key:event[key] for key in ('kind', 'flagidx', 'timed_out')})
            if event['kind'] != 'MEMORY':
                continue
            source = _source(evidence['mapping'].get(event['ip']), event['ip'])
            if source is None:
                continue
            counts[event['ip']] += 1
            stack_id = candidates.fingerprint(event['stack'])
            stacks[stack_id] += 1
            projected.append(dict({key:copy.deepcopy(event[key]) for key in ('kind', 'record_type', 'ip', 'size', 'flags', 'stack')},
                source=source, access_ordinal=len(projected), same_ip_occurrence=counts[event['ip']],
                full_stack_occurrence=stacks[stack_id]))
            symbol = source['symbol']
            if source['file'] == FILES[1] and symbol in APIS:
                invocation = event['stack'][:-1]
                _require(bool(invocation), 'API occurrence needs a full invocation stack')
                if invocation not in observed_calls[symbol]:
                    observed_calls[symbol].append(copy.deepcopy(invocation))
        _require(bool(projected), 'No component path for a logical operation')
        paths[role], controls[role] = projected, control
        api_calls[role] = {name:dict(count=len(v), invocations=v) for name,v in observed_calls.items()}
        family = candidate['identity']['input']['family']
        expected = dict.fromkeys(APIS, 0)
        if family == 'rmw':
            if phases[0]['mode'] == 'split':
                expected.update(regmap_read=1, regmap_write=1)
            else:
                expected['regmap_update_bits_base'] = 1
        else:
            expected['regmap_update_bits_base'] = int(phases[2]['results'][0 if role=='A' else 1]['result']['outcome'] == 1)
        _require({name:item['count'] for name,item in api_calls[role].items()} == expected,
                 'Actual public API invocation identities disagree with the fixed source protocol')
    tids = {metadata['slot_tids'][slot]:role for slot,role in metadata['slot_to_logical_role'].items()}
    return dict(schema_version=1, policy_sha256=POLICY_SHA256,
        candidate_id=candidate['candidate_id'], input=candidate['identity']['input'],
        logical_roles=candidate['identity']['logical_roles'], slot_to_logical_role=metadata['slot_to_logical_role'],
        critical_paths=paths, api_calls=api_calls, control=controls,
        phases=_normalize_pids(phases, tids), property=report.get('observed_property'),
        source_basis={name:_sha(REPO/name) for name in ('kernel/k06/kconc-regmap.c', 'kernel/k07/kconc-regmap.c')})


def _reference_binding(directory, ledger):
    evidence = _recomputed(directory)
    _require(evidence['task']['operation'] == 'kernel.check', 'Replay source must be an original K09 candidate execution')
    r = evidence['analysis']
    _require(r['candidate_hit'] is True and r['classification'] == 'hit' and r['property_evaluated'] is True
             and r['recovery_required'] is False, 'Only fully matched K09 witnesses can be bound')
    rows = [a for a in ledger['attempts'] if a['attempt_id'] == evidence['task']['attempt_id']]
    _require(len(rows) == 1, 'Original K09 ledger lacks a unique attempt')
    row = rows[0]
    _require(row['candidate_id'] == evidence['candidate']['candidate_id'] and row['outcome'] == 'hit'
             and row['guest_started'] is True and row['cleanup_confirmed'] is True
             and row['property_evaluated'] is True and row['property_violation'] is r['property_violation']
             and row['evidence']['analysis_sha256'] == _sha(Path(directory)/'analysis.json')
             and row['evidence']['result_sha256'] == _sha(Path(directory)/'attempt-result.json'),
             'Original K09 ledger and saved witness disagree')
    return evidence


def create_bundle(attempt_dir, output_dir):
    """Bind a verified original witness to a new portable directory, never overwrite."""
    attempt_dir, output_dir = Path(attempt_dir).resolve(), Path(output_dir).resolve()
    _require(not output_dir.exists(), 'Replay bundle output already exists')
    _require(not output_dir.is_relative_to(REPO) and output_dir not in REPO.parents,
             'Replay evidence must remain outside the code repository')
    ledger = _read(attempt_dir.parent/'ledger.json')
    evidence = _reference_binding(attempt_dir, ledger)
    expected = signature(attempt_dir, evidence)
    output_dir.mkdir(parents=True)
    for name in REFERENCE_FILES:
        original = _path(attempt_dir, name)
        _require(original.is_file(), 'Missing original witness artifact: '+name)
        target = _path(output_dir, 'reference/'+name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
    _write(output_dir/'origin-ledger.json', ledger)
    _write(output_dir/'signature.json', expected)
    paths = ['reference/'+n for n in REFERENCE_FILES]+['origin-ledger.json', 'signature.json']
    record = dict(schema_version=1, kind='kconc.replay-bundle', policy=MATCH_POLICY,
        policy_sha256=POLICY_SHA256,
        source=dict(original_attempt=str(attempt_dir), attempt_id=evidence['task']['attempt_id'],
                    run_id=evidence['guest']['run_id'], candidate_id=evidence['candidate']['candidate_id'],
                    reference_classification='hit', property_violation=evidence['analysis']['property_violation']),
        artifacts={name:_sha(_path(output_dir,name)) for name in paths},
        signature_sha256=candidates.fingerprint(expected),
        scope='Self-contained K09 witness for original-build K10 reexecution; no new execution or stability claim')
    record['bundle_id'] = candidates.fingerprint(record)
    _write(output_dir/'bundle.json', record)
    return load_bundle(output_dir)


def load_bundle(path):
    """Recheck hashes and recompute the reference using only files inside the bundle."""
    path = Path(path)
    directory = path if path.is_dir() else path.parent
    _require(path.is_dir() or path.name == 'bundle.json', 'Expected bundle directory or bundle.json')
    record = _read(_path(directory, 'bundle.json'))
    _require(isinstance(record,dict) and set(record) == _BUNDLE_FIELDS
             and type(record['schema_version']) is int and record['schema_version'] == 1
             and record['kind'] == 'kconc.replay-bundle', 'Unknown replay bundle schema')
    _require(record['bundle_id'] == candidates.fingerprint({k:v for k,v in record.items() if k != 'bundle_id'}), 'Bundle identity mismatch')
    _require(_same(record['policy'], MATCH_POLICY) and record['policy_sha256'] == POLICY_SHA256,
             'Replay matching policy differs from this implementation')
    names = {'reference/'+n for n in REFERENCE_FILES}|{'origin-ledger.json','signature.json'}
    _require(isinstance(record['artifacts'],dict) and set(record['artifacts']) == names, 'Incomplete or extra bundle artifacts')
    for name,digest in record['artifacts'].items():
        _require(type(digest) is str and digest == _sha(_path(directory,name)), 'Changed replay artifact: '+name)
    evidence = _reference_binding(directory/'reference', _read(directory/'origin-ledger.json'))
    expected = signature(directory/'reference', evidence)
    _require(_same(expected, _read(directory/'signature.json')) and record['signature_sha256'] == candidates.fingerprint(expected),
             'Frozen signature does not reproduce from the reference')
    source = record['source']
    _require(source['attempt_id'] == evidence['task']['attempt_id'] and source['run_id'] == evidence['guest']['run_id']
             and source['candidate_id'] == evidence['candidate']['candidate_id'] and source['reference_classification'] == 'hit'
             and source['property_violation'] is evidence['analysis']['property_violation'], 'Bundle source identity mismatch')
    return dict(record, _directory=str(directory.resolve()), candidate=evidence['candidate'],
                runtime_identity=evidence['runtime_identity'])


def compare(bundle, actual_attempt_dir):
    """Compare one actual attempt, retaining property-only reproduction separately."""
    bundle = load_bundle(bundle['_directory'] if isinstance(bundle, dict) else bundle)
    actual_attempt_dir = Path(actual_attempt_dir)
    result = dict(schema_version=1, kind='kconc.replay-comparison', bundle_id=bundle['bundle_id'],
        policy_sha256=POLICY_SHA256, full_match=False, property_reproduced=False,
        property_reproduction_scope='Diagnostic same declared property result; never substitutes for complete path matching',
        classification='invalid', checks={}, differences={}, errors=[],
        reference_signature_sha256=bundle['signature_sha256'], actual_signature_sha256=None)
    try:
        actual = _recomputed(actual_attempt_dir)
        candidate, report, guest = actual['candidate'], actual['analysis'], actual['guest']
        reference = _read(Path(bundle['_directory'])/'signature.json')
        prior_guest = _read(Path(bundle['_directory'])/'reference/guest/guest-result.json')
        checks = result['checks']
        checks.update(original_candidate=_same(candidate,bundle['candidate']),
            original_complete_build=_same(actual['runtime_identity'],bundle['runtime_identity']),
            original_k09_match=report['candidate_hit'] is True and report['classification'] == 'hit',
            clean_execution=report['execution_valid'] is True and report['cleanup_verified'] is True and report['recovery_required'] is False,
            new_run_id=guest['run_id'] != bundle['source']['run_id'])
        started = datetime.datetime.fromisoformat(guest['started_utc'])
        finished = datetime.datetime.fromisoformat(prior_guest['finished_utc'])
        checks['new_time_after_reference'] = started.tzinfo is not None and finished.tzinfo is not None and started > finished
        result['property_reproduced'] = (report['execution_valid'] is True and report['cleanup_verified'] is True
            and _same(report.get('observed_property'),reference['property']))
        if report['execution_valid'] and report['cleanup_verified']:
            current = signature(actual_attempt_dir,actual)
            result['actual_signature_sha256'] = candidates.fingerprint(current)
            for key in reference:
                matches = _same(reference[key],current[key])
                checks['signature.'+key] = matches
                if not matches:
                    result['differences'][key] = dict(reference_sha256=candidates.fingerprint(reference[key]),
                        actual_sha256=candidates.fingerprint(current[key]))
        result['full_match'] = bool(checks) and all(v is True for v in checks.values()) and result['actual_signature_sha256'] is not None
        result['classification'] = ('matched' if result['full_match'] else report['classification']
            if report['classification'] in ('timeout','invalid','infrastructure-error') else 'path-diverged')
        result['observed_candidate_classification'] = report['classification']
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['errors'].append(str(error))
    return result

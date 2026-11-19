"""K09 bounded FIFO and K08 evidence import. This module never starts a guest.

Candidate identity is immutable. Queue status and attempts are separate records;
an attempted candidate is never silently converted into schedule coverage.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from . import candidates

OUTCOMES = ('hit', 'miss', 'timeout', 'invalid', 'infrastructure-error')
FINAL_STATES = OUTCOMES + ('unsupported', 'budget-unexplored', 'scope-excluded',
                          'unattempted-interrupted')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _same(left, right):
    return candidates.canonical(left) == candidates.canonical(right)


def validate_pool(pool):
    """Validate format and complete identities, without asserting file provenance."""
    _require(isinstance(pool, dict) and set(pool) == {'schema_version', 'kind',
        'catalog_sha256', 'catalog', 'candidates', 'summary'}, 'Unexpected K08 pool fields')
    _require(type(pool['schema_version']) is int and pool['schema_version'] == 1
        and pool['kind'] == 'kconc.candidate-pool', 'Unsupported candidate-pool format')
    catalog = candidates.validate_catalog(pool['catalog'])
    _require(pool['catalog_sha256'] == candidates.fingerprint(catalog), 'Catalog hash mismatch')
    _require(_same(catalog, candidates.load_catalog()), 'Pool catalog differs from the fixed current inputs')
    rows = pool['candidates']
    _require(type(rows) is list, 'Pool candidates must be an array')
    ids = []
    for row in rows:
        candidates.validate_candidate(row)
        ids.append(row['candidate_id'])
    _require(len(set(ids)) == len(ids), 'Pool must merge complete duplicate identities before execution')
    expected = {(x['input_id'], order) for x in catalog['inputs'] for order in catalog['orders']}
    observed = {(x['identity']['input']['input_id'], x['identity']['baseline_order']) for x in rows}
    _require(observed <= expected, 'Candidate outside fixed finite inputs')
    summary = dict(expected_baselines=len(expected), observed_baselines=len(observed),
        unobserved_baselines=[dict(input_id=i, order=o) for i, o in sorted(expected - observed)],
        unique_candidates=len(rows), source_records=sum(len(x['sources']) for x in rows),
        executed_candidates=0, unobserved_branches='unknown', interleavings_covered=None,
        complete_search=False)
    _require(_same(pool['summary'], summary), 'Pool summary differs from complete candidate records')
    return pool


def revalidate_sources(pool):
    """Read and recompute every source; never modify archived K08 evidence.

    Return records for every imported source, including repeated imports. The
    original K08 analyzer is used with its dictionary source-map representation.
    This is a local integrity check, not authentication of an untrusted archive.
    """
    validate_pool(pool)
    from .lifecycle import load
    from .sampling import candidate_from_analysis
    analyzer = load('k09_import_k08_analysis', candidates.REPO / 'adapters/maccconc/k08_analysis.py')
    validated = []
    cache = {}
    for candidate in pool['candidates']:
        for number, source in enumerate(candidate['sources']):
            # The cache preserves duplicate provenance while avoiding repeated
            # decoding of the exact same hash-bound source in this import only.
            key = (candidate['candidate_id'], candidates.fingerprint(source))
            if key not in cache:
                trace = Path(source['trace_path'])
                _require(trace.is_absolute() and trace.parts[-3:] == ('guest', 'trace', 'baseline'),
                    'K08 source must identify its absolute guest/trace/baseline directory')
                root = trace.parents[2]
                _require(not root.resolve().is_relative_to(candidates.REPO.resolve()),
                    'Source evidence must remain outside the delivery repository')
                for name in candidates.TRACE_FILES:
                    _require(_sha(trace/name) == source['trace_sha256'][name], 'Source trace bytes changed: ' + name)
                files = {'analysis_sha256':'analysis.json', 'source_map_sha256':'source-map.jsonl',
                    'runtime_identity_sha256':'runtime-identity.json', 'guest_sha256':'guest/guest-result.json',
                    'task_sha256':'task.json'}
                for field, relative in files.items():
                    _require(candidates._sha(source.get(field)) and _sha(root/relative) == source[field],
                        'Source binding changed: ' + field)
                task = candidates._read_json(root/'task.json')
                outer = candidates._read_json(root/'result.json')
                _require(task.get('operation') == outer.get('operation') == 'sample.run'
                    and outer.get('status') == 'passed', 'Source is not a completed K08 sample')
                source_pool = candidates._read_json(root/'candidate.json')
                _require(outer.get('data', {}).get('candidate_sha256') == _sha(root/'candidate.json'),
                    'Source candidate file differs from its completed run')
                _require(type(source_pool.get('candidates')) is list and len(source_pool['candidates']) == 1,
                    'A K08 sample must contain one original candidate')
                original = source_pool['candidates'][0]
                candidates.validate_candidate(original)
                _require(_same(original['identity'], candidate['identity']) and original['sources'] == [source],
                    'Imported candidate/source differs from the original sample')
                scenario = task.get('scenario', {})
                expected = {key:candidate['identity']['input'][key] for key in ('family', 'case_id', 'mode')}
                expected['order'] = candidate['identity']['baseline_order']
                _require(_same(scenario, expected), 'Submitted sample differs from candidate identity')
                mapping = {}
                for line in (root/'source-map.jsonl').read_text(encoding='utf-8').splitlines():
                    row = json.loads(line, object_pairs_hook=candidates._pairs)
                    candidates.canonical(row)
                    _require(isinstance(row, dict) and row.get('raw_ip') not in mapping, 'Invalid source mapping')
                    mapping[row.get('raw_ip')] = row
                analysis = analyzer.analyze(trace, mapping, root/'guest/guest-result.json',
                    scenario['family'], scenario['order'])
                matches = all(analysis.get('observations', {}).get(k) == v for k, v in scenario.items())
                analysis['checks']['submitted_scenario_matches'] = matches
                analysis['passed'] = analysis['passed'] and matches
                _require(analysis['passed'] and _same(analysis, candidates._read_json(root/'analysis.json')),
                    'Original sample no longer passes exact K08 analysis')
                identity = candidates._read_json(root/'runtime-identity.json')
                _require(_same(identity, candidate['identity']['build_identity']), 'Source build identity differs')
                extra = {k:v for k,v in source.items() if k not in {'trace_path', 'trace_sha256', 'analysis_sha256'}}
                reconstructed = candidate_from_analysis(analysis, trace, identity, root/'analysis.json', extra)
                _require(_same(reconstructed, original), 'Reconstructed candidate differs from original source')
                cache[key] = dict(candidate_id=candidate['candidate_id'], source_sha256=key[1],
                    trace_path=str(trace), passed=True)
            validated.append(dict(cache[key], source_index=number))
    return dict(passed=True, source_records=len(validated), distinct_source_records=len(cache),
        records=validated, current_vm_checked=False, candidate_executed=False)


def load_pool(path, *, verify_sources=True):
    pool = validate_pool(candidates._read_json(path))
    if verify_sources:
        revalidate_sources(pool)
    return pool


def make_plan(candidate, spin_limit=1000000):
    """Encode an unchanged observed stack for physical slot A; no guest action."""
    candidates.validate_candidate(candidate)
    _require(type(spin_limit) is int and 1 <= spin_limit <= 1000000000, 'Invalid finite spin limit')
    stack = candidate['identity']['target']['event']['stack']
    text = f'MACCCONC_K03_PLAN_V1\nspin_limit {spin_limit}\nrole A\ncount {len(stack)}\n'
    text += ''.join(f"{int(frame['ip'], 16):016x} {frame['parent_idx']}\n" for frame in stack)
    return text.encode('ascii')


def eligibility(candidate, runtime_identity):
    """Check the explicit old-sampler/new-executor bridge, not source correctness."""
    candidates.validate_candidate(candidate)
    _require(isinstance(runtime_identity, dict), 'Runtime identity must be an object')
    original = candidate['identity']['build_identity']
    accepted = runtime_identity.get('inputs', {}).get('accepted_k08', {}).get('record', {})
    old_binaries = {row.get('name'):row.get('sha256') for row in accepted.get('binaries', []) if isinstance(row, dict)}
    current = runtime_identity.get('binaries', {})
    expected_names = {row['native_so'] for row in candidates.load_catalog()['inputs']}
    old_hashes = original.get('binaries', {})
    checks = {
        'kernel_and_k03_exact':_same(original.get('kernel_and_k03'), runtime_identity.get('kernel_and_k03'))
            and isinstance(original.get('kernel_and_k03'), dict) and bool(original['kernel_and_k03']),
        'catalog_exact':candidates._sha(original.get('catalog_sha256'))
            and original['catalog_sha256'] == runtime_identity.get('catalog_sha256'),
        'accepted_k08_record':accepted.get('passed') is True and accepted.get('kind') == 'kconc.sampler.build'
            and accepted.get('task') == 'K08',
        'old_k08_inputs_exact':isinstance(original.get('inputs'), dict) and bool(original['inputs'])
            and _same(original['inputs'], accepted.get('inputs')),
        'old_k08_binaries_exact':len(accepted.get('binaries', [])) == 16 and len(old_binaries) == 16
            and _same(old_hashes, old_binaries),
        'copied_scenario_bytes_exact':all(candidates._sha(old_hashes.get(name))
            and current.get(name) == old_hashes[name] for name in expected_names),
    }
    supported = all(checks.values())
    failed = [name for name, ok in checks.items() if not ok]
    return dict(supported=supported, reason='supported-fixed-marker' if supported else 'incompatible:' + ','.join(failed),
        checks=checks, failed_checks=failed,
        scope='Existing two-thread regmap marker protocol only; no arbitrary control-point adaptation')


def make_queue(pool, family, budget, runtime_identity):
    """Freeze source order and a one-attempt-per-candidate budget before running."""
    validate_pool(pool)
    _require(family in ('rmw', 'mutex'), 'Select one registered kernel family')
    _require(type(budget) is int and 0 <= budget <= 4096, 'Budget must be an integer from 0 to 4096')
    rows, selected = [], 0
    for index, candidate in enumerate(pool['candidates']):
        identity = candidate['identity']
        row = dict(candidate_id=candidate['candidate_id'], pool_index=index,
            input_id=identity['input']['input_id'], family=identity['input']['family'],
            order=identity['baseline_order'], access_id=identity['access_id'], attempts=[])
        if row['family'] != family:
            row.update(status='scope-excluded', reason='Other kernel family; not an unsupported candidate')
        else:
            support = eligibility(candidate, runtime_identity)
            row['eligibility'] = support
            if not support['supported']:
                row.update(status='unsupported', reason=support['reason'])
            elif selected >= budget:
                row.update(status='budget-unexplored', reason='Fixed attempt budget exhausted before this candidate')
            else:
                selected += 1
                row.update(status='pending', reason='Selected in immutable pool order')
        rows.append(row)
    return dict(schema_version=1, kind='kconc.search-ledger', family=family, budget=budget,
        pool_sha256=candidates.fingerprint(pool), order_policy='pool-order-no-feedback',
        candidates=rows, attempts=[], finalized=False, interrupted_reason=None,
        unobserved_branches='unknown', complete_search=False)


def begin_attempt(ledger, candidate_id, attempt_id):
    _require(not ledger['finalized'], 'Finalized ledger cannot start another attempt')
    _require(type(attempt_id) is str and bool(attempt_id) and all(a['attempt_id'] != attempt_id for a in ledger['attempts']),
        'Attempt identity must be unique and nonempty')
    _require(not any(row['status'] == 'running' for row in ledger['candidates']), 'Only one candidate may be active')
    pending = next((row for row in ledger['candidates'] if row['status'] == 'pending'), None)
    _require(pending is not None and pending['candidate_id'] == candidate_id, 'Execution cannot skip the frozen FIFO order')
    _require(len(ledger['attempts']) < ledger['budget'], 'Attempt budget exhausted')
    attempt = dict(attempt_id=attempt_id, ordinal=len(ledger['attempts']) + 1,
        candidate_id=candidate_id, outcome='running', guest_started=None,
        cleanup_confirmed=None, property_evaluated=False, property_violation=None, evidence={})
    ledger['attempts'].append(attempt)
    pending['attempts'].append(attempt_id)
    pending['status'] = 'running'
    return attempt


def finish_attempt(ledger, attempt_id, outcome, *, guest_started, cleanup_confirmed,
                   property_evaluated=False, property_violation=None, evidence=None):
    _require(not ledger['finalized'] and outcome in OUTCOMES, 'Invalid/finalized attempt outcome')
    matches = [row for row in ledger['attempts'] if row['attempt_id'] == attempt_id]
    _require(len(matches) == 1 and matches[0]['outcome'] == 'running', 'Attempt must be active and may finish only once')
    _require(type(guest_started) is bool and type(cleanup_confirmed) is bool and type(property_evaluated) is bool,
        'Execution/cleanup/property axes must be explicit booleans')
    _require(property_violation is None if not property_evaluated else type(property_violation) is bool,
        'Unevaluated property must remain unknown')
    _require(outcome not in ('hit', 'miss', 'timeout') or guest_started,
        'A control outcome requires an actual guest attempt')
    _require(outcome != 'hit' or cleanup_confirmed, 'A successful candidate hit requires confirmed cleanup')
    _require(not property_evaluated or outcome == 'hit', 'A nonmatching attempt cannot establish the candidate property')
    _require(evidence is None or isinstance(evidence, dict), 'Evidence references must be an object')
    attempt = matches[0]
    attempt.update(outcome=outcome, guest_started=guest_started, cleanup_confirmed=cleanup_confirmed,
        property_evaluated=property_evaluated, property_violation=property_violation,
        evidence=copy.deepcopy(evidence or {}))
    row = next(row for row in ledger['candidates'] if row['candidate_id'] == attempt['candidate_id'])
    row['status'] = outcome
    return attempt


def finalize(ledger, interrupted_reason=None):
    _require(not ledger['finalized'], 'Ledger was already finalized')
    _require(not any(row['status'] == 'running' for row in ledger['candidates']), 'Active attempt must be classified before finalization')
    pending = [row for row in ledger['candidates'] if row['status'] == 'pending']
    _require(not pending or type(interrupted_reason) is str and bool(interrupted_reason),
        'Unattempted selected candidates need an explicit interruption reason')
    for row in pending:
        row.update(status='unattempted-interrupted', reason=interrupted_reason)
    ledger.update(finalized=True, interrupted_reason=interrupted_reason)
    ledger['summary'] = summarize(ledger)
    return ledger


def summarize(ledger):
    rows, attempts = ledger['candidates'], ledger['attempts']
    counts = {state:sum(row['status'] == state for row in rows) for state in FINAL_STATES + ('pending', 'running')}
    _require(sum(counts.values()) == len(rows), 'Unknown candidate classification')
    return dict(total_candidates=len(rows), in_scope_candidates=len(rows)-counts['scope-excluded'],
        candidate_status=counts, attempts=len(attempts),
        attempt_outcomes={state:sum(a['outcome'] == state for a in attempts) for state in OUTCOMES + ('running',)},
        guest_started=sum(a['guest_started'] is True for a in attempts),
        property_evaluated=sum(a['property_evaluated'] is True for a in attempts),
        property_violations=sum(a['property_evaluated'] is True and a['property_violation'] is True for a in attempts),
        cleanup_unconfirmed=sum(a['cleanup_confirmed'] is not True for a in attempts),
        complete_search=False, unobserved_branches='unknown', coverage_claimed=False)

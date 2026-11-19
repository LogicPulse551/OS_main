"""Read-only, exact-source evidence import for K12 feedback.

Samples supply candidate features, never coverage. Historical counts come only
from checked completed runs and individually re-analyzed attempts. File hashes
check local integrity; they do not authenticate a hostile remote archive.
"""
from collections import Counter
import copy
import json
from pathlib import Path

from . import candidates
from .lifecycle import REPO, digest, load, read
from .sampling import candidate_from_analysis
from .search_queue import validate_pool, make_plan


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyzer():
    return load('k12_evidence_k11_analysis', REPO/'adapters/maccconc/k11_analysis.py')


def ordinary(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            'Evidence must be an absolute ordinary file: '+str(path))
    return path


def evidence(path):
    path = ordinary(path)
    return dict(path=str(path), sha256=digest(path))


def directory(value):
    path = Path(value)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(),
            'Evidence directory must be absolute and ordinary')
    require(not path.resolve().is_relative_to(REPO.resolve()),
            'Evidence must remain outside the delivery repository')
    return path


def mapping(path):
    rows = [json.loads(line, object_pairs_hook=candidates._pairs)
            for line in ordinary(path).read_text(encoding='utf-8').splitlines()]
    require(all(isinstance(row, dict) and isinstance(row.get('raw_ip'), str) for row in rows)
            and len({row['raw_ip'] for row in rows}) == len(rows), 'Invalid/duplicate source mapping')
    return {row['raw_ip']:row for row in rows}


def _pool(rows):
    catalog = candidates.load_catalog()
    rows = candidates.merge_candidates(rows)
    expected = {(x['input_id'], order) for x in catalog['inputs'] for order in catalog['orders']}
    observed = {(x['identity']['input']['input_id'], x['identity']['baseline_order']) for x in rows}
    value = dict(schema_version=1, kind='kconc.candidate-pool',
        catalog_sha256=candidates.fingerprint(catalog), catalog=catalog, candidates=rows,
        summary=dict(expected_baselines=len(expected), observed_baselines=len(observed),
            unobserved_baselines=[dict(input_id=i, order=o) for i,o in sorted(expected-observed)],
            unique_candidates=len(rows), source_records=sum(len(row['sources']) for row in rows),
            executed_candidates=0, unobserved_branches='unknown', interleavings_covered=None,
            complete_search=False))
    return validate_pool(value)


def verify_sample(value, module=None):
    """Recompute a K11 regression.sample without rewriting any source binding."""
    root = directory(value)
    module = analyzer() if module is None else module
    task = read(ordinary(root/'task.json'))
    require(task.get('operation') == 'regression.sample', 'Expected a K11 regression.sample')
    saved_pool = validate_pool(read(ordinary(root/'candidate.json')))
    require(type(saved_pool.get('candidates')) is list and len(saved_pool['candidates']) == 1,
            'A sample must contain exactly one candidate')
    candidate = candidates.validate_candidate(saved_pool['candidates'][0])
    require(len(candidate['sources']) == 1, 'Sample must retain exactly its original source')
    source = candidate['sources'][0]
    trace = root/'guest/trace/baseline'
    require(source['trace_path'] == str(trace), 'Original sample trace path differs')
    for name in candidates.TRACE_FILES:
        require(digest(ordinary(trace/name)) == source['trace_sha256'][name],
                'Sample raw trace changed: '+name)
    files = {'analysis_sha256':'analysis.json', 'source_map_sha256':'source-map.jsonl',
        'runtime_identity_sha256':'runtime-identity.json', 'guest_sha256':'guest/guest-result.json',
        'task_sha256':'task.json'}
    for key, name in files.items():
        require(source.get(key) == digest(ordinary(root/name)), 'Sample source binding changed: '+key)
    identity = read(root/'runtime-identity.json')
    require(candidate['identity']['build_identity'] == identity, 'Sample build identity differs')
    scenario = task.get('scenario', {})
    expected = {key:candidate['identity']['input'][key] for key in ('family','case_id','mode')}
    expected['order'] = candidate['identity']['baseline_order']
    require(scenario == expected, 'Submitted sample differs from candidate')
    guest = read(root/'guest/guest-result.json')
    require(source.get('run_id') == guest.get('run_id'), 'Sample guest identity differs')
    profile = module.verify_profile(read(ordinary(root/'repair-binding.json')))
    require(identity.get('repair_profile') == profile.identity, 'Sample repair profile differs')
    report = module.analyze_sample(trace, mapping(root/'source-map.jsonl'), guest,
                                  expected['family'], expected['order'], profile)
    matches = all(report.get('observations', {}).get(key) == val for key,val in scenario.items())
    report['checks']['submitted_scenario_matches'] = matches
    report['passed'] = report['passed'] and matches
    require(report['passed'] is True and report == read(root/'analysis.json'),
            'Sample no longer reproduces under its exact analyzer')
    result = read(ordinary(root/'sample-result.json'))
    require(result.get('passed') is True and result.get('recovery_required') is False
            and result.get('candidate_execution_performed') is False
            and result.get('candidate_sha256') == digest(root/'candidate.json')
            and result.get('analysis') == report, 'Sample completion does not bind its candidate/analysis')
    provenance = {k:v for k,v in source.items() if k not in
                  {'trace_path','trace_sha256','analysis_sha256'}}
    require(candidate_from_analysis(report, trace, identity, root/'analysis.json', provenance) == candidate,
            'Candidate differs from its rebuilt raw sample')
    return candidate, report, dict(passed=True, candidate_id=candidate['candidate_id'],
        directory=str(root), sample=evidence(root/'sample-result.json'), candidate=evidence(root/'candidate.json'),
        analysis=evidence(root/'analysis.json'), binding=evidence(root/'repair-binding.json'))


def load_samples(samples):
    """Merge only complete candidate duplicates; preserve every source record."""
    require(type(samples) is list and bool(samples), 'Nonempty sample directory list required')
    from .feedback_queue import feature
    module = analyzer()
    rows, records, features = [], [], {}
    for value in samples:
        candidate, analysis, record = verify_sample(value, module)
        key = candidate['candidate_id']
        item = feature(candidate, analysis)
        require(key not in features or features[key] == item, 'Identical candidate has different observed feature')
        rows.append(candidate);records.append(record);features[key] = item
    pool = _pool(rows)
    return pool, dict(kind='kconc.feedback-sample-import', passed=True, records=records,
        features=features, source_records=len(records), unique_candidates=len(pool['candidates']),
        pool_sha256=candidates.fingerprint(pool), candidate_executed=False, current_vm_checked=False)


def verify_attempt(value, candidate, runtime_identity, module=None):
    """Check actual request/plan/raw execution before using its feedback."""
    root = directory(value)
    module = analyzer() if module is None else module
    candidates.validate_candidate(candidate)
    require(read(ordinary(root/'candidate.json')) == candidate, 'Attempt uses another candidate')
    identity = read(ordinary(root/'runtime-identity.json'))
    require(identity == runtime_identity == candidate['identity']['build_identity'],
            'Attempt kernel/native identity differs')
    profile = module.verify_profile(read(ordinary(root/'repair-binding.json')))
    require(profile.identity == identity.get('repair_profile'), 'Attempt repair profile differs')
    plan = ordinary(root/'input-plan.txt').read_bytes()
    require(plan == make_plan(candidate), 'Submitted plan differs from the complete candidate stack')
    trace = root/'guest/trace'
    require(ordinary(trace/'plan.txt').read_bytes() == plan, 'Executed plan differs from submitted plan')
    guest = read(ordinary(root/'guest/guest-result.json'))
    request = read(ordinary(root/'guest-request.json'))
    order = candidate['identity']['baseline_order']
    command = [request['executable'], request['scenario_library'], '--k09-execute', order,
               request['plan_path'], request['plan_path'].rsplit('/',1)[0]+'/trace']
    require(guest.get('run_id') == request.get('run_id') and guest.get('command') == command
            and guest.get('fault') == request.get('fault') == 'none', 'Guest not bound to submitted request')
    report = module.analyze_execution(trace, mapping(root/'source-map.jsonl'), guest, candidate, profile)
    report['checks']['executed_plan_matches_submitted'] = True
    report.update(runtime_identity_bound=True, runtime_identity_sha256=digest(root/'runtime-identity.json'),
        candidate_file_sha256=digest(root/'candidate.json'), plan_sha256=digest(root/'input-plan.txt'))
    require(report == read(ordinary(root/'analysis.json')), 'Historical raw analysis no longer reproduces')
    result = read(ordinary(root/'attempt-result.json'))
    require(result.get('candidate_id') == candidate['candidate_id'] and result.get('guest_started') is True
            and result.get('guest') == guest and result.get('analysis') == report
            and result.get('classification') == report['classification']
            and result.get('recovery_required') == report['recovery_required']
            and result.get('passed') == report['passed'], 'Attempt completion differs from raw analysis')
    return report, dict(directory=str(root), analysis_sha256=digest(root/'analysis.json'),
                        result_sha256=digest(root/'attempt-result.json'), guest_run_id=guest['run_id'])


def execution_feature(value, candidate, analysis):
    """Extract actual execution accesses after binding every original raw file."""
    from .feedback_queue import feature
    root=directory(value);trace=root/'guest/trace'
    for name in candidates.TRACE_FILES:
        require(digest(ordinary(trace/name)) == analysis.get('artifacts',{}).get(name),
                'Execution feature raw binding changed: '+name)
    sources=mapping(root/'source-map.jsonl')
    module=analyzer();projection={}
    for slot in ('A','B'):
        projection[slot]=[]
        for event in module.k06.k03.read_events(trace,slot):
            if event.get('kind')!='MEMORY':continue
            source=sources.get(event['ip'],{})
            projection[slot].append(dict(event=event,source=source,physical_slot=slot))
    return feature(candidate,analysis,projection=projection)


def load_history(paths, pool):
    """Import finalized K12 attempts; never trust user-supplied feature counts."""
    require(type(paths) is list, 'History must be a directory list')
    validate_pool(pool)
    from .feedback_queue import feature
    current = {row['candidate_id']:row for row in pool['candidates']}
    module = analyzer()
    records, runs, seen, guest_runs = [], [], {}, set()
    duplicates = 0
    for value in paths:
        root = directory(value)
        result = read(ordinary(root/'feedback-result.json'))
        envelope = read(ordinary(root/'result.json'))
        ledger = read(ordinary(root/'ledger.json'))
        original_pool = validate_pool(read(ordinary(root/'imported-pool.json')))
        identity = read(ordinary(root/'runtime-identity.json'))
        require(result.get('kind') == 'kconc.feedback-search' and type(result.get('passed')) is bool
                and envelope.get('operation') == 'kernel.explore'
                and envelope.get('data') == result
                and envelope.get('status') == ('passed' if result['passed'] else 'failed'),
                'Not a completed K12 feedback run')
        require(ledger.get('finalized') is True and type(ledger.get('attempts')) is list,
                'Historical ledger is not finalized')
        require(result.get('ledger_sha256') == digest(root/'ledger.json')
                and result.get('runtime_identity_sha256') == digest(root/'runtime-identity.json')
                and result.get('imported_pool_sha256') == digest(root/'imported-pool.json')
                and result.get('history_validation_sha256') == digest(ordinary(root/'history-validation.json')),
                'Historical run file binding changed')
        originals = {row['candidate_id']:row for row in original_pool['candidates']}
        require(ledger.get('pool_sha256') == candidates.fingerprint(original_pool),
                'Historical ledger belongs to another candidate pool')
        run_rows = []
        for ordinal, row in enumerate(ledger['attempts'], 1):
            cid = row.get('candidate_id');attempt_id = row.get('attempt_id')
            require(cid in originals and cid in current and type(attempt_id) is str and bool(attempt_id)
                    and row.get('ordinal') == ordinal, 'History candidate/attempt identity differs')
            candidate = originals[cid]
            require(candidate['identity'] == current[cid]['identity'], 'Historical complete candidate identity differs')
            details = row.get('evidence', {})
            require(isinstance(details, dict), 'Missing attempt evidence')
            attempt_root = directory(details.get('directory', ''))
            require(attempt_root == root/f'attempt-{ordinal:03d}', 'History attempt escaped its run')
            if row.get('outcome') == 'infrastructure-error' and (attempt_root/'exception.json').exists():
                exc = read(ordinary(attempt_root/'exception.json'))
                require(details.get('exception_sha256') == digest(attempt_root/'exception.json')
                        and type(exc.get('guest_started')) is bool
                        and exc['guest_started'] == row.get('guest_started')
                        and row.get('cleanup_confirmed') is False
                        and row.get('property_evaluated') is False and row.get('property_violation') is None,
                        'Unfinished infrastructure attempt lacks checked exception evidence')
                require(row.get('candidate_hit') is False and row.get('recovery_required') is True,
                        'Infrastructure failure cannot claim a clean candidate hit')
                report = dict(classification='infrastructure-error', candidate_hit=False,
                    property_evaluated=False, property_violation=None, cleanup_verified=False, recovery_required=True)
                proof = dict(directory=str(attempt_root), exception_sha256=digest(attempt_root/'exception.json'))
                observed_feature = None
            else:
                report, proof = verify_attempt(attempt_root, candidate, identity, module)
                require(details.get('analysis_sha256') == proof['analysis_sha256']
                        and details.get('result_sha256') == proof['result_sha256'], 'Attempt evidence hash changed')
                require(row.get('guest_started') is True, 'Raw execution must retain guest_started')
                fields = {'outcome':'classification','cleanup_confirmed':'cleanup_verified',
                    'property_evaluated':'property_evaluated','candidate_hit':'candidate_hit',
                    'recovery_required':'recovery_required'}
                require(all(row.get(k) == report[v] for k,v in fields.items()),
                        'Historical aggregate differs from re-analyzed attempt')
                require(row.get('property_violation') == (report['property_violation']
                        if report['property_evaluated'] else None), 'Historical property verdict differs')
                observed_feature = execution_feature(attempt_root,candidate,report) if report['classification']=='hit' else None
            require(row.get('observed_feature') == observed_feature,
                    'Historical observed feature differs from actual execution')
            task = read(ordinary(attempt_root/'task.json'))
            require(task.get('candidate_id') == cid and task.get('attempt_id') == attempt_id,
                    'Attempt task identity differs')
            normalized = dict(candidate_id=cid, input_id=candidate['identity']['input']['input_id'],
                attempt_id=attempt_id, outcome=report['classification'], candidate_hit=report['candidate_hit'],
                property_evaluated=report['property_evaluated'], property_violation=report['property_violation']
                    if report['property_evaluated'] else None,
                cleanup_confirmed=report['cleanup_verified'], recovery_required=report['recovery_required'],
                guest_started=row['guest_started'], observed_feature=observed_feature, evidence=proof)
            if attempt_id in seen:
                require(seen[attempt_id] == normalized, 'Repeated attempt identity has different evidence')
                duplicates += 1
            else:
                run_id = proof.get('guest_run_id')
                require(run_id is None or run_id not in guest_runs, 'One guest execution was assigned two attempts')
                if run_id is not None:guest_runs.add(run_id)
                seen[attempt_id] = normalized;records.append(normalized)
            run_rows.append(attempt_id)
        require({p.name for p in root.glob('attempt-*') if p.is_dir()} ==
                {f'attempt-{i:03d}' for i in range(1,len(run_rows)+1)}, 'History contains unrecorded attempts')
        runs.append(dict(directory=str(root), result=evidence(root/'feedback-result.json'),
            envelope=evidence(root/'result.json'), ledger=evidence(root/'ledger.json'), attempt_ids=run_rows))
    return records, dict(kind='kconc.feedback-history-import', passed=True, runs=runs,
        attempts=len(records), duplicate_attempt_records=duplicates,
        outcomes=dict(Counter(row['outcome'] for row in records)),
        verified_hits=sum(row['outcome']=='hit' and row['candidate_hit'] is True
            and row['property_evaluated'] is True and row['cleanup_confirmed'] is True
            and row['recovery_required'] is False for row in records),
        historical_guest_executions=len(guest_runs), current_guest_executions=0)

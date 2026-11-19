"""Finite K08 observations and marker candidates; this module executes nothing.

Complete candidate identities are deduplicated. Raw prefixes retain addresses,
values and timestamps conservatively; clocks never establish inter-thread order.
Evidence validation is performed by k08_analysis before construction. This layer
also checks its input, prefix, marker and occurrence bindings for consistency.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from . import mutex_oracle, regmap_oracle

REPO = Path(__file__).resolve().parents[2]
CATALOG = REPO / 'configs/scenarios/k08-inputs.json'
FAMILIES = {'rmw': (regmap_oracle, 2, 'regmap-rmw-v1', 'k06'),
            'mutex': (mutex_oracle, 3, 'regmap-mutex-v1', 'k07')}
ROLES = {'A': {'role': 0, 'callback': 'test_thread1'},
         'B': {'role': 1, 'callback': 'test_thread2'}}
WIDTH = {'MEMORY': 5, 'ENTRY': 2, 'EXIT': 1, 'NORMAL': 1,
         'EESUM': 1, 'WAIT': 1, 'WAKE': 1}
TRACE_FILES = ('run.json', 'testcase.stdout.txt', 'A.words', 'B.words',
               'A.events.jsonl', 'B.events.jsonl')
HEX = re.compile(r'0x[0-9a-f]{16}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    """A strict JSON identity: no float, implicit key conversion or NaN."""
    def check(item):
        if isinstance(item, dict):
            require(all(type(k) is str for k in item), 'JSON keys must be strings')
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        else:
            require(type(item) in (str, int, bool, type(None)), 'Noncanonical JSON value')
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def _read_json(path):
    def reject(value):
        raise ValueError('Non-finite JSON value: ' + value)
    result = json.loads(Path(path).read_text(encoding='utf-8'),
                        object_pairs_hook=_pairs, parse_constant=reject)
    canonical(result)
    return result


def _uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def _sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def _expected_input(family, case_id, mode):
    require(type(family) is str and family in FAMILIES, 'Unknown input family')
    oracle, abi, scenario, task = FAMILIES[family]
    spec = oracle.case_spec(case_id)
    oracle.validate_case(case_id, mode, spec['initial'], spec['operations'])
    return dict(input_id=f'{family}:{case_id}:{mode}', family=family, scenario=scenario,
                abi=abi, case_id=case_id, mode=mode, **spec,
                native_so=f'regmap-{task}-{case_id}-{mode}.so')


def validate_input(entry):
    require(isinstance(entry, dict), 'Input must be an object')
    expected = _expected_input(entry.get('family'), entry.get('case_id'), entry.get('mode'))
    require(canonical(entry) == canonical(expected), 'Catalog input differs from accepted case')
    return entry


def validate_catalog(catalog):
    require(isinstance(catalog, dict), 'Catalog must be an object')
    require(type(catalog.get('schema_version')) is int and catalog['schema_version'] == 1,
            'Unknown catalog schema')
    require(catalog.get('kind') == 'kconc.finite-inputs', 'Unknown catalog kind')
    require(catalog.get('orders') == ['ab', 'ba'], 'Both sampling orders are required')
    require(canonical(catalog.get('logical_roles')) == canonical(ROLES), 'Logical role contract changed')
    rows = catalog.get('inputs')
    require(type(rows) is list and len(rows) == 14, 'Exactly fourteen inputs are required')
    ids = [validate_input(row)['input_id'] for row in rows]
    wanted = {f'{family}:{case_id}:{mode}' for family, (oracle, _, _, _) in FAMILIES.items()
              for case_id in oracle.CASES for mode in oracle.MODES}
    require(len(set(ids)) == len(ids) and set(ids) == wanted, 'Missing or duplicate catalog input')
    canonical(catalog)
    return catalog


def load_catalog(path=CATALOG):
    return validate_catalog(_read_json(path))


def get_input(catalog, family, case_id, mode):
    validate_catalog(catalog)
    expected = _expected_input(family, case_id, mode)
    return copy.deepcopy(next(row for row in catalog['inputs'] if row == expected))


def _validate_source(source):
    require(isinstance(source, dict), 'Missing candidate provenance')
    require(type(source.get('trace_path')) is str and bool(source['trace_path']), 'Missing trace path')
    require(_sha(source.get('analysis_sha256')), 'Missing validation-report hash')
    hashes = source.get('trace_sha256')
    require(isinstance(hashes, dict) and all(_sha(hashes.get(name)) for name in TRACE_FILES),
            'Every raw trace artifact must be hashed')
    canonical(source)


def _validate_prefix_target(prefix, target, order, marker_source):
    first = order[0].upper()
    require(isinstance(prefix, dict) and isinstance(target, dict), 'Missing observed prefix/target')
    require(prefix.get('physical_slot') == target.get('physical_slot') == 'A', 'Target must use first execution slot')
    require(prefix.get('logical_role') == target.get('logical_role') == first, 'Target logical role changed')
    require(prefix.get('basis') == 'verified-sequential-baseline', 'Unsupported prefix origin')
    require(prefix.get('observed_baseline_order') == order and prefix.get('completed_logical_roles') == [],
            'Prefix contains an unobserved earlier handoff or completed operation')
    events, event = prefix.get('events'), target.get('event')
    require(type(events) is list and isinstance(event, dict), 'Missing raw prefix events')
    offset, memory = 0, []
    for previous in events:
        require(isinstance(previous, dict) and previous.get('thread') == 'A', 'Prefix must keep physical slot A')
        require(previous.get('kind') in WIDTH, 'Unknown prefix event kind')
        require(previous['kind'] not in ('WAIT', 'WAKE'), 'New switched prefixes need a separately supported protocol')
        require(_uint(previous.get('word_index')) and previous['word_index'] == offset, 'Noncontiguous prefix')
        offset += WIDTH[previous['kind']]
        if previous['kind'] == 'MEMORY':
            memory.append(previous)
    require(event.get('kind') == 'MEMORY' and event.get('thread') == 'A', 'Target is not a first-slot memory access')
    require(_uint(event.get('word_index')) and event['word_index'] == offset, 'Target does not follow actual prefix')
    stack = event.get('stack')
    require(type(stack) is list and 2 <= len(stack) <= 32, 'Target stack is outside fixed executor format')
    for frame in stack:
        require(isinstance(frame, dict) and type(frame.get('ip')) is str and HEX.fullmatch(frame['ip'])
                and int(frame['ip'], 16) >= 0xffffffff80000000 and _uint(frame.get('parent_idx')), 'Invalid target frame')
    require(event.get('ip') == stack[-1]['ip'], 'Target IP and stack differ')
    for field in ('address', 'value', 'timestamp'):
        require(type(event.get(field)) is str and HEX.fullmatch(event[field]), 'Invalid target ' + field)
    require(type(event.get('size')) is int and event['size'] == 4 and _uint(event.get('flags'), 0xffffffff)
            and event['flags'] & 0x1f == 0x10 and not event['flags'] & 0x20, 'Target is not the declared marker store')
    expected = dict(access_index=len(memory), call_depth=len(stack),
                    same_ip_occurrence=1 + sum(x.get('ip') == event['ip'] for x in memory),
                    full_stack_occurrence=1 + sum(x.get('stack') == stack for x in memory))
    require(all(_uint(target.get(k)) and target[k] == v for k, v in expected.items()), 'Access occurrence/depth mismatch')
    source = target.get('source')
    require(isinstance(marker_source, dict) and _sha(marker_source.get('source_sha256')), 'Missing marker source identity')
    require(marker_source.get('file') == 'drivers/base/regmap/kconc-regmap.c'
            and marker_source.get('symbol') == 'kconc_regmap_checkpoint'
            and _uint(marker_source.get('line')) and marker_source['line'] > 0, 'Unsupported control-point source')
    require(isinstance(source, dict) and type(source.get('file')) is str, 'Missing target source mapping')
    filename = source['file'].replace('\\', '/')
    require((filename == marker_source['file'] or filename.endswith('/' + marker_source['file']))
            and source.get('symbol') == marker_source['symbol'] and type(source.get('line')) is int
            and source['line'] == marker_source['line'] and source.get('exact_line') is True,
            'Arbitrary kernel access is not a supported safe control point')


def _repair_profile(build_identity, family):
    """Validate a declared variant; live/archived build verification is separate."""
    if 'repair_profile' not in build_identity:
        return None
    profile = build_identity['repair_profile']
    fields = {'profile_id', 'family', 'kernel_record_sha256', 'native_record_sha256', 'driver_sha256', 'repair_patch_sha256'}
    require(isinstance(profile, dict) and set(profile) == fields
            and profile.get('profile_id') == 'kconc.k11.regmap-repair-v1'
            and profile.get('family') == family
            and all(_sha(profile.get(key)) for key in fields - {'profile_id', 'family'}),
            'Invalid explicitly bound repair profile')
    return profile


def _support(family, mode, repair_profile=None):
    result = dict(status='candidate-only', candidate_execution='not-executed',
                protocol='physical-A-pause-before-marker / physical-B-completes / physical-A-resumes',
                scope='Declared regmap marker only; arbitrary memory conflicts are unsupported',
                held_locks=('tested sleeping mutex; peer uses nonblocking trylock; observer and regmap locks released'
                            if family == 'mutex' else 'no regmap lock at the declared marker'),
                marker_position=('before locked update API' if family == 'rmw' and mode == 'update-bits'
                                 else 'between split read and write' if family == 'rmw' else 'inside declared caller critical interval'),
                interleaved_suffix='unobserved', unobserved_branches='unknown',
                coverage_claim=False, global_event_order=False, reads_from_inferred=False)
    if repair_profile is not None:
        result['repair_profile_id'] = repair_profile['profile_id']
        if family == 'rmw':
            result['held_locks'] = 'no update guard or regmap lock at the declared marker'
            result['marker_position'] = 'before shared update guard and real regmap operation'
        else:
            result['held_locks'] = 'repaired shared sleeping mutex for both requested modes; peer uses nonblocking trylock; observer and regmap locks released'
    return result


def _schedule(order):
    first, second = (letter.upper() for letter in order)
    return dict(pattern='-'.join((first, second, first)), logical_roles=[first, second, first],
                physical_slots=['A', 'B', 'A'], switch_before='target-access',
                resume_after='peer-operation-completed', required_switches=2)


def observed_initial_state(analysis):
    """Return the full recorded initial observation, without inventing fields.

    ABI 2 exports its observation directly in the initial-state phase; ABI 3
    exports the complete status struct under that phase's ``initial`` field.
    """
    obs = analysis.get('observations', {})
    rows = obs.get('phases')
    require(type(rows) is list and len(rows) == 5 and isinstance(rows[1], dict),
            'Missing initial-state phase')
    require(obs.get('family') in FAMILIES, 'Unknown initial-state family')
    return copy.deepcopy(rows[1] if obs['family'] == 'rmw' else rows[1].get('initial'))


def _validate_identity(identity):
    require(isinstance(identity, dict), 'Missing candidate identity')
    entry = validate_input(identity.get('input'))
    require(isinstance(identity.get('build_identity'), dict) and bool(identity['build_identity']), 'Missing exact build identity')
    initial = identity.get('initial_state')
    require(isinstance(initial, dict) and regmap_oracle.vector(initial.get('values'))
            and initial['values'] == entry['initial']
            and _uint(initial.get('epoch')) and initial['epoch'] > 0, 'Initial state differs from input/ABI')
    if entry['family'] == 'mutex':
        require(type(initial.get('abi')) is int and initial['abi'] == entry['abi'], 'Initial-state ABI mismatch')
    else:
        require(initial.get('phase') == 'initial_state' and initial.get('passed') is True,
                'Missing ABI 2 initial-state phase observation')
    require(identity.get('initial_state_id') == fingerprint(initial), 'Initial-state identity mismatch')
    order = identity.get('baseline_order')
    require(order in ('ab', 'ba'), 'Unknown sampling order')
    require(identity.get('slot_to_logical_role') == dict(zip(('A', 'B'), order.upper())), 'Slot/role mapping mismatch')
    require(identity.get('logical_roles') == ROLES, 'Logical operations have been relabelled')
    _validate_prefix_target(identity.get('observed_prefix'), identity.get('target'), order, identity.get('marker_source'))
    target = identity['target']
    require(identity.get('access_id') == fingerprint(target), 'Target-access identity mismatch')
    require(identity.get('schedule') == _schedule(order), 'Proposed switch sequence mismatch')
    repair_profile = _repair_profile(identity['build_identity'], entry['family'])
    require(repair_profile is None or identity['marker_source']['source_sha256'] == repair_profile['driver_sha256'],
            'Candidate marker does not belong to its repaired driver')
    require(identity.get('support') == _support(entry['family'], entry['mode'], repair_profile), 'Unsupported execution/coverage claim')
    canonical(identity)


def make_candidate(entry, build_identity, initial_state, analysis, source):
    """Bind one validated first-slot marker; do not reuse a peer's baseline prefix.

    ``analysis`` is k08_analysis.analyze's complete report. ``source`` contains
    trace_path, trace_sha256 (all six raw artifacts) and analysis_sha256 (report
    file bytes). Additional provenance fields are preserved without filtering.
    """
    validate_input(entry)
    require(isinstance(analysis, dict) and analysis.get('passed') is True, 'A failed observation cannot generate a candidate')
    checks = analysis.get('checks')
    require(isinstance(checks, dict) and bool(checks) and all(v is True for v in checks.values())
            and analysis.get('errors') == [], 'Missing or failed observation checks')
    obs = analysis.get('observations', {})
    require(all(obs.get(k) == entry[k] for k in ('family', 'case_id', 'mode')), 'Analysis belongs to a different input')
    order = obs.get('order')
    require(order in ('ab', 'ba'), 'Analysis has no supported baseline order')
    first = order[0].upper()
    markers = obs.get('markers', {}).get(first)
    require(type(markers) is list and len(markers) == 1, 'Exactly one observed first-role marker required')
    target, prefix = markers[0], obs.get('observed_prefix')
    phases = obs.get('phases')
    require(canonical(observed_initial_state(analysis)) == canonical(initial_state),
            'Initial state is not the validated phase snapshot')
    require(all(phases[0].get(k) == entry[k] for k in ('case_id', 'mode', 'initial', 'operations')),
            'Observed logical inputs differ from the catalog')
    _validate_prefix_target(prefix, target, order, obs.get('marker_source'))
    trace = obs.get('trace_events', {}).get(first)
    require(type(trace) is list and len(trace) > len(prefix['events'])
            and trace[:len(prefix['events'])] == prefix['events'] and trace[len(prefix['events'])] == target['event'],
            'Target prefix was not observed in this trace')
    _validate_source(source)
    for name in TRACE_FILES:
        require(analysis.get('artifacts', {}).get(name) == source['trace_sha256'][name], 'Trace provenance differs from validation report: ' + name)
    identity = dict(build_identity=build_identity, input=entry, initial_state=initial_state,
                    initial_state_id=fingerprint(initial_state), baseline_order=order,
                    slot_to_logical_role=obs.get('slot_to_role'), logical_roles=ROLES,
                    observed_prefix=prefix, target=target, access_id=fingerprint(target),
                    marker_source=obs.get('marker_source'), schedule=_schedule(order),
                    support=_support(entry['family'], entry['mode'], _repair_profile(build_identity, entry['family'])))
    _validate_identity(identity)
    return copy.deepcopy(dict(schema_version=1, kind='kconc.marker-candidate',
                              candidate_id=fingerprint(identity), identity=identity, sources=[source]))


def validate_candidate(candidate):
    require(isinstance(candidate, dict) and type(candidate.get('schema_version')) is int
            and candidate['schema_version'] == 1 and candidate.get('kind') == 'kconc.marker-candidate', 'Unknown candidate format')
    require(set(candidate) == {'schema_version', 'kind', 'candidate_id', 'identity', 'sources'}, 'Unexpected candidate fields')
    _validate_identity(candidate.get('identity'))
    require(candidate.get('candidate_id') == fingerprint(candidate['identity']), 'Candidate identity hash mismatch')
    require(type(candidate.get('sources')) is list and bool(candidate['sources']), 'Candidate provenance cannot be empty')
    for source in candidate['sources']:
        _validate_source(source)
    return candidate


def merge_candidates(candidates):
    """Merge only complete identical identities; preserve *every* source record."""
    merged = {}
    for candidate in candidates:
        validate_candidate(candidate)
        key = candidate['candidate_id']
        if key in merged:
            require(canonical(merged[key]['identity']) == canonical(candidate['identity']), 'Candidate hash collision')
            merged[key]['sources'].extend(copy.deepcopy(candidate['sources']))
        else:
            merged[key] = copy.deepcopy(candidate)
    return list(merged.values())


def export_candidates(path, candidates, catalog=None):
    """Write an exclusive pool file and return it; sampling is not coverage."""
    catalog = load_catalog() if catalog is None else validate_catalog(catalog)
    rows = merge_candidates(candidates)
    expected = {(row['input_id'], order) for row in catalog['inputs'] for order in catalog['orders']}
    observed = {(row['identity']['input']['input_id'], row['identity']['baseline_order']) for row in rows}
    require(observed <= expected, 'Candidate outside finite input set')
    result = dict(schema_version=1, kind='kconc.candidate-pool',
                  catalog_sha256=fingerprint(catalog), catalog=copy.deepcopy(catalog), candidates=rows,
                  summary=dict(expected_baselines=len(expected), observed_baselines=len(observed),
                               unobserved_baselines=[dict(input_id=i, order=o) for i, o in sorted(expected - observed)],
                               unique_candidates=len(rows), source_records=sum(len(row['sources']) for row in rows),
                               executed_candidates=0, unobserved_branches='unknown',
                               interleavings_covered=None, complete_search=False))
    path = Path(path).resolve()
    require(not path.is_relative_to(REPO.resolve()), 'Candidate evidence belongs outside the code repository')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    return result

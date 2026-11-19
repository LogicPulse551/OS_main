"""K12 finite feedback scheduling. No file import, guest or coverage proof.

The caller verifies samples/history before supplying them. Coarse conflict pairs
affect priority only; complete candidate identities and every excluded/untried
row remain intact. A hit counts as observed only after all execution axes pass.
"""
from __future__ import annotations

import copy
from collections import Counter

from . import candidates, search_queue

POLICY_ID = 'kconc.k12.regmap-pair-feedback-v1'
FEATURE_ID = 'kconc.k12.observed-regmap-location-pairs-v1'
OUTCOMES = search_queue.OUTCOMES
TERMINAL = OUTCOMES + ('scope-excluded', 'unsupported', 'pool-unexplored',
    'input-budget-unexplored', 'budget-unexplored', 'unattempted-interrupted')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _number(value, name, maximum=4096):
    require(type(value) is int and 0 <= value <= maximum, 'Invalid '+name)
    return value


def feature(candidate, verified_analysis, *, projection=None):
    """Summarize actual cross-thread overlapping regmap accesses, not values.

    Linux/MAccConc KCOV_MEMORY uses bit 0x10 for writes. Raw addresses establish
    overlap only within this observed sample; source locations form a coarse
    signature. There is no inferred inter-thread order or reads-from relation.
    """
    candidates.validate_candidate(candidate)
    analysis = verified_analysis
    require(isinstance(analysis, dict) and analysis.get('passed') is True
        and analysis.get('errors') == [], 'Feature requires a verified sample')
    identity = candidate['identity'];obs = analysis.get('observations', {})
    require(all(obs.get(k) == identity['input'][k] for k in ('family', 'case_id', 'mode'))
        and obs.get('order') == identity['baseline_order'], 'Feature sample input differs')
    execution = 'candidate_id' in analysis
    if execution:
        require(analysis['candidate_id'] == candidate['candidate_id'] and analysis.get('classification') == 'hit'
            and all(analysis.get(key) is True for key in ('candidate_hit','execution_valid','control_valid',
                'target_matches','prefix_matches','schedule_valid','cleanup_verified','property_evaluated'))
            and analysis.get('recovery_required') is False, 'Feature execution is not a fully verified candidate hit')
        require(projection is not None, 'Execution features need the actual verified raw memory projection')
    else:
        require(projection is None, 'A sample must use its own bound memory projection')
        require(obs.get('target') == identity['target'] and obs.get('observed_prefix') == identity['observed_prefix'],
            'Feature sample target/prefix differs')
    rows = projection if execution else obs.get('projection')
    require(isinstance(rows, dict) and set(rows) == {'A', 'B'}, 'Missing observed memory projection')
    if not execution:
        # K08/K11 sample observations index projections by logical role. Raw
        # events still carry physical callback slots, including in B-A samples.
        slots = dict(zip(('A','B'), identity['baseline_order'].upper()))
        require(obs.get('slot_to_role') == slots, 'Sample physical/logical role mapping differs')
        rows = {physical:rows[logical] for physical,logical in slots.items()}
    unmapped = dict(A=0, B=0)
    def accesses(slot):
        result = []
        require(type(rows[slot]) is list, 'Projection must contain actual accesses')
        for row in rows[slot]:
            event, source = row.get('event', {}), row.get('source', {})
            path = source.get('file', '').replace('\\', '/')
            marker = '/drivers/base/regmap/'
            if marker not in path or event.get('kind') != 'MEMORY':
                continue
            if not (source.get('found') is True and type(source.get('line')) is int
                    and source['line'] > 0 and type(source.get('symbol')) is str and source['symbol']):
                # A function-only mapping can be valid raw evidence. It lacks
                # the source location needed by this optional coarse feature.
                # Preserve that unknown explicitly rather than guessing a line.
                unmapped[slot] += 1
                continue
            require(event.get('thread') == slot and row.get('physical_slot') == slot
                and candidates.HEX.fullmatch(event.get('address', '')) is not None
                and type(event.get('size')) is int and 0 < event['size'] <= 4096
                and type(event.get('flags')) is int and event['flags'] >= 0
                and type(event.get('word_index')) is int and event['word_index'] >= 0,
                'Malformed observed conflict access')
            location = dict(file='drivers/base/regmap/'+path.split(marker, 1)[1],
                symbol=source['symbol'], line=source['line'], size=event['size'],
                access='write' if event['flags'] & 0x10 else 'read')
            result.append((int(event['address'], 16), event['size'], location, event['word_index']))
        return result
    left, right = accesses('A'), accesses('B')
    pairs = {}
    for address_a, size_a, location_a, word_a in left:
        for address_b, size_b, location_b, word_b in right:
            if max(address_a, address_b) >= min(address_a+size_a, address_b+size_b):
                continue
            if location_a['access'] == location_b['access'] == 'read':
                continue
            key = dict(build_id=candidates.fingerprint(identity['build_identity']),
                family=identity['input']['family'], order=identity['baseline_order'],
                first=location_a, peer=location_b)
            pair_id = candidates.fingerprint(key)
            if pair_id not in pairs:
                pairs[pair_id] = dict(pair_id=pair_id, identity=key, observations=0,
                    witness=dict(first_word_index=word_a, peer_word_index=word_b,
                        overlapping_address=hex(max(address_a, address_b))))
            pairs[pair_id]['observations'] += 1
    return dict(schema_version=1, kind=FEATURE_ID, candidate_id=candidate['candidate_id'],
        analysis_fingerprint=candidates.fingerprint(analysis), observation_kind='execution' if execution else 'sample',
        projection_fingerprint=candidates.fingerprint(rows), pairs=[pairs[k] for k in sorted(pairs)],
        regmap_accesses=dict(A=len(left), B=len(right)), unmapped_regmap_accesses=unmapped,
        unobserved_conflicts='unknown', global_order_inferred=False, reads_from_inferred=False)


def _validate_feature(record, candidate):
    require(isinstance(record, dict) and record.get('schema_version') == 1
        and record.get('kind') == FEATURE_ID and record.get('candidate_id') == candidate['candidate_id']
        and candidates._sha(record.get('analysis_fingerprint')) and candidates._sha(record.get('projection_fingerprint'))
        and record.get('observation_kind') in ('sample','execution'), 'Feature not bound to this sample candidate')
    pairs = record.get('pairs');require(type(pairs) is list, 'Missing conflict pair features')
    seen = set()
    for pair in pairs:
        require(isinstance(pair, dict) and candidates._sha(pair.get('pair_id'))
            and pair['pair_id'] == candidates.fingerprint(pair.get('identity'))
            and pair['pair_id'] not in seen, 'Malformed/duplicate conflict feature')
        require(pair['identity'].get('build_id') == candidates.fingerprint(candidate['identity']['build_identity'])
            and pair['identity'].get('family') == candidate['identity']['input']['family']
            and pair['identity'].get('order') == candidate['identity']['baseline_order'], 'Conflict feature uses another build/input direction')
        require(type(pair.get('observations')) is int and pair['observations'] > 0
            and isinstance(pair.get('witness'), dict), 'Conflict feature lacks observed witness')
        seen.add(pair['pair_id'])
    require(record.get('unobserved_conflicts') == 'unknown'
        and record.get('global_order_inferred') is False and record.get('reads_from_inferred') is False,
        'Unsupported feature coverage claim')
    candidates.canonical(record)


def _valid_observation(record):
    return (record.get('outcome') == 'hit' and record.get('candidate_hit') is True
        and record.get('guest_started') is True and record.get('cleanup_confirmed') is True
        and record.get('property_evaluated') is True and record.get('recovery_required') is False)


def _history(records, by_id):
    require(type(records) is list, 'History must be verified attempt records, not aggregate stats')
    ids = set()
    for row in records:
        require(isinstance(row, dict) and row.get('candidate_id') in by_id
            and type(row.get('attempt_id')) is str and bool(row['attempt_id'])
            and row['attempt_id'] not in ids and row.get('outcome') in OUTCOMES,
            'History contains unknown candidate, duplicate attempt or invalid outcome')
        for key in ('candidate_hit', 'guest_started', 'cleanup_confirmed', 'property_evaluated', 'recovery_required'):
            require(type(row.get(key)) is bool, 'History requires explicit '+key)
        require(row['candidate_hit'] is (row['outcome'] == 'hit'), 'History hit classification differs')
        require(not row['property_evaluated'] or _valid_observation(row), 'History property lacks a valid controlled hit')
        if _valid_observation(row):
            _validate_feature(row.get('observed_feature'), by_id[row['candidate_id']])
            require(row['observed_feature']['observation_kind'] == 'execution', 'History must use actual execution features')
        else:require(row.get('observed_feature') is None, 'Incomplete history cannot contribute observed features')
        ids.add(row['attempt_id'])
    candidates.canonical(records)


def make_queue(pool, family, total_budget, *, pool_limit, per_input_budget,
               feedback, features, history=None, eligible=None, rotation_interval=3):
    """Freeze a finite pool and caller-verified history; never launch anything.

    ``eligible`` is candidate_id -> explicit bool, after live identity checking.
    With feedback disabled admission and selection retain immutable pool order.
    A pool-limited row remains stored and can be admitted by a later run.
    """
    search_queue.validate_pool(pool)
    require(family in ('rmw', 'mutex'), 'Unknown kernel family')
    _number(total_budget, 'total budget');_number(pool_limit, 'pool limit')
    _number(per_input_budget, 'per-input budget')
    require(type(feedback) is bool, 'Feedback switch must be a boolean')
    require(type(rotation_interval) is int and 1 <= rotation_interval <= 4096, 'Invalid rotation interval')
    by_id = {row['candidate_id']: row for row in pool['candidates']}
    require(isinstance(features, dict) and set(features) == set(by_id), 'Every candidate requires an observed feature record')
    for cid, candidate in by_id.items():_validate_feature(features[cid], candidate)
    require(isinstance(eligible, dict) and set(eligible) == set(by_id)
        and all(type(value) is bool for value in eligible.values()), 'Explicit verified eligibility required')
    history = [] if history is None else history;_history(history, by_id)
    attempts, last, observed = Counter(), {}, Counter()
    for seq, old in enumerate(history):
        cid = old['candidate_id'];attempts[cid] += 1;last[cid] = seq
        if _valid_observation(old):
            observed.update(pair['pair_id'] for pair in old['observed_feature']['pairs'])
    rows = []
    for index, candidate in enumerate(pool['candidates']):
        cid = candidate['candidate_id'];identity = candidate['identity']
        row = dict(candidate_id=cid, pool_index=index, input_id=identity['input']['input_id'],
            family=identity['input']['family'], order=identity['baseline_order'],
            feature_ids=[pair['pair_id'] for pair in features[cid]['pairs']],
            historical_attempts=attempts[cid], last_historical_attempt=last.get(cid, -1), attempts=[])
        if row['family'] != family:row.update(status='scope-excluded', reason='Other kernel family')
        elif not eligible[cid]:row.update(status='unsupported', reason='Live build identity does not support candidate')
        else:row.update(status='pool-unexplored', reason='Outside this run admission limit; retained for later rotation')
        rows.append(row)
    admission = [r for r in rows if r['status'] == 'pool-unexplored']
    if feedback:admission.sort(key=lambda row:(row['historical_attempts'], row['last_historical_attempt'], row['pool_index']))
    for row in admission[:pool_limit]:row.update(status='pending', reason='Admitted without coarse-feature deduplication')
    return dict(schema_version=1, kind='kconc.feedback-ledger', policy_id=POLICY_ID,
        family=family, budget=total_budget, pool_limit=pool_limit, per_input_budget=per_input_budget,
        feedback=feedback, rotation_interval=rotation_interval, pool_sha256=candidates.fingerprint(pool),
        order_policy='observed-pair-rarity-with-old-candidate-rotation' if feedback else 'pool-order-no-feedback',
        candidates=rows, candidate_records=copy.deepcopy(by_id), features=copy.deepcopy(features), history=copy.deepcopy(history),
        history_trust='Caller revalidated raw records before queue construction; not self-authenticating',
        feature_hits=dict(observed), input_attempts={}, attempts=[], selections=[],
        finalized=False, interrupted_reason=None, unobserved_branches='unknown', complete_search=False)


def _selection(ledger):
    require(not ledger['finalized'], 'Finalized ledger cannot select another candidate')
    require(not any(a['outcome'] == 'running' for a in ledger['attempts']), 'Only one attempt may be active')
    if len(ledger['attempts']) >= ledger['budget']:return None
    available = [r for r in ledger['candidates'] if r['status'] == 'pending'
        and ledger['input_attempts'].get(r['input_id'], 0) < ledger['per_input_budget']]
    if not available:return None
    number = len(ledger['attempts'])+1
    if not ledger['feedback']:
        row = min(available, key=lambda r:r['pool_index']);reason = 'feedback-disabled-pool-order'
    elif number % ledger['rotation_interval'] == 0:
        old = [r for r in available if r['historical_attempts'] > 0]
        row = min(old or available, key=lambda r:(r['last_historical_attempt'], r['pool_index']))
        reason = 'old-candidate-rotation' if old else 'fifo-rotation-no-old-candidate'
    else:
        def rank(row):
            hits = [ledger['feature_hits'].get(key, 0) for key in row['feature_ids']]
            return (min(hits, default=0), sum(hits), row['historical_attempts'],
                row['last_historical_attempt'], row['pool_index'])
        row = min(available, key=rank);reason = 'unseen-or-rare-observed-pair' if row['feature_ids'] else 'no-observed-pair-unknown'
    feature_counts = {key:ledger['feature_hits'].get(key, 0) for key in row['feature_ids']}
    return dict(ordinal=number, candidate_id=row['candidate_id'], reason=reason,
        pool_index=row['pool_index'], historical_attempts=row['historical_attempts'],
        feature_hits_before=feature_counts, input_attempts_before=ledger['input_attempts'].get(row['input_id'], 0),
        policy_id=POLICY_ID)


def next_candidate(ledger):
    """Return the next row or None; preview does not consume an attempt slot."""
    decision = _selection(ledger)
    ledger['selection_preview'] = copy.deepcopy(decision)
    if decision is None:return None
    return next(row for row in ledger['candidates'] if row['candidate_id'] == decision['candidate_id'])


def begin_attempt(ledger, candidate_id, attempt_id):
    decision = _selection(ledger)
    require(decision is not None and decision['candidate_id'] == candidate_id, 'Cannot skip the current deterministic queue decision')
    require(type(attempt_id) is str and bool(attempt_id)
        and all(row['attempt_id'] != attempt_id for row in ledger['attempts']+ledger['history']), 'Attempt id must be new')
    row = next(r for r in ledger['candidates'] if r['candidate_id'] == candidate_id)
    record = dict(attempt_id=attempt_id, ordinal=len(ledger['attempts'])+1, candidate_id=candidate_id,
        outcome='running', guest_started=None, candidate_hit=False, cleanup_confirmed=None,
        property_evaluated=False, property_violation=None, recovery_required=True, evidence={})
    ledger['selections'].append(copy.deepcopy(decision));ledger['attempts'].append(record)
    ledger['input_attempts'][row['input_id']] = ledger['input_attempts'].get(row['input_id'], 0)+1
    row['status'] = 'running';row['attempts'].append(attempt_id)
    ledger.pop('selection_preview', None)
    return record


def finish_attempt(ledger, attempt_id, outcome, *, guest_started, cleanup_confirmed,
                   candidate_hit=None, property_evaluated=False, property_violation=None,
                   recovery_required=False, observed_feature=None, evidence=None):
    require(not ledger['finalized'] and outcome in OUTCOMES, 'Invalid/finalized attempt outcome')
    matches = [a for a in ledger['attempts'] if a['attempt_id'] == attempt_id]
    require(len(matches) == 1 and matches[0]['outcome'] == 'running', 'Attempt must be active and finish once')
    if candidate_hit is None:candidate_hit = outcome == 'hit'
    for name, value in [('guest_started',guest_started),('cleanup_confirmed',cleanup_confirmed),
            ('candidate_hit',candidate_hit),('property_evaluated',property_evaluated),('recovery_required',recovery_required)]:
        require(type(value) is bool, 'Explicit boolean required: '+name)
    require(candidate_hit is (outcome == 'hit'), 'Candidate hit differs from outcome')
    require(outcome not in ('hit','miss','timeout') or guest_started, 'Control outcome needs an actual guest attempt')
    require(outcome != 'hit' or cleanup_confirmed, 'A controlled hit needs confirmed cleanup')
    require(property_violation is None if not property_evaluated else type(property_violation) is bool,
        'Unevaluated property remains unknown')
    record = dict(matches[0], outcome=outcome, guest_started=guest_started, candidate_hit=candidate_hit,
        cleanup_confirmed=cleanup_confirmed, property_evaluated=property_evaluated,
        property_violation=property_violation, recovery_required=recovery_required,
        evidence=copy.deepcopy(evidence or {}), observed_feature=copy.deepcopy(observed_feature))
    require(not property_evaluated or _valid_observation(record), 'A property result needs a valid controlled hit')
    if _valid_observation(record):
        # The feature validator needs only this already-verified candidate's
        # build/input identity; obtain it from immutable queue construction.
        _validate_feature(observed_feature, ledger['candidate_records'][record['candidate_id']])
        require(observed_feature['observation_kind'] == 'execution', 'Seen pairs require the actual execution feature')
    else:require(observed_feature is None, 'Incomplete attempts cannot contribute observed features')
    require(evidence is None or isinstance(evidence, dict), 'Evidence must be an object')
    candidates.canonical(record)
    matches[0].update(record)
    row = next(r for r in ledger['candidates'] if r['candidate_id'] == record['candidate_id'])
    row['status'] = outcome
    if _valid_observation(record):
        for pair in observed_feature['pairs']:
            key = pair['pair_id'];ledger['feature_hits'][key] = ledger['feature_hits'].get(key, 0)+1
    return matches[0]


def finalize(ledger, interrupted_reason=None):
    require(not ledger['finalized'], 'Ledger was already finalized')
    require(not any(a['outcome'] == 'running' for a in ledger['attempts']), 'Classify active attempt before finalization')
    require(interrupted_reason is None or type(interrupted_reason) is str and bool(interrupted_reason), 'Invalid interruption reason')
    if interrupted_reason is None:require(_selection(ledger) is None, 'Available candidate requires execution or explicit interruption')
    for row in ledger['candidates']:
        if row['status'] != 'pending':continue
        if interrupted_reason is not None:row.update(status='unattempted-interrupted', reason=interrupted_reason)
        elif ledger['input_attempts'].get(row['input_id'], 0) >= ledger['per_input_budget']:
            row.update(status='input-budget-unexplored', reason='Per-input attempt budget exhausted')
        else:row.update(status='budget-unexplored', reason='Total attempt budget exhausted')
    ledger.update(finalized=True, interrupted_reason=interrupted_reason)
    ledger.pop('selection_preview', None);ledger['summary'] = summarize(ledger)
    return ledger


def summarize(ledger):
    rows, attempts = ledger['candidates'], ledger['attempts']
    counts = Counter(row['status'] for row in rows)
    require(set(counts) <= set(TERMINAL)|{'pending','running'}, 'Unknown candidate classification')
    input_ids = sorted({row['input_id'] for row in rows if row['family'] == ledger['family']})
    return dict(total_candidates=len(rows), candidate_status={s:counts[s] for s in TERMINAL+('pending','running')},
        admitted_candidates=sum(r['status'] not in ('scope-excluded','unsupported','pool-unexplored') for r in rows),
        attempts=len(attempts), attempt_outcomes={s:sum(a['outcome']==s for a in attempts) for s in OUTCOMES+('running',)},
        guest_started=sum(a['guest_started'] is True for a in attempts),
        candidate_hits=sum(a['candidate_hit'] is True for a in attempts),
        property_evaluated=sum(a['property_evaluated'] is True for a in attempts),
        property_violations=sum(a['property_evaluated'] is True and a['property_violation'] is True for a in attempts),
        cleanup_unconfirmed=sum(a['cleanup_confirmed'] is not True for a in attempts),
        observed_pair_signatures=sum(count>0 for count in ledger['feature_hits'].values()),
        per_input=[dict(input_id=i, budget=ledger['per_input_budget'], attempts=ledger['input_attempts'].get(i,0),
            unattempted=sum(r['input_id']==i and not r['attempts'] for r in rows)) for i in input_ids],
        complete_search=False, coverage_claimed=False, unobserved_branches='unknown',
        global_order_inferred=False, reads_from_inferred=False)

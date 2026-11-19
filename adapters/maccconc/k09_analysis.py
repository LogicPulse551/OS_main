"""K09 candidate execution matching on fixed real-regmap entry points.

The original K08 identity and complete raw prefix are never rewritten. Matching
compares the entire structural prefix, excluding only dynamic memory address,
pre-access payload and timestamp fields. Declared initial state, operation inputs
and protocol-dependent values are independently checked. This is not equality of
the whole kernel state, and an observed property is a candidate witness only when
the prefix, target and handoff all match.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import candidates


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


k08 = _module('k09_k08', Path(__file__).with_name('k08_analysis.py'))
k06, k07, k03 = k08.k06, k08.k07, k08.k03
MATCH_POLICY = dict(
    id='kconc.k09.complete-structural-prefix-v1', schema_version=1,
    prefix='Every exported event before the candidate marker, in exact order and with exact word offsets',
    excluded_memory_fields=['address', 'value', 'timestamp'],
    preserved_fields='All other event fields, including kind, raw record type, IP, caller IP, size, flags and full stack IP/parent_idx',
    control_subtraction='Only the adjacent WAKE(0), WAIT(1) pair immediately before the actual declared marker',
    target='Exact raw IP, size, flags, full stack, call depth, zero-based memory ordinal and one-based IP/full-stack occurrences',
    initial_state='Exact validated declared-object initial snapshot from the originating K08 candidate',
    logical_identity='Original role A/test_thread1/0 and B/test_thread2/1, checked against actual slot caller TIDs',
    semantic_values='Fixed input and per-role returned values or mutex boundary records, independently checked against the declared protocol',
    handoff='Accepted K03 control checks, one adjacent wake0/wait1/target, peer completion and no timeout',
    nonclaims=['No whole-kernel-state equality', 'No timestamp-derived total order',
               'No inferred reads-from relation', 'No general DPOR or exhaustive coverage',
               'No K10 stable replay or K11 cross-build regression'])
POLICY_SHA256 = candidates.fingerprint(MATCH_POLICY)
TRACE_FILES = (*k08.TRACE_FILES, 'plan.txt')


def structural_event(event):
    """Keep all non-dynamic fields; no source, call or control event is dropped."""
    return {key: value for key, value in event.items()
            if key not in ('address', 'value', 'timestamp')}


def _contract(metadata, rows, identity):
    checks, mapping = k08._sample_contract(metadata, rows, identity['baseline_order'])
    checks.pop('sampling_only')
    checks['no_automatic_enumeration'] = checks.pop('no_candidate_executions')
    checks.update(k09_schema=k06._equal_int(metadata.get('k09_schema_version'), 1),
        sampling_only_false=metadata.get('sampling_only') is False,
        candidate_requested=metadata.get('candidate_execution_requested') is True,
        exactly_one_requested=k06._equal_int(metadata.get('requested_candidate_executions'), 1),
        candidate_pattern=metadata.get('candidate_pattern') == identity['schedule']['pattern'],
        original_slot_mapping=mapping == identity['slot_to_logical_role'])
    return checks, mapping


def schedule_checks(rows, family, order):
    """Check a declared ABA/BAB protocol using logical operation identities."""
    first, second = (0, 1) if order == 'ab' else (1, 0)
    setup, _, operations, prop, _ = rows
    if family == 'mutex':
        final = prop['final']
        protocol = [(e['role'], e['kind'], e['depth']) for e in final['events'][:final['event_count']]]
        peer_entered = operations['results'][second]['result']['outcome'] == 1
        expected = ([(first, 1, 1), (second, 1, 2), (second, 2, 1), (first, 2, 0)]
                    if peer_entered else [(first, 1, 1), (second, 3, 1), (first, 2, 0)])
        return {'boundary_order': protocol == expected,
                'peer_admission_matches_lock_domain': peer_entered == (setup['mode'] == 'per-role')}
    initial, declared = setup['initial'], setup['operations']
    first_after = k06.oracle.apply_update(initial, declared[first])
    peer_after = k06.oracle.apply_update(initial, declared[second])
    checks = {}
    if setup['mode'] == 'split':
        expected = list(peer_after)
        expected[declared[first]['reg']] = first_after[declared[first]['reg']]
        for role, after in [(first, first_after), (second, peer_after)]:
            op, actual = declared[role], operations['results'][role]
            checks[f'role{role}_before_after'] = (k06._equal_int(actual.get('before'), initial[op['reg']])
                and k06._equal_int(actual.get('after'), after[op['reg']]))
    else:
        expected = k06.oracle.apply_update(peer_after, declared[first])
    checks['final_values'] = k06._vector(prop['values'], expected)
    return checks


def _matching(identity, events, observed, plan):
    reference, wanted = identity['observed_prefix']['events'], identity['target']
    first = events['A']
    markers = observed['markers']['A']
    checks = {'unique_actual_marker': len(markers) == 1,
              'plan_is_original_target': plan['stack'] == wanted['event']['stack']}
    detail = dict(policy_sha256=POLICY_SHA256, reference_event_count=len(reference),
                  reference_candidate_prefix_sha256=candidates.fingerprint(identity['observed_prefix']))
    if len(markers) != 1:
        return checks, detail
    actual = markers[0]['event']
    index = next(i for i, event in enumerate(first) if event == actual)
    before = first[:index]
    adjacent = (len(before) >= 2 and before[-2]['kind'] == 'WAKE' and before[-2]['flagidx'] == 0
                and before[-1]['kind'] == 'WAIT' and before[-1]['flagidx'] == 1)
    prefix = before[:-2] if adjacent else before
    expected_signature, actual_signature = ([structural_event(e) for e in rows] for rows in (reference, prefix))
    memories = [e for e in prefix if e['kind'] == 'MEMORY']
    stats = dict(access_index=len(memories), call_depth=len(actual['stack']),
        same_ip_occurrence=1+sum(e['ip'] == actual['ip'] for e in memories),
        full_stack_occurrence=1+sum(e['stack'] == actual['stack'] for e in memories))
    checks.update(complete_structural_prefix=expected_signature == actual_signature,
        target_static_fields=all(actual.get(key) == wanted['event'].get(key) for key in ('kind', 'thread', 'record_type', 'ip', 'size', 'flags', 'stack')),
        target_occurrences=all(stats[key] == wanted[key] for key in stats),
        target_offset=actual['word_index'] == wanted['event']['word_index'] + (2 if adjacent else 0),
        adjacent_wake_wait=adjacent,
        adjacent_wait_not_timed_out=adjacent and before[-1]['timed_out'] is False)
    differences = [i for i, (x, y) in enumerate(zip(expected_signature, actual_signature)) if x != y]
    detail.update(actual_event_count=len(prefix), first_differing_event=differences[0] if differences else None,
        expected_signature_sha256=candidates.fingerprint(expected_signature), actual_signature_sha256=candidates.fingerprint(actual_signature),
        actual_target=copy.deepcopy(actual), actual_occurrences=stats,
        original_raw_prefix_retained=True, excluded_fields=list(MATCH_POLICY['excluded_memory_fields']))
    return checks, detail


def analyze(trace, mapping, guest, candidate, *, backend=None, schedule_checker=None, candidate_validator=None):
    """Classify one actual attempt, preserving control, property and cleanup axes."""
    trace = Path(trace)
    result = dict(schema_version=1, kind='kconc.candidate-execution.analysis', passed=False,
        classification='invalid', checks={}, groups={}, errors=[], observations={}, artifacts={},
        candidate_hit=False, execution_valid=False, control_valid=False, prefix_matches=False,
        target_matches=False, schedule_valid=False, cleanup_verified=False, recovery_required=True,
        property_evaluated=False, property_violation=False, runtime_identity_bound=False,
        matching_policy=MATCH_POLICY, matching_policy_sha256=POLICY_SHA256,
        scope='One K08 regmap marker candidate, with complete structural-prefix matching; no general coverage or stable replay claim')
    sections, rows, metadata, events, observation, verdict = {}, None, None, None, None, None
    try:
        (candidates.validate_candidate if candidate_validator is None else candidate_validator)(candidate)
        identity = candidate['identity'];entry = identity['input']
        family, order = entry['family'], identity['baseline_order'];base = k08.FAMILIES[family] if backend is None else backend
        result.update(candidate_id=candidate['candidate_id'], family=family, order=order)
    except (ValueError, KeyError, TypeError) as error:
        result['errors'].append('candidate: '+str(error))
        return result
    try:
        rows = base.read_phases(trace)
        result['observations'].update(phases=rows, family=family, order=order, case_id=rows[0]['case_id'], mode=rows[0]['mode'])
        sections.update(base.phase_checks(rows))
        initial = candidates.observed_initial_state(dict(observations=dict(family=family, phases=rows)))
        sections['candidate_input'] = {'declared_input': all(rows[0].get(k) == entry[k] for k in ('case_id', 'mode', 'initial', 'operations')),
            'initial_snapshot_matches': initial == identity['initial_state']}
        sections['schedule'] = (schedule_checks if schedule_checker is None else schedule_checker)(rows, family, order)
        verdict = (base.oracle.evaluate(rows[0]['initial'], rows[0]['operations'], rows[3]['values'])
                   if family == 'rmw' else base.oracle.check_observation(rows[0]['case_id'], rows[0]['mode'], rows[2]['results'], rows[3]['final'], rows[0]['epoch']))
        result['observed_property'] = verdict
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['errors'].append('phases: '+str(error));sections['phase_evidence'] = {'valid':False}
    try:
        metadata = base._object(trace/'run.json')
        contract, slot_to_role = _contract(metadata, rows, identity)
        sections['contract'] = contract
        result['observations'].update(slot_to_role=slot_to_role, slot_tids=metadata.get('slot_tids'))
        source_map, map_record = base.read_mapping(mapping)
        result['artifacts']['source_map'] = map_record
        for slot in ('A','B'):
            for line in (trace/(slot+'.events.jsonl')).read_text().splitlines():
                base._json(line)
        if family == 'rmw':
            traced, observation = base.inspect_trace(trace,source_map,True,rows[0]['mode'])
        else:
            entered = [rows[2]['results'][0 if slot_to_role[slot]=='A' else 1]['result']['outcome']==1 for slot in ('A','B')]
            traced, observation = base.inspect_trace(trace,source_map,True,entered)
        traced['raw']['roles'] = contract['physical_callback_identity']
        traced['control']['roles'] = contract['physical_callback_identity']
        sections.update(traced)
        # A stack mismatch is an observed candidate miss, not malformed evidence.
        marker_plan = sections['marker'].pop('plan_names_declared_A_store',False)
        sections['requested_target'] = {'declared_marker_stack':marker_plan}
        events = {slot:k03.read_events(trace,slot) for slot in ('A','B')}
        plan = k03.read_plan(trace/'plan.txt')
        sections['matching'], result['matching'] = _matching(identity,events,observation,plan)
        stats = {slot:k03._stats(events[slot],plan['stack'] if slot=='A' else None) for slot in ('A','B')}
        sections['trace_integrity'] = {slot+'_stats_match':metadata.get(slot)==stats[slot] for slot in ('A','B')}
        sections['trace_integrity'].update(child_zero=metadata.get('child_ok') is True and k06._equal_int(metadata.get('child_status'),0),
            both_finished=metadata.get('a_done') is True and metadata.get('b_done') is True,
            finished_declared=metadata.get('safe_to_continue') is True,
            reset_ok=k03._call_ok(metadata,'reset'), gate_ok=k03._call_ok(metadata,'gate0'), peer_wake_ok=k03._call_ok(metadata,'b_completed_wake1'))
        result['observations'].update(raw=observation['raw'], markers=observation['markers'], marker_source=observation['marker_source'])
        result['timed_out'] = any(e['kind']=='WAIT' and e['timed_out'] for es in events.values() for e in es)
        sections['candidate_source'] = {'declared_source_identity':identity['marker_source']==observation['marker_source']}
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['errors'].append('trace: '+str(error));sections['trace_evidence'] = {'valid':False}
    try:
        guest = base._object(guest);cleanup = guest.get('local_cleanup',{})
        sections['supervisor'] = dict(schema=k06._equal_int(guest.get('schema_version'),1) and guest.get('kind')=='kconc.guest',
            complete_exit=(guest.get('outcome')=='completed' and k06._equal_int(guest.get('exit_code'),0))
                or (guest.get('outcome')=='execution_failed' and k06._equal_int(guest.get('exit_code'),2)),
            exit_matches_control=metadata is not None and guest.get('exit_code')==(0 if metadata.get('control_valid') is True else 2),
            no_remaining_processes=type(guest.get('remaining_pids')) is list and guest['remaining_pids']==[],
            cleanup=isinstance(cleanup,dict) and cleanup.get('confirmed') is True and cleanup.get('errors')==[],
            phase_errors_absent=guest.get('phase_errors')==[], phases_match=rows is not None and guest.get('phases')==rows,
            not_fault_injection=guest.get('fault')=='none')
        result['supervisor_timed_out'] = guest.get('outcome')=='timeout'
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append('supervisor: '+str(error));sections['supervisor'] = {'valid':False}
    for group, checks in sections.items():
        result['groups'][group] = bool(checks) and all(v is True for v in checks.values())
        result['checks'].update({group+'.'+key:value is True for key,value in checks.items()})
    for name in TRACE_FILES:
        if (trace/name).is_file():result['artifacts'][name] = k06.digest(trace/name)
    result['artifacts'].update(analysis_sha256=k06.digest(Path(__file__)), inherited_analysis_sha256=k06.digest(Path(base.__file__)),
        k03_analysis_sha256=k06.digest(Path(k03.__file__)), k08_analysis_sha256=k06.digest(Path(k08.__file__)),
        oracle_sha256=k06.digest(Path(base.oracle.__file__)), candidates_sha256=k06.digest(Path(candidates.__file__)))
    g = result['groups']
    essential = set(g)-{'control','schedule','matching','requested_target'}
    result['execution_valid'] = bool(essential) and all(g[x] for x in essential) and not result['errors']
    result['cleanup_verified'] = (g.get('cleanup') is True and sections.get('supervisor',{}).get('cleanup') is True
        and sections.get('supervisor',{}).get('no_remaining_processes') is True)
    result['control_valid'] = g.get('control') is True
    result['prefix_matches'] = sections.get('matching',{}).get('complete_structural_prefix') is True
    target_checks = ('unique_actual_marker','plan_is_original_target','target_static_fields','target_occurrences','target_offset')
    result['target_matches'] = all(sections.get('matching',{}).get(k) is True for k in target_checks) and g.get('requested_target') is True
    result['schedule_valid'] = g.get('schedule') is True
    result['candidate_hit'] = (result['execution_valid'] and result['control_valid'] and g.get('matching') is True
        and result['target_matches'] and result['schedule_valid'])
    if result.get('timed_out') or result.get('supervisor_timed_out'):
        result['classification'] = 'timeout'
    elif result['execution_valid']:
        result['classification'] = 'hit' if result['candidate_hit'] else 'miss'
    elif g.get('supervisor') is not True or metadata is not None and (metadata.get('child_ok') is not True or metadata.get('safe_to_continue') is not True):
        result['classification'] = 'infrastructure-error'
    else:
        result['classification'] = 'invalid'
    result['passed'] = result['classification'] in ('hit','miss')
    result['recovery_required'] = (not result['cleanup_verified'] or not result['execution_valid']
        or result['classification'] in ('timeout','invalid','infrastructure-error'))
    result['property_evaluated'] = result['candidate_hit'] and verdict is not None
    result['property_violation'] = result['property_evaluated'] and verdict['allowed'] is False
    if result['property_evaluated']:result['property'] = verdict
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('trace','mapping','guest','candidate','output'):p.add_argument('--'+name,required=True,type=Path)
    args=p.parse_args(argv)
    result=analyze(args.trace,args.mapping,args.guest,candidates._read_json(args.candidate))
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2);stream.write('\n')
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())

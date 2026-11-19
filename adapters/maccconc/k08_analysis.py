"""Validate K08 sequential samples without executing their future candidates.

Raw A/B names are executor slots. Logical A/B remain the original ioctl role
and callback identities even when slot A invokes test_thread2. K06/K07 retain
ownership of lifecycle/property/source checks; only the explicit serial order
and this additional slot-to-role contract are new here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


k06 = _module('k08_k06', Path(__file__).with_name('k06_analysis.py'))
k07 = _module('k08_k07', Path(__file__).with_name('k07_analysis.py'))
k03 = k06.k03
FAMILIES = {'rmw': k06, 'mutex': k07}
ORDERS = {'ab': ('A', 'B'), 'ba': ('B', 'A')}
CALLBACKS = {'A': 'test_thread1', 'B': 'test_thread2'}
TRACE_FILES = ('run.json', 'testcase.stdout.txt', 'A.words', 'B.words',
               'A.events.jsonl', 'B.events.jsonl')
SCOPE = ('Finite serial A-B/B-A observations on real regmap; derived A-B-A/B-A-B '
         'candidates remain unexecuted. Unobserved branches and prefixes are unknown; '
         'no exhaustive search, coverage, K09 execution or K10 stability claim.')


def schedule_checks(rows, family, order):
    """Validate observed results in the declared logical order, not array order."""
    roles = [0 if role == 'A' else 1 for role in ORDERS[order]]
    if family == 'mutex':
        final = rows[3]['final']
        observed = [(e['role'], e['kind'], e['depth'])
                    for e in final['events'][:final['event_count']]]
        expected = [(role, kind, depth) for role in roles for kind, depth in ((1, 1), (2, 0))]
        return {'actual_boundaries_match_logical_order': observed == expected,
                'both_roles_entered': all(x['result']['outcome'] == 1 for x in rows[2]['results'])}
    setup, _, operations, prop, _ = rows
    values = list(setup['initial'])
    checks = {}
    for role in roles:
        declared = setup['operations'][role]
        before = values[declared['reg']]
        values = k06.oracle.apply_update(values, declared)
        if setup['mode'] == 'split':
            actual = operations['results'][role]
            checks[f'role{role}_read_write_matches_serial_order'] = (
                k06._equal_int(actual.get('before'), before)
                and k06._equal_int(actual.get('after'), values[declared['reg']]))
    checks['final_matches_serial_order'] = k06._vector(prop['values'], values)
    return checks


def _sample_contract(metadata, rows, order):
    mapping = dict(zip(('A', 'B'), ORDERS[order]))
    tids = metadata.get('slot_tids')
    checks = {
        'declared_order': metadata.get('baseline_order') == order,
        'slot_to_logical_role': metadata.get('slot_to_logical_role') == mapping,
        'logical_role_to_callback': metadata.get('logical_role_to_callback') == CALLBACKS,
        'raw_trace_namespace': metadata.get('raw_trace_namespace') == 'execution_slot',
        'sampling_only': metadata.get('sampling_only') is True,
        'no_candidate_executions': k06._equal_int(metadata.get('automatic_candidates_executed'), 0),
        'physical_callback_identity': metadata.get('roles') == {slot: CALLBACKS[role] for slot, role in mapping.items()},
        'slot_tid_shape': isinstance(tids, dict) and set(tids) == {'A', 'B'}
            and all(k06._int(value, 1, 0x7fffffff) for value in tids.values())
            and tids['A'] != tids['B'],
    }
    results = rows[2].get('results') if rows else None
    shape = isinstance(results, list) and len(results) == 2 and all(isinstance(x, dict) for x in results)
    checks['logical_results_order'] = shape and all(k06._equal_int(results[i].get('role'), i) for i in range(2))
    for slot, role in mapping.items():
        row = results[0 if role == 'A' else 1] if shape else {}
        checks[slot + '_callback_caller_matches_slot'] = checks['slot_tid_shape'] and k06._equal_int(row.get('caller_tid'), tids[slot])
    return checks, mapping


def _logical_observations(observed, events, slot_to_role, order):
    """Keep all event types in prefixes and name occurrence conventions explicitly."""
    result = dict(observed)
    result['projection'], result['markers'], result['trace_events'] = {}, {}, {}
    for slot, role in slot_to_role.items():
        by_ip, by_stack, projection = {}, {}, []
        for index, item in enumerate(observed['projection'][slot]):
            event = item['event']
            ip, stack = event['ip'], k03._stack_key(event['stack'])
            by_ip[ip] = by_ip.get(ip, 0) + 1
            by_stack[stack] = by_stack.get(stack, 0) + 1
            projection.append(dict(item, physical_slot=slot, logical_role=role,
                access_index=index, same_ip_occurrence=by_ip[ip],
                full_stack_occurrence=by_stack[stack], call_depth=len(event['stack'])))
        marker_offsets = {x['event']['word_index'] for x in observed['markers'][slot]}
        result['projection'][role] = projection
        result['markers'][role] = [x for x in projection if x['event']['word_index'] in marker_offsets]
        result['trace_events'][role] = events[slot]
    first = ORDERS[order][0]
    if len(result['markers'][first]) == 1:
        target = result['markers'][first][0]
        prefix = [event for event in events['A'] if event['word_index'] < target['event']['word_index']]
        result['observed_prefix'] = dict(physical_slot='A', logical_role=first, events=prefix,
            completed_logical_roles=[], observed_baseline_order=order,
            basis='verified-sequential-baseline')
        result['target'] = target
    result['occurrence_conventions'] = dict(access_index='zero-based MEMORY ordinal in this logical trace',
        same_ip_occurrence='one-based occurrence of exact raw IP',
        full_stack_occurrence='one-based occurrence of exact full stack including parent_idx',
        call_depth='number of frames in the exported full stack')
    return result


def analyze(trace, mapping, guest, family, order, *, backend=None):
    """Return a failed report on malformed evidence; never mutate input evidence.

    Build/manifest identity is bound by the caller. The accepted native upstream
    decoder supplies events; the reused raw checker validates lengths/format,
    not a second independent decoding of every raw machine word.
    """
    result = dict(schema_version=1, kind='kconc.finite-sample.analysis', passed=False,
        family=family, order=order, checks={}, groups={}, errors=[], observations={}, artifacts={},
        scope=SCOPE, runtime_identity_bound=False, candidate_execution_performed=False,
        unobserved_branches='unknown', coverage_claimed=False)
    sections, rows = {}, None
    trace = Path(trace)
    if not isinstance(family, str) or family not in FAMILIES or not isinstance(order, str) or order not in ORDERS:
        result['errors'].append('Unsupported sample family or order')
        result.update(execution_valid=False, control_valid=False, property_evaluated=False, property_violation=False)
        return result
    base = FAMILIES[family] if backend is None else backend
    try:
        rows = base.read_phases(trace)
        result['observations'].update(family=family, order=order, case_id=rows[0]['case_id'],
            mode=rows[0]['mode'], phases=rows)
        sections.update(base.phase_checks(rows))
        sections['schedule_outcome'] = schedule_checks(rows, family, order)
        if family == 'rmw':
            verdict = base.oracle.evaluate(rows[0]['initial'], rows[0]['operations'], rows[3]['values'])
        else:
            verdict = base.oracle.check_observation(rows[0]['case_id'], rows[0]['mode'],
                rows[2]['results'], rows[3]['final'], rows[0]['epoch'])
        result['property'] = verdict
        sections['sequential_property'] = {'allowed': verdict['allowed'] is True}
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['errors'].append('phases: ' + str(error))
        sections['phase_evidence'] = {'valid': False}
    try:
        metadata = base._object(trace / 'run.json')
        contract, slot_to_role = _sample_contract(metadata, rows, order)
        sections['sample_contract'] = contract
        result['observations'].update(slot_to_role=slot_to_role, slot_tids=metadata.get('slot_tids'),
            raw_trace_namespace='execution_slot')
        # K03's reader checks shape/offsets; reject duplicate keys/nonfinite data
        # before invoking its ordinary JSON loader.
        for slot in ('A', 'B'):
            for line in (trace / (slot + '.events.jsonl')).read_text().splitlines():
                base._json(line)
        source_map, map_record = base.read_mapping(mapping)
        result['artifacts']['source_map'] = map_record
        traced, observed = base.inspect_trace(trace, source_map, False,
            rows[0]['mode'] if family == 'rmw' else [True, True])
        # The reused check otherwise assumes a permanent slot/callback mapping.
        # Every other raw/serial/source/marker check retains its original meaning.
        traced['raw']['roles'] = contract['physical_callback_identity']
        sections.update(traced)
        events = {slot: k03.read_events(trace, slot) for slot in ('A', 'B')}
        result['observations'].update(_logical_observations(observed, events, slot_to_role, order))
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['errors'].append('trace: ' + str(error))
        sections['trace_evidence'] = {'valid': False}
    try:
        guest = base._object(guest)
        cleanup = guest.get('local_cleanup', {})
        sections['supervisor'] = {
            'schema': k06._equal_int(guest.get('schema_version'), 1) and guest.get('kind') == 'kconc.guest',
            'completed': guest.get('outcome') == 'completed' and k06._equal_int(guest.get('exit_code'), 0),
            'no_remaining_processes': type(guest.get('remaining_pids')) is list and guest['remaining_pids'] == [],
            'cleanup': isinstance(cleanup, dict) and cleanup.get('confirmed') is True and cleanup.get('errors') == [],
            'phase_errors_absent': guest.get('phase_errors') == [],
            'phases_match': rows is not None and guest.get('phases') == rows,
            'not_fault_injection': guest.get('fault') == 'none'}
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append('supervisor: ' + str(error))
        sections['supervisor'] = {'valid': False}
    for group, checks in sections.items():
        result['groups'][group] = bool(checks) and all(value is True for value in checks.values())
        result['checks'].update({group + '.' + key: value is True for key, value in checks.items()})
    for name in TRACE_FILES:
        if (trace / name).is_file():
            result['artifacts'][name] = k06.digest(trace / name)
    result['artifacts'].update(analysis_sha256=k06.digest(Path(__file__)),
        inherited_analysis_sha256=k06.digest(Path(base.__file__)),
        k03_analysis_sha256=k06.digest(Path(k03.__file__)),
        oracle_sha256=k06.digest(Path(base.oracle.__file__)))
    result['passed'] = bool(result['checks']) and all(result['checks'].values()) and not result['errors']
    result['execution_valid'] = result['passed']
    result['control_valid'] = all(result['groups'].get(g) is True
        for g in ('raw', 'sequence', 'control', 'marker', 'sample_contract', 'schedule_outcome'))
    result['property_evaluated'] = result['passed'] and 'property' in result
    result['property_violation'] = result['property_evaluated'] and result['property']['allowed'] is False
    if not result['passed'] and 'observed_prefix' in result['observations']:
        result['observations']['observed_prefix']['basis'] = 'invalid-sample-not-candidate-evidence'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', required=True, type=Path)
    parser.add_argument('--mapping', required=True, type=Path)
    parser.add_argument('--guest', required=True, type=Path)
    parser.add_argument('--family', required=True, choices=tuple(FAMILIES))
    parser.add_argument('--order', required=True, choices=tuple(ORDERS))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    result = analyze(args.trace, args.mapping, args.guest, args.family, args.order)
    # Evidence is append-only at this interface: a retry needs another output.
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

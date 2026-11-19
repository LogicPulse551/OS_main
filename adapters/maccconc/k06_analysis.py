"""Evidence checks for K06's split and locked masked register updates.

This reads evidence only. It reuses the accepted K03 export reader and control
checks, but never its dup/close outcome or fs/file.c path comparison. KCOV write
values are pre-access snapshots, not the value being stored. Neither timestamps
nor equal values establish a cross-thread total order.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('k06_k03_analysis', Path(__file__).with_name('k03_analysis.py'))
k03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k03)
spec = importlib.util.spec_from_file_location('k06_oracle', REPO / 'src/kconc/regmap_oracle.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
PHASES = ('setup', 'initial_state', 'operations', 'property', 'teardown')
MARKER_SYMBOL = 'kconc_regmap_checkpoint'
MARKER_FILE = 'drivers/base/regmap/kconc-regmap.c'
DRIVER = REPO / 'kernel/k06/kconc-regmap.c'
SCOPE = 'Constructed caller-misuse masked-update comparison on real regmap; not an upstream bug claim, general search or K10 stability'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('Duplicate evidence key: ' + key)
        result[key] = value
    return result


def _json(text):
    def constant(value):
        raise ValueError('Non-finite evidence value: ' + value)
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=constant)


def _object(value):
    result = _json(Path(value).read_text()) if isinstance(value, (str, Path)) else value
    if not isinstance(result, dict):
        raise ValueError('Expected an evidence object')
    return result


def _int(value, minimum=0, maximum=0xffffffff):
    return type(value) is int and minimum <= value <= maximum


def _equal_int(value, wanted):
    return type(value) is int and value == wanted


def _vector(value, wanted):
    return type(value) is list and len(value) == len(wanted) and all(_equal_int(a, b) for a, b in zip(value, wanted))


def _fds(value):
    return type(value) is list and all(_int(fd) for fd in value) and value == sorted(set(value))


def marker_source():
    lines = DRIVER.read_text().splitlines()
    matches = [number for number, line in enumerate(lines, 1) if 'WRITE_ONCE(role->checkpoint, epoch);' in line]
    if len(matches) != 1:
        raise ValueError('Expected exactly one declared checkpoint store in the current driver')
    return {'file': MARKER_FILE, 'symbol': MARKER_SYMBOL, 'line': matches[0], 'source_sha256': digest(DRIVER)}


def read_mapping(value):
    if isinstance(value, (str, Path)):
        path = Path(value)
        rows = [_json(line) for line in path.read_text().splitlines() if line.strip()]
        mapping = {}
        for row in rows:
            if not isinstance(row, dict) or row.get('raw_ip') in mapping:
                raise ValueError('Invalid or duplicate source-map row')
            mapping[row.get('raw_ip')] = row
        return mapping, {'path': str(path), 'sha256': digest(path)}
    if not isinstance(value, dict):
        raise ValueError('Mapping must be a source-map JSONL path or dictionary')
    return value, {'canonical_sha256': hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def read_phases(trace):
    rows = []
    for line in (Path(trace) / 'testcase.stdout.txt').read_text().splitlines():
        if line.startswith('KCONC_PHASE '):
            row = _json(line[len('KCONC_PHASE '):])
            if not isinstance(row, dict):
                raise ValueError('Phase is not an object')
            rows.append(row)
    if tuple(row.get('phase') for row in rows) != PHASES or any(type(row.get('passed')) is not bool for row in rows):
        raise ValueError('Expected exactly five ordered lifecycle phases with boolean verdicts')
    return rows


def phase_checks(rows):
    setup, initial, operations, prop, teardown = rows
    case_id, mode = setup.get('case_id'), setup.get('mode')
    wanted = oracle.case_spec(case_id)
    oracle.validate_case(case_id, mode, setup.get('initial'), setup.get('operations'))
    verdict = oracle.evaluate(wanted['initial'], wanted['operations'], prop.get('values'))
    epoch = setup.get('epoch')
    results = operations.get('results')
    role_shape = (type(results) is list and len(results) == 2 and all(isinstance(r, dict) for r in results))
    initial_checks = {
        'setup_passed': setup['passed'], 'setup_not_injected': setup.get('fault') == 'none' and setup.get('injected') is False,
        'setup_reset_succeeded': _equal_int(setup.get('reset_rc'), 0) and _equal_int(setup.get('errno'), 0),
        'valid_epoch': _int(epoch, 1), 'device_open': _int(setup.get('fd')),
        'initial_fd_set': _fds(setup.get('initial_fds')) and setup.get('fd') not in setup.get('initial_fds', []),
        'initial_passed': initial['passed'], 'initial_epoch': _int(epoch, 1) and _equal_int(initial.get('epoch'), epoch),
        'initial_status_succeeded': _equal_int(initial.get('status_rc'), 0),
        'initial_ready': initial.get('regmap_ready') is True and _equal_int(initial.get('context_state'), 1),
        'initial_snapshot_valid': _equal_int(initial.get('snapshot_valid'), 1),
        'initial_values': _vector(initial.get('values'), wanted['initial']),
        'initial_idle': _equal_int(initial.get('active'), 0) and _equal_int(initial.get('completed_mask'), 0),
        'initial_role_state_zero': initial.get('roles_zero') is True,
        'initial_fd_matches': initial.get('fd_set_matches') is True,
    }
    threads = {'operations_passed': operations['passed'], 'exactly_two_calls': _equal_int(operations.get('a_calls'), 1) and _equal_int(operations.get('b_calls'), 1), 'role_results_shape': role_shape}
    if role_shape:
        for role, row in enumerate(results):
            prefix = 'role' + str(role) + '_'
            declared = wanted['operations'][role]
            threads.update({prefix + 'identity': all(_equal_int(row.get(key), value) for key, value in declared.items()),
                prefix + 'abi_and_mode': _equal_int(row.get('abi'), 2) and _equal_int(row.get('mode'), oracle.MODES[mode]),
                prefix + 'reserved_zero': _equal_int(row.get('reserved'), 0),
                prefix + 'operation_succeeded': all(_equal_int(row.get(key), 0) for key in ('rc', 'errno', 'status')),
                prefix + 'epoch': _int(epoch, 1) and _equal_int(row.get('epoch'), epoch),
                prefix + 'same_calling_thread': _int(row.get('caller_tid'), 1) and _equal_int(row.get('kernel_pid'), row.get('caller_tid')),
                prefix + 'checkpoint_reached': _int(epoch, 1) and _equal_int(row.get('checkpoint'), epoch),
                prefix + 'sleepable_checkpoint': _equal_int(row.get('preempt_count'), 0) and _equal_int(row.get('irqs_disabled'), 0)})
            if mode == 'split':
                threads[prefix + 'split_values'] = (_equal_int(row.get('values_valid'), 1)
                    and _int(row.get('before')) and _int(row.get('after'))
                    and row['after'] == ((row['before'] & (0xffffffff ^ declared['mask'])) | (declared['value'] & declared['mask'])))
            else:
                threads[prefix + 'no_invented_locked_observation'] = all(_equal_int(row.get(key), 0) for key in ('values_valid', 'before', 'after'))
        threads['distinct_calling_threads'] = _int(results[0].get('caller_tid'), 1) and _int(results[1].get('caller_tid'), 1) and results[0]['caller_tid'] != results[1]['caller_tid']
    property_checks = {'passed': prop['passed'], 'oracle': prop.get('oracle') == oracle.ORACLE,
        'infrastructure_valid': prop.get('infrastructure_valid') is True,
        'caller_misuse_example': prop.get('caller_misuse_example') is True,
        'native_oracle_agrees': prop.get('allowed') is verdict['allowed'] and prop.get('natural_passed') is verdict['allowed'],
        'not_injected': prop.get('injected') is False,
        'not_kernel_bug_claim': prop.get('kernel_bug_claim') is False,
        'status_succeeded': _equal_int(prop.get('status_rc'), 0),
        'epoch': _int(epoch, 1) and _equal_int(prop.get('epoch'), epoch),
        'ready_snapshot': _equal_int(prop.get('context_state'), 1) and _equal_int(prop.get('snapshot_valid'), 1),
        'both_roles_finished': _equal_int(prop.get('active'), 0) and _equal_int(prop.get('completed_mask'), 3)}
    slots = prop.get('roles')
    property_checks['role_status_shape'] = type(slots) is list and len(slots) == 2 and all(isinstance(x, dict) for x in slots)
    if property_checks['role_status_shape'] and role_shape:
        for role, slot in enumerate(slots):
            row = results[role]
            property_checks[f'role{role}_completed'] = _equal_int(slot.get('started'), 1) and _equal_int(slot.get('completed'), 1)
            property_checks[f'role{role}_matches_returned_operation'] = all(
                _equal_int(slot.get(key), row.get(key)) for key in
                ('reg', 'before', 'after', 'checkpoint', 'preempt_count', 'irqs_disabled', 'status', 'mode', 'values_valid')) and _equal_int(slot.get('pid'), row.get('kernel_pid'))
    cleanup = {'passed': teardown['passed'], 'teardown_succeeded': _equal_int(teardown.get('ioctl_rc'), 0) and _equal_int(teardown.get('errno'), 0),
        'map_empty': teardown.get('map_empty') is True and _equal_int(teardown.get('context_state'), 0),
        'empty_snapshot': _equal_int(teardown.get('snapshot_valid'), 1) and _vector(teardown.get('values'), [0, 0, 0, 0]),
        'idle_empty': _equal_int(teardown.get('active'), 0) and _equal_int(teardown.get('completed_mask'), 0) and teardown.get('roles_zero') is True,
        'resources_closed': teardown.get('resources_closed') is True,
        'fd_observation': teardown.get('fd_set_restored') is True and teardown.get('fd_snapshot_observed') is True,
        'fd_set_equality': _fds(teardown.get('expected_fds')) and _fds(teardown.get('actual_fds')) and teardown['expected_fds'] == teardown['actual_fds'] == setup.get('initial_fds')}
    return {'initial': initial_checks, 'threads': threads, 'property': property_checks, 'cleanup': cleanup}


def _source_ends(value, suffix):
    text = value.replace('\\', '/')
    return text == suffix or text.endswith('/' + suffix)


def schedule_checks(rows, replay):
    """Check only the executor's declared serial AB or marker A-B-A protocol.

    Cross-thread order comes from the checked handoff protocol, not event clocks
    or equal access values. The fixed API's internal values are not exported.
    """
    setup, _, operations, prop, _ = rows
    if type(operations.get('results')) is not list or len(operations['results']) != 2 or any(not isinstance(x, dict) for x in operations['results']):
        return {'observations_available': False}
    initial, declared, mode = setup['initial'], setup['operations'], setup['mode']
    expected = list(initial)
    checks = {}
    if mode == 'split':
        before_a = initial[declared[0]['reg']]
        after_a_state = oracle.apply_update(initial, declared[0])
        before_b_state = initial if replay else after_a_state
        before_b = before_b_state[declared[1]['reg']]
        after_b_state = oracle.apply_update(before_b_state, declared[1])
        expected = list(after_b_state)
        if replay:
            expected[declared[0]['reg']] = after_a_state[declared[0]['reg']]
        for role, before, after in [(0, before_a, after_a_state[declared[0]['reg']]),
                                    (1, before_b, after_b_state[declared[1]['reg']])]:
            row = operations['results'][role]
            checks[f'role{role}_read_write_matches_protocol'] = _equal_int(row.get('before'), before) and _equal_int(row.get('after'), after)
    else:
        order = (1, 0) if replay else (0, 1)
        for role in order:
            expected = oracle.apply_update(expected, declared[role])
    checks['final_matches_completed_protocol'] = _vector(prop['values'], expected)
    return checks


def inspect_trace(trace, mapping, replay, mode='split', *, declared_marker=None, guarded_split=False):
    trace = Path(trace)
    metadata = _object(trace / 'run.json')
    events = {role: k03.read_events(trace, role) for role in ('A', 'B')}
    raw = {role: k03._raw_consistency(trace, role, events[role], metadata) for role in events}
    checks = {'raw': {'schema': _equal_int(metadata.get('schema_version'), 1),
        'roles': metadata.get('roles') == {'A': 'test_thread1', 'B': 'test_thread2'},
        'no_overflow': metadata.get('overflow') is False, 'declared_well_formed': metadata.get('raw_words_well_formed') is True,
        **{role + '_raw_valid': item['valid'] for role, item in raw.items()}}, 'sequence': {}, 'control': {}}
    checks['raw']['strict_control_flags'] = all(type(metadata.get(key)) is bool for key in
        ('sequential_A_B', 'plan_loaded_from_file', 'child_ok', 'a_done', 'b_done', 'overflow', 'raw_words_well_formed', 'control_valid', 'safe_to_continue'))
    for role in events:
        stats = metadata.get(role)
        checks['raw'][role + '_strict_stats'] = isinstance(stats, dict) and bool(stats) and all(_int(value, 0, 0xffffffffffffffff) for value in stats.values())
    if replay:
        plan = k03.read_plan(trace / 'plan.txt')
        checks['control'] = k03._control_checks(metadata, events, plan)
        checks['control']['loaded_saved_plan'] = metadata.get('plan_loaded_from_file') is True
        checks['sequence']['replay_is_not_sequential'] = metadata.get('sequential_A_B') is False
    else:
        checks['sequence'] = {'sequential_A_B': metadata.get('sequential_A_B') is True,
            'not_saved_plan_replay': metadata.get('plan_loaded_from_file') is False,
            'declared_control_valid': metadata.get('control_valid') is True,
            'safe_to_continue': metadata.get('safe_to_continue') is True,
            'child_exited_zero': metadata.get('child_ok') is True and _equal_int(metadata.get('child_status'), 0),
            'both_operations_finished': metadata.get('a_done') is True and metadata.get('b_done') is True,
            **{key + '_succeeded': k03._call_ok(metadata, key) for key in ('gate0', 'a_completed_wake0', 'b_completed_wake1', 'reset')}}
        for role, rows in events.items():
            stats = k03._stats(rows, None)
            checks['sequence'][role + '_nonempty_memory'] = stats['memory_records'] > 0
            checks['sequence'][role + '_no_in_trace_wait_or_wake'] = stats['waits'] == stats['wakes'] == stats['timeouts'] == 0
            checks['sequence'][role + '_reported_stats_match'] = metadata.get(role) == stats
        checks['control']['not_requested_in_baseline'] = True
    declared = marker_source() if declared_marker is None else declared_marker
    mapped, markers, projections = {}, {}, {}
    for role, rows in events.items():
        projection = []
        for event in rows:
            if event['kind'] != 'MEMORY':
                continue
            source = k03._mapping(event['ip'], mapping)
            if source.get('raw_ip') != event['ip'] or int(source.get('lookup_ip', '0'), 16) != int(event['ip'], 16) - 1:
                raise ValueError('Source map does not bind raw return IP to lookup IP minus one')
            projection.append({'event': event, 'source': source})
        projections[role] = projection
        mapped[role + '_real_core_memory'] = any(_source_ends(x['source']['file'], 'drivers/base/regmap/regmap.c') for x in projection)
        for operation in ('read', 'write'):
            # update_bits skips the write when the masked value is unchanged.
            if operation == 'write' and mode == 'update-bits':
                continue
            mapped[role + '_real_ram_' + operation] = any(_source_ends(x['source']['file'], 'drivers/base/regmap/regmap-ram.c') and x['source']['symbol'] == 'regmap_ram_' + operation for x in projection)
        if mode == 'update-bits':
            mapped[role + '_locked_update_api'] = any(_source_ends(x['source']['file'], 'drivers/base/regmap/regmap.c') and x['source']['symbol'] == 'regmap_update_bits_base' for x in projection)
        candidates = [x for x in projection if _source_ends(x['source']['file'], declared['file'])
            and x['source']['symbol'] == declared['symbol'] and x['source']['line'] == declared['line']
            and x['source']['exact_line'] is True and x['event']['size'] == 4
            and (x['event']['flags'] & 0x1f) == 0x10 and not (x['event']['flags'] & 0x20)]
        markers[role] = candidates
    checks['mapping'] = mapped
    checks['marker'] = {role + '_unique_declared_store': len(rows) == 1 for role, rows in markers.items()}
    if all(len(rows) == 1 for rows in markers.values()):
        checks['marker']['distinct_role_storage'] = markers['A'][0]['event']['address'] != markers['B'][0]['event']['address']
        for role in markers:
            checkpoint = markers[role][0]['event']['word_index']
            ram_reads = [x for x in projections[role] if _source_ends(x['source']['file'], 'drivers/base/regmap/regmap-ram.c') and x['source']['symbol'] == 'regmap_ram_read']
            ram_writes = [x for x in projections[role] if _source_ends(x['source']['file'], 'drivers/base/regmap/regmap-ram.c') and x['source']['symbol'] == 'regmap_ram_write']
            if mode == 'split' and guarded_split:
                checks['marker'][role + '_before_guarded_read_write'] = bool(ram_reads and ram_writes) and all(x['event']['word_index'] > checkpoint for x in ram_reads + ram_writes)
            elif mode == 'split':
                checks['marker'][role + '_after_read_before_write'] = bool(ram_reads and ram_writes) and all(x['event']['word_index'] < checkpoint for x in ram_reads) and all(x['event']['word_index'] > checkpoint for x in ram_writes)
            elif mode == 'update-bits':
                checks['marker'][role + '_before_locked_update'] = bool(ram_reads) and all(x['event']['word_index'] > checkpoint for x in ram_reads + ram_writes)
            else:
                checks['marker']['known_mode'] = False
        if replay:
            checks['marker']['plan_names_declared_A_store'] = plan['stack'] == markers['A'][0]['event']['stack']
    return checks, {'raw': raw, 'markers': markers, 'projection': projections, 'marker_source': declared,
                    'write_value_semantics': 'KCOV pre-access snapshot; not the value being stored or proof of a reads-from relation'}


def analyze(trace, mapping, guest, replay=False):
    """Independently check a baseline or one marker replay, retaining failures."""
    result = {'schema_version': 1, 'kind': 'kconc.regmap-rmw.analysis', 'passed': False, 'replay': replay,
              'checks': {}, 'groups': {}, 'errors': [], 'observations': {}, 'artifacts': {}, 'scope': SCOPE}
    trace = Path(trace)
    sections = {}
    rows = None
    mode = None
    try:
        rows = read_phases(trace)
        result['observations']['phases'] = rows
        sections.update(phase_checks(rows))
        mode = rows[0]['mode']
        result['observations'].update(case_id=rows[0]['case_id'], mode=mode)
        result['property'] = oracle.evaluate(rows[0]['initial'], rows[0]['operations'], rows[3]['values'])
        sections['schedule_outcome'] = schedule_checks(rows, replay)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append('phases: ' + str(error))
        sections['phase_evidence'] = {'readable_and_valid': False}
    try:
        source_map, map_record = read_mapping(mapping)
        result['artifacts']['source_map'] = map_record
        traced, observed = inspect_trace(trace, source_map, replay, mode)
        sections.update(traced)
        result['observations'].update(observed)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append('trace: ' + str(error))
        sections['trace_evidence'] = {'readable_and_valid': False}
    try:
        guest = _object(guest)
        cleanup = guest.get('local_cleanup', {})
        sections['supervisor'] = {'schema': _equal_int(guest.get('schema_version'), 1) and guest.get('kind') == 'kconc.guest',
            'completed': guest.get('outcome') == 'completed' and _equal_int(guest.get('exit_code'), 0),
            'no_remaining_processes': guest.get('remaining_pids') == [] and type(guest.get('remaining_pids')) is list,
            'process_cleanup_confirmed': isinstance(cleanup, dict) and cleanup.get('confirmed') is True and cleanup.get('errors') == [],
            'no_phase_parse_errors': guest.get('phase_errors') == [],
            'phases_match_collected_stdout': rows is not None and guest.get('phases') == rows,
            'not_fault_injection': guest.get('fault') == 'none'}
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['errors'].append('supervisor: ' + str(error))
        sections['supervisor'] = {'readable_and_valid': False}
    for group, checks in sections.items():
        result['groups'][group] = bool(checks) and all(value is True for value in checks.values())
        result['checks'].update({group + '.' + key: value is True for key, value in checks.items()})
    for name in ('run.json', 'testcase.stdout.txt', 'A.words', 'B.words', 'A.events.jsonl', 'B.events.jsonl', 'plan.txt'):
        path = trace / name
        if path.is_file():
            result['artifacts'][name] = digest(path)
    result['passed'] = bool(result['checks']) and all(result['checks'].values()) and not result['errors']
    result['execution_valid'] = result['passed']
    result['control_valid'] = all(result['groups'].get(group) is True for group in ('raw', 'sequence', 'control', 'marker'))
    result['property_evaluated'] = result['passed'] and 'property' in result
    result['property_violation'] = result['property_evaluated'] and result['property']['allowed'] is False
    return result


def make_plan(trace, mapping, out):
    """Bind one observed lock-free marker stack; never search arbitrary conflicts.

    This binds trace/source/plan bytes, not the running kernel or guest build.
    The caller must bind and validate those identities before any execution.
    """
    trace, out = Path(trace), Path(out)
    source_map, map_record = read_mapping(mapping)
    rows = read_phases(trace)
    checks, observations = inspect_trace(trace, source_map, False, rows[0].get('mode'))
    checks.update(phase_checks(rows))
    checks['schedule_outcome'] = schedule_checks(rows, False)
    failed = [group + '.' + key for group, values in checks.items() for key, value in values.items() if value is not True]
    if failed:
        raise ValueError('Cannot bind invalid baseline: ' + ', '.join(failed))
    if not oracle.evaluate(rows[0]['initial'], rows[0]['operations'], rows[3]['values'])['allowed']:
        raise ValueError('Sequential baseline violates the declared masked-update contract')
    marker = observations['markers']['A'][0]
    stack = marker['event']['stack']
    text = 'MACCCONC_K03_PLAN_V1\nspin_limit 1000000\nrole A\ncount ' + str(len(stack)) + '\n'
    text += ''.join(entry['ip'][2:] + ' ' + str(entry['parent_idx']) + '\n' for entry in stack)
    # Validate exactly the bytes that will be used; no existing output is replaced.
    if not 2 <= len(stack) <= 32 or any(int(x['ip'], 16) < 0xffffffff80000000 for x in stack):
        raise ValueError('Observed marker stack is outside the fixed executor plan format')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'plan.txt').write_text(text, encoding='ascii')
    plan = k03.read_plan(out / 'plan.txt')
    binding = {'schema_version': 1, 'kind': 'kconc.regmap-rmw.marker-binding', 'scenario': 'regmap-rmw-v1',
        'case_id': rows[0]['case_id'], 'mode': rows[0]['mode'],
        'plan_path': str(out / 'plan.txt'), 'binding_path': str(out / 'binding.json'), 'plan_sha256': plan['sha256'],
        'source_map': map_record, 'marker': marker, 'marker_source': observations['marker_source'],
        'trace_sha256': {name: digest(trace / name) for name in ('run.json', 'testcase.stdout.txt', 'A.words', 'B.words', 'A.events.jsonl', 'B.events.jsonl')},
        'analysis_sha256': digest(Path(__file__)), 'k03_analysis_sha256': digest(Path(__file__).with_name('k03_analysis.py')),
        'oracle_sha256': digest(REPO / 'src/kconc/regmap_oracle.py'),
        'runtime_identity_bound': False, 'scope': 'Observed fixed marker plan; caller must bind kernel, configuration, binaries and ABI before replay'}
    (out / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
    return binding

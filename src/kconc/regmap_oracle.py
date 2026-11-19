"""K06 specification oracle for two synchronous masked register updates.

The contract is the final state of two atomic masked updates in either serial
order. It is intentionally independent of the split-RMW implementation and of
the native verdict. It is not an oracle for all Linux concurrency semantics.
"""
from __future__ import annotations

U32 = 0xffffffff
MODES = {'split': 0, 'update-bits': 1}
ORACLE = 'regmap-two-masked-updates'
CASES = {
    'disjoint-bits': ([0, 0, 0, 0], [(0, 1, 1), (0, 2, 2)]),
    'overlap-bits': ([0, 0, 0, 0], [(0, 3, 1), (0, 3, 2)]),
    'different-registers': ([0, 0, 0, 0], [(0, 1, 1), (1, 2, 2)]),
    'zero-mask': ([0, 0, 0, 0], [(0, 0, 0), (0, 2, 2)]),
    'high-bits': ([0xa5a55a5a, 17, 34, 51], [(0, 0x80000000, 0), (0, 0x40000000, 0x40000000)]),
}


def uint(value, maximum=U32):
    return type(value) is int and 0 <= value <= maximum


def vector(value):
    return type(value) is list and len(value) == 4 and all(uint(x) for x in value)


def case_spec(case_id):
    if type(case_id) is not str or case_id not in CASES:
        raise ValueError('Unknown K06 input case')
    initial, operations = CASES[case_id]
    return {'initial': list(initial), 'operations': [
        dict(role=role, reg=reg, mask=mask, value=value)
        for role, (reg, mask, value) in enumerate(operations)]}


def validate_inputs(initial, operations):
    if not vector(initial):
        raise ValueError('Initial state must contain exactly four uint32 registers')
    if type(operations) is not list or len(operations) != 2:
        raise ValueError('Exactly two logical operations are required')
    for role, op in enumerate(operations):
        if not isinstance(op, dict) or set(op) != {'role', 'reg', 'mask', 'value'}:
            raise ValueError('Operation must specify role, reg, mask and value')
        if not uint(op['role'], 1) or op['role'] != role or not uint(op['reg'], 3):
            raise ValueError('Logical roles must remain A=0/B=1 and register must be in range')
        if not uint(op['mask']) or not uint(op['value']):
            raise ValueError('Masks and values must be uint32')


def apply_update(state, operation):
    """Apply the specification, keeping bits outside the mask unchanged."""
    result = list(state)
    reg, mask, value = (operation[key] for key in ('reg', 'mask', 'value'))
    result[reg] = (result[reg] & (U32 ^ mask)) | (value & mask)
    return result


def evaluate(initial, operations, final):
    validate_inputs(initial, operations)
    if not vector(final):
        raise ValueError('Observed final state must contain exactly four uint32 registers')
    serial = {name: apply_update(apply_update(initial, operations[first]), operations[second])
              for name, first, second in [('A-B', 0, 1), ('B-A', 1, 0)]}
    legal = []
    for state in serial.values():
        if state not in legal:
            legal.append(state)
    matching = [name for name, state in serial.items() if state == final]
    return {'oracle': ORACLE, 'initial': list(initial), 'operations': [dict(x) for x in operations],
            'serial_results': serial, 'legal_results': legal, 'observed': list(final),
            'allowed': bool(matching), 'matching_orders': matching,
            'error_type': None if matching else 'nonserializable-masked-update',
            'scope': 'Final-state contract for two declared masked updates; caller-misuse construction, not an upstream kernel bug claim'}


def validate_case(case_id, mode, initial, operations):
    validate_inputs(initial, operations)
    if type(mode) is not str or mode not in MODES:
        raise ValueError('Unknown K06 operation mode')
    if {'initial': initial, 'operations': operations} != case_spec(case_id):
        raise ValueError('Input does not match the bound K06 case')
    return True


def validate_client(record):
    """Recompute every exported observation in the fixed 20-row AB/BA matrix."""
    checks, verdicts = {}, []

    def check(name, value):
        checks[name] = value is True

    def eq(value, expected):
        return type(value) is int and value == expected

    def equal_vector(actual, expected):
        return vector(actual) and actual == expected

    role_fields = ('pid', 'checkpoint', 'preempt_count', 'irqs_disabled', 'before', 'after',
                   'reg', 'started', 'completed', 'status', 'mode', 'values_valid')

    def status(label, observed, epoch, state, values, roles):
        check(label + '.object', isinstance(observed, dict))
        observed = observed if isinstance(observed, dict) else {}
        for name, wanted in dict(abi=2, epoch=epoch, state=state, active=0,
                                 completed_mask=3 if roles else 0, snapshot_valid=1).items():
            check(label + '.' + name, eq(observed.get(name), wanted))
        check(label + '.values', equal_vector(observed.get('values'), values))
        slots = observed.get('roles')
        shape = type(slots) is list and len(slots) == 2 and all(isinstance(s, dict) for s in slots)
        check(label + '.roles_shape', shape)
        if shape:
            for role, slot in enumerate(slots):
                expected = roles[role] if roles else dict.fromkeys(role_fields, 0)
                check(label + f'.role{role}', set(slot) == set(role_fields) and all(eq(slot.get(k), expected.get(k)) for k in role_fields))

    check('record.object', isinstance(record, dict))
    record = record if isinstance(record, dict) else {}
    check('schema', eq(record.get('schema_version'), 1))
    check('kind', record.get('kind') == 'kconc.regmap-rmw-matrix')
    check('native_passed', record.get('passed') is True)
    check('caller_misuse_example', record.get('caller_misuse_example') is True and record.get('kernel_bug_claim') is False)
    check('requested_rounds', eq(record.get('requested_rounds'), 20))
    check('completed_rounds', eq(record.get('completed_rounds'), 20))
    tid = record.get('caller_tid')
    check('caller_tid', uint(tid, 0x7fffffff) and tid > 0)
    rounds = record.get('rounds')
    check('rounds.shape', type(rounds) is list and len(rounds) == 20)
    rounds = rounds if type(rounds) is list else []
    combinations = [(case_id, mode, order) for case_id in CASES for mode in MODES for order in ('A-B', 'B-A')]
    for index, (case_id, mode, order) in enumerate(combinations):
        row = rounds[index] if index < len(rounds) else None
        prefix = f'round[{index}]'
        check(prefix + '.object', isinstance(row, dict))
        row = row if isinstance(row, dict) else {}
        epoch, wanted = index + 1, case_spec(case_id)
        inputs = row.get('inputs')
        try:
            if not isinstance(inputs, dict):
                raise ValueError('input object missing')
            validate_case(inputs.get('case_id'), row.get('mode'), inputs.get('initial'), inputs.get('operations'))
            input_ok = inputs['case_id'] == case_id
        except (TypeError, ValueError):
            input_ok = False
        check(prefix + '.bound_inputs', input_ok)
        check(prefix + '.mode', row.get('mode') == mode)
        check(prefix + '.order', row.get('order') == order)
        for key, value in {'round': index, 'reset_rc': 0, 'reset_errno': 0, 'initial_rc': 0, 'final_rc': 0}.items():
            check(prefix + '.' + key, eq(row.get(key), value))
        check(prefix + '.initial_passed', row.get('initial_passed') is True)
        check(prefix + '.native_passed', row.get('passed') is True)
        status(prefix + '.initial', row.get('initial'), epoch, 1, wanted['initial'], None)
        operations = row.get('operations')
        check(prefix + '.operations_shape', type(operations) is list and len(operations) == 2)
        operations = operations if type(operations) is list else []
        expected = list(wanted['initial'])
        expected_slots = [None, None]
        for number, role in enumerate((0, 1) if order == 'A-B' else (1, 0)):
            op = operations[number] if number < len(operations) else None
            label = prefix + f'.operation[{number}]'
            check(label + '.object', isinstance(op, dict))
            op = op if isinstance(op, dict) else {}
            declared = wanted['operations'][role]
            before = expected[declared['reg']]
            expected = apply_update(expected, declared)
            after = expected[declared['reg']]
            expected_op = dict(declared, abi=2, epoch=epoch, mode=MODES[mode], reserved=0,
                               rc=0, errno=0, status=0, caller_tid=tid, kernel_pid=tid,
                               checkpoint=epoch, preempt_count=0, irqs_disabled=0,
                               before=before if mode == 'split' else 0,
                               after=after if mode == 'split' else 0,
                               values_valid=1 if mode == 'split' else 0)
            for key, value in expected_op.items():
                check(label + '.' + key, eq(op.get(key), value))
            expected_slots[role] = {key: expected_op[key] for key in role_fields if key in expected_op}
            expected_slots[role].update(pid=tid, started=1, completed=1)
        status(prefix + '.final', row.get('final'), epoch, 1, expected, expected_slots)
        final = row.get('final')
        try:
            verdict = evaluate(wanted['initial'], wanted['operations'], final.get('values') if isinstance(final, dict) else None)
            verdicts.append(dict(round=index, case_id=case_id, mode=mode, order=order, **verdict))
            check(prefix + '.allowed', verdict['allowed'] is True and row.get('allowed') is verdict['allowed'])
        except (TypeError, ValueError):
            check(prefix + '.allowed', False)
    check('teardown_rc', eq(record.get('teardown_rc'), 0))
    check('close_rc', eq(record.get('close_rc'), 0))
    check('resources_closed', record.get('resources_closed') is True)
    status('teardown', record.get('teardown'), 20, 0, [0, 0, 0, 0], None)
    errors = [name for name, passed in checks.items() if not passed]
    return {'passed': not errors, 'checks': checks, 'errors': errors, 'verdicts': verdicts,
            'scope': 'All 20 declared sequential controls and exported status/roles; not concurrent search or whole-kernel correctness'}

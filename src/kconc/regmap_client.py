"""Independently check the visible fields of the fixed K05 native client report.

The native executable is separately bound to its source/build hashes. Its
unexported per-role bookkeeping remains a native-only check, named below; the
host does not infer missing observations from the aggregate passed flag.
"""


def _int(value, expected=None, minimum=0, maximum=0xffffffff):
    return type(value) is int and minimum <= value <= maximum and (expected is None or value == expected)


def _signed(value, expected):
    return type(value) is int and value == expected


def _vector(value, expected):
    return type(value) is list and len(value) == len(expected) and all(_int(a, b) for a, b in zip(value, expected))


def validate_client(record, fault=False):
    """Validate the fixed 20-round baseline or explicitly injected reset test."""
    checks = {}

    def check(name, value):
        checks[name] = value is True

    def status(name, value, *, epoch, state, mask, values):
        check(name + '.object', isinstance(value, dict))
        value = value if isinstance(value, dict) else {}
        for key, expected in {'abi': 1, 'epoch': epoch, 'state': state, 'active': 0,
                              'completed_mask': mask, 'snapshot_valid': 1}.items():
            check(name + '.' + key, _int(value.get(key), expected))
        check(name + '.values', _vector(value.get('values'), values))

    check('record.object', isinstance(record, dict))
    record = record if isinstance(record, dict) else {}
    check('fault_argument', type(fault) is bool)
    check('schema_version', _int(record.get('schema_version'), 1))
    check('kind', record.get('kind') == ('kconc.regmap-reset-fault' if fault else 'kconc.regmap-baseline'))
    check('native_reported_passed', record.get('passed') is True)
    check('no_kernel_bug_claim', record.get('kernel_bug_claim') is False)
    if fault:
        check('injected', record.get('injected') is True)
        # Fixed Linux x86_64 ABI: EIO=5, EUCLEAN=117. These are errno values,
        # never a deadlock/property verdict or proof of whole-guest recovery.
        expected = {'initial_reset_rc': 0, 'fault_rc': -1, 'fault_errno': 5,
                    'operation_rc': -1, 'operation_errno': 117,
                    'reset_retry_rc': -1, 'reset_retry_errno': 117,
                    'teardown_rc': 0, 'close_rc': 0,
                    'after_teardown_reset_rc': -1, 'after_teardown_reset_errno': 117,
                    'fresh_operation_rc': 0, 'fresh_operation_before': 0,
                    'fresh_operation_after': 1, 'fresh_teardown_rc': 0, 'fresh_close_rc': 0}
        for name, value in expected.items():
            check(name, _signed(record.get(name), value))
        for name in ('poison_after_teardown', 'failed_closed', 'fresh_open_ready', 'fresh_operation_passed'):
            check(name, record.get(name) is True)
        status('poisoned', record.get('poisoned'), epoch=1, state=2, mask=0, values=[17, 32, 48, 64])
        status('fresh_status', record.get('fresh_status'), epoch=1, state=1, mask=0, values=[0, 0, 0, 0])
        native_only = ['Unexported per-role bookkeeping in initial and fresh status',
                       'Fresh operation PID, checkpoint, preemption/IRQ state and status',
                       'Post-teardown zero resource/role snapshot']
    else:
        check('requested_rounds', _int(record.get('requested_rounds'), 20))
        check('completed_rounds', _int(record.get('completed_rounds'), 20))
        tid = record.get('caller_tid')
        check('caller_tid', _int(tid, minimum=1, maximum=0x7fffffff))
        rounds = record.get('rounds')
        check('rounds.shape', type(rounds) is list and len(rounds) == 20)
        rounds = rounds if type(rounds) is list else []
        for number in range(20):
            row = rounds[number] if number < len(rounds) else None
            prefix = f'round[{number}]'
            check(prefix + '.object', isinstance(row, dict))
            row = row if isinstance(row, dict) else {}
            epoch = number + 1
            check(prefix + '.index', _int(row.get('round'), number))
            check(prefix + '.reset_rc', _signed(row.get('reset_rc'), 0))
            check(prefix + '.reset_errno', _int(row.get('reset_errno'), 0))
            check(prefix + '.initial_passed', row.get('initial_passed') is True)
            check(prefix + '.native_round_passed', row.get('passed') is True)
            same = bool(number & 1)
            reversed_order = bool(number & 2)
            check(prefix + '.same_register', type(row.get('same_register')) is bool and row['same_register'] == same)
            check(prefix + '.order', row.get('order') == ('B-A' if reversed_order else 'A-B'))
            values = [epoch * 16 + i * 4 for i in range(4)]
            status(prefix + '.initial', row.get('initial'), epoch=epoch, state=1, mask=0, values=values)
            operations = row.get('operations')
            check(prefix + '.operations.shape', type(operations) is list and len(operations) == 2)
            operations = operations if type(operations) is list else []
            for index in range(2):
                operation = operations[index] if index < len(operations) else None
                label = prefix + f'.operation[{index}]'
                check(label + '.object', isinstance(operation, dict))
                operation = operation if isinstance(operation, dict) else {}
                role = 1 - index if reversed_order else index
                reg = 0 if same else role
                before = values[reg]
                values[reg] = before | (1 << role)
                expected = {'role': role, 'reg': reg, 'rc': 0, 'errno': 0,
                            'before': before, 'after': values[reg],
                            'expected_before': before, 'expected_after': values[reg],
                            'checkpoint': epoch, 'preempt_count': 0, 'irqs_disabled': 0}
                for key, value in expected.items():
                    check(label + '.' + key, _int(operation.get(key), value))
                check(label + '.pid', _int(tid, minimum=1) and _int(operation.get('pid'), tid))
                check(label + '.native_passed', operation.get('passed') is True)
            status(prefix + '.final', row.get('final'), epoch=epoch, state=1, mask=3, values=values)
        check('teardown_rc', _signed(record.get('teardown_rc'), 0))
        status('teardown', record.get('teardown'), epoch=20, state=0, mask=0, values=[0, 0, 0, 0])
        check('resources_closed', record.get('resources_closed') is True)
        native_only = ['Initial/final/teardown per-role bookkeeping is checked in the pinned native client but not exported',
                       'Native close return is summarized by resources_closed']
    errors = [name for name, passed in checks.items() if not passed]
    return {'passed': not errors, 'checks': checks, 'errors': errors,
            'native_only_checks': native_only,
            'scope': 'Independent validation of exported fixed-client observations; unexported checks remain native-only; not whole-guest recovery'}

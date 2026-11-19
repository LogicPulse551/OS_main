"""Specification examples and malformed-evidence checks; no kernel execution."""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from kconc import regmap_oracle as oracle


class OracleTests(unittest.TestCase):
    def verdict(self, case, final):
        spec = oracle.case_spec(case)
        return oracle.evaluate(spec['initial'], spec['operations'], final)

    def test_disjoint_bits_requires_both_updates(self):
        for value in (0, 1, 2):
            self.assertFalse(self.verdict('disjoint-bits', [value, 0, 0, 0])['allowed'])
        self.assertEqual(self.verdict('disjoint-bits', [3, 0, 0, 0])['matching_orders'], ['A-B', 'B-A'])

    def test_overlapping_mask_allows_either_last_writer(self):
        for value, order in [(1, 'B-A'), (2, 'A-B')]:
            result = self.verdict('overlap-bits', [value, 0, 0, 0])
            self.assertTrue(result['allowed'])
            self.assertEqual(result['matching_orders'], [order])
        self.assertFalse(self.verdict('overlap-bits', [3, 0, 0, 0])['allowed'])

    def test_zero_mask_is_noop_contract_but_stale_split_write_can_erase_b(self):
        self.assertTrue(self.verdict('zero-mask', [2, 0, 0, 0])['allowed'])
        self.assertFalse(self.verdict('zero-mask', [0, 0, 0, 0])['allowed'])

    def test_distinct_registers_and_untouched_registers_are_checked(self):
        self.assertTrue(self.verdict('different-registers', [1, 2, 0, 0])['allowed'])
        self.assertFalse(self.verdict('different-registers', [1, 2, 1, 0])['allowed'])

    def test_high_bit_unsigned_mask_clearing(self):
        result = self.verdict('high-bits', [0x65a55a5a, 17, 34, 51])
        self.assertTrue(result['allowed'])
        self.assertFalse(self.verdict('high-bits', [0x25a55a5a, 17, 34, 51])['allowed'])

    def test_values_outside_mask_have_no_effect(self):
        operations = [dict(role=0, reg=0, mask=1, value=0xfffffffe), dict(role=1, reg=0, mask=2, value=0xffffffff)]
        self.assertTrue(oracle.evaluate([15, 0, 0, 0], operations, [14, 0, 0, 0])['allowed'])

    def test_bad_initial_or_final_shape_is_rejected(self):
        spec = oracle.case_spec('disjoint-bits')
        for bad in ([0, 0, 0], [False, 0, 0, 0], [-1, 0, 0, 0], [2**32, 0, 0, 0], (0, 0, 0, 0)):
            with self.assertRaises(ValueError):
                oracle.evaluate(bad, spec['operations'], [3, 0, 0, 0])
            with self.assertRaises(ValueError):
                oracle.evaluate(spec['initial'], spec['operations'], bad)

    def test_bad_roles_registers_masks_and_bool_aliases_are_rejected(self):
        spec = oracle.case_spec('disjoint-bits')
        for key, value in [('role', 1), ('role', False), ('reg', 4), ('mask', True), ('value', -1)]:
            bad = copy.deepcopy(spec['operations'])
            bad[0][key] = value
            with self.assertRaises(ValueError):
                oracle.evaluate(spec['initial'], bad, [3, 0, 0, 0])

    def test_contract_cannot_be_silently_renamed(self):
        spec = oracle.case_spec('disjoint-bits')
        for case, mode in [('other', 'split'), ('disjoint-bits', 'atomic'), ([], 'split')]:
            with self.assertRaises(ValueError):
                oracle.validate_case(case, mode, spec['initial'], spec['operations'])


def matrix_fixture():
    """Native report shape with known sequential controls; assertions mutate it."""
    tid = 200
    rows = []
    fields = ('pid', 'checkpoint', 'preempt_count', 'irqs_disabled', 'before', 'after', 'reg', 'started', 'completed', 'status', 'mode', 'values_valid')
    def status(epoch, state, values, slots=None):
        return dict(abi=2, epoch=epoch, state=state, active=0, completed_mask=3 if slots else 0,
                    snapshot_valid=1, values=list(values), roles=slots or [dict.fromkeys(fields, 0), dict.fromkeys(fields, 0)])
    for case in oracle.CASES:
        for mode in oracle.MODES:
            for reverse in (False, True):
                index, spec = len(rows), oracle.case_spec(case)
                epoch = index + 1
                state, operations, slots = list(spec['initial']), [], [None, None]
                for role in ((1, 0) if reverse else (0, 1)):
                    op = dict(spec['operations'][role])
                    before = state[op['reg']]
                    state[op['reg']] = (before & ~op['mask']) | (op['value'] & op['mask'])
                    op.update(abi=2, epoch=epoch, mode=oracle.MODES[mode], reserved=0,
                              rc=0, errno=0, status=0, caller_tid=tid, kernel_pid=tid,
                              checkpoint=epoch, preempt_count=0, irqs_disabled=0,
                              before=before if mode == 'split' else 0,
                              after=state[op['reg']] if mode == 'split' else 0,
                              values_valid=int(mode == 'split'))
                    operations.append(op)
                    slots[role] = {key: op[key] for key in fields if key in op}
                    slots[role].update(pid=tid, started=1, completed=1)
                rows.append(dict(round=index, mode=mode, order='B-A' if reverse else 'A-B',
                    inputs=dict(case_id=case, **spec), reset_rc=0, reset_errno=0, initial_rc=0,
                    initial_passed=True, initial=status(epoch, 1, spec['initial']), operations=operations,
                    final_rc=0, final=status(epoch, 1, state, slots), allowed=True, passed=True))
    return dict(schema_version=1, kind='kconc.regmap-rmw-matrix', passed=True, caller_tid=tid,
                requested_rounds=20, completed_rounds=20, rounds=rows, teardown_rc=0, close_rc=0,
                teardown=status(20, 0, [0, 0, 0, 0]), resources_closed=True,
                kernel_bug_claim=False, caller_misuse_example=True)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.record = matrix_fixture()

    def check(self):
        return oracle.validate_client(self.record)

    def test_complete_matrix(self):
        result = self.check()
        self.assertTrue(result['passed'], result['errors'])
        self.assertEqual(len(result['verdicts']), 20)

    def test_round_missing_or_wrong_order_is_rejected(self):
        self.record['rounds'][0], self.record['rounds'][1] = self.record['rounds'][1], self.record['rounds'][0]
        self.assertFalse(self.check()['passed'])
        self.record['rounds'].pop()
        self.assertFalse(self.check()['passed'])

    def test_native_flags_do_not_hide_wrong_value(self):
        self.record['rounds'][0]['final']['values'][0] = 1
        self.assertFalse(self.check()['passed'])

    def test_operation_input_cannot_be_relabelled(self):
        self.record['rounds'][0]['operations'][0]['mask'] = 2
        self.assertFalse(self.check()['passed'])

    def test_same_input_cannot_replace_distinct_case(self):
        self.record['rounds'][4]['inputs'] = copy.deepcopy(self.record['rounds'][0]['inputs'])
        self.assertFalse(self.check()['passed'])

    def test_fixed_values_not_available_is_enforced(self):
        self.record['rounds'][2]['operations'][0]['values_valid'] = 1
        self.assertFalse(self.check()['passed'])

    def test_kernel_role_slot_is_checked(self):
        self.record['rounds'][0]['final']['roles'][0]['pid'] = 123
        self.assertFalse(self.check()['passed'])

    def test_initial_roles_and_final_cleanup_are_checked(self):
        self.record['rounds'][0]['initial']['roles'][1]['started'] = 1
        self.assertFalse(self.check()['passed'])
        self.record = matrix_fixture()
        self.record['teardown']['roles'][0]['values_valid'] = 1
        self.assertFalse(self.check()['passed'])

    def test_integer_boolean_alias_is_rejected(self):
        self.record['rounds'][0]['operations'][0]['rc'] = False
        self.assertFalse(self.check()['passed'])

    def test_incomplete_record_does_not_raise(self):
        for record in ({}, None, {'rounds': [None]}, {'rounds': [dict(inputs=None)]}):
            self.assertFalse(oracle.validate_client(record)['passed'])


if __name__ == '__main__':
    unittest.main()

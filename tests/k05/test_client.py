"""Host report-validation regressions; fixtures are not kernel executions."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from kconc.regmap_client import validate_client


def status(epoch, state, mask, values):
    return dict(abi=1, epoch=epoch, state=state, active=0, completed_mask=mask,
                snapshot_valid=1, values=list(values))


def baseline():
    rows = []
    for n in range(20):
        values = [(n + 1) * 16 + i * 4 for i in range(4)]
        row = dict(round=n, reset_rc=0, reset_errno=0, initial_passed=True, passed=True,
                   initial=status(n + 1, 1, 0, values), same_register=bool(n & 1),
                   order='B-A' if n & 2 else 'A-B', operations=[])
        for role in ([1, 0] if n & 2 else [0, 1]):
            reg = 0 if n & 1 else role
            before = values[reg]
            values[reg] |= 1 << role
            row['operations'].append(dict(role=role, reg=reg, rc=0, errno=0, passed=True,
                before=before, after=values[reg], expected_before=before, expected_after=values[reg],
                pid=321, checkpoint=n + 1, preempt_count=0, irqs_disabled=0))
        row['final'] = status(n + 1, 1, 3, values)
        rows.append(row)
    return dict(schema_version=1, kind='kconc.regmap-baseline', requested_rounds=20,
        completed_rounds=20, caller_tid=321, rounds=rows, teardown_rc=0,
        teardown=status(20, 0, 0, [0]*4), resources_closed=True,
        passed=True, kernel_bug_claim=False)


def fault_report():
    return dict(schema_version=1, kind='kconc.regmap-reset-fault', passed=True,
        injected=True, kernel_bug_claim=False, initial_reset_rc=0, fault_rc=-1, fault_errno=5,
        poisoned=status(1, 2, 0, [17, 32, 48, 64]), operation_rc=-1, operation_errno=117,
        reset_retry_rc=-1, reset_retry_errno=117, teardown_rc=0, close_rc=0,
        after_teardown_reset_rc=-1, after_teardown_reset_errno=117,
        poison_after_teardown=True, failed_closed=True, fresh_open_ready=True,
        fresh_status=status(1, 1, 0, [0]*4), fresh_operation_rc=0,
        fresh_operation_passed=True, fresh_operation_before=0, fresh_operation_after=1,
        fresh_teardown_rc=0, fresh_close_rc=0)


class ClientTests(unittest.TestCase):
    def reject(self, value, *, fault=False, contains=None):
        result = validate_client(value, fault=fault)
        self.assertFalse(result['passed'])
        self.assertTrue(result['errors'])
        if contains:
            self.assertTrue(any(contains in error for error in result['errors']), result['errors'])

    def test_complete_baseline_and_fault_reports_pass_visible_checks(self):
        for value, fault in [(baseline(), False), (fault_report(), True)]:
            with self.subTest(fault=fault):
                result = validate_client(value, fault=fault)
                self.assertTrue(result['passed'], result['errors'])
                self.assertTrue(result['native_only_checks'])

    def test_aggregate_success_alone_cannot_establish_execution(self):
        for value in (None, [], True, {'passed': True}, {'schema_version': 1, 'passed': True}):
            for fault in (False, True):
                with self.subTest(value=value, fault=fault):
                    self.reject(value, fault=fault)

    def test_schema_kind_and_bug_claim_cannot_be_coerced(self):
        for key, value in [('schema_version', True), ('kind', 'kconc.guest'),
                           ('passed', 1), ('kernel_bug_claim', 0), ('kernel_bug_claim', True)]:
            row = baseline(); row[key] = value
            with self.subTest(key=key, value=value): self.reject(row)

    def test_all_twenty_rounds_are_required_in_denominator(self):
        for mutation in ('missing', 'duplicate', 'count', 'zero'):
            row = baseline()
            if mutation == 'missing': row['rounds'].pop()
            elif mutation == 'duplicate': row['rounds'][5] = copy.deepcopy(row['rounds'][4])
            elif mutation == 'count': row['completed_rounds'] = 19
            else: row['rounds'] = []; row['completed_rounds'] = 0
            with self.subTest(mutation=mutation): self.reject(row)

    def test_reset_epochs_initial_values_and_idle_state_are_checked(self):
        for key, value in [('epoch', 1), ('state', 2), ('active', 1), ('snapshot_valid', 0),
                           ('completed_mask', 3), ('values', [0, 0, 0, 0])]:
            row = baseline(); row['rounds'][1]['initial'][key] = value
            with self.subTest(key=key): self.reject(row, contains='round[1].initial')

    def test_declared_order_and_logical_roles_cannot_disagree(self):
        row = baseline(); row['rounds'][2]['operations'].reverse()
        self.reject(row, contains='role')
        row = baseline(); row['rounds'][0]['same_register'] = 0
        self.reject(row, contains='same_register')
        row = baseline(); row['rounds'][3]['order'] = 'A-B'
        self.reject(row, contains='order')

    def test_caller_context_and_checkpoint_must_match(self):
        for key, value in [('pid', 322), ('pid', True), ('checkpoint', 0),
                           ('preempt_count', 1), ('irqs_disabled', 1), ('rc', False)]:
            row = baseline(); row['rounds'][0]['operations'][0][key] = value
            with self.subTest(key=key, value=value): self.reject(row, contains=key)

    def test_expected_fields_do_not_override_recomputed_values(self):
        row = baseline()
        op = row['rounds'][1]['operations'][1]
        op['before'] = op['expected_before'] = 777
        op['after'] = op['expected_after'] = 779
        row['rounds'][1]['final']['values'][0] = 779
        self.reject(row, contains='before')

    def test_final_snapshot_and_teardown_must_be_clean(self):
        for target, key, value in [('final', 'completed_mask', 1), ('final', 'snapshot_valid', 0),
                                   ('teardown', 'state', 1), ('teardown', 'values', [1, 0, 0, 0])]:
            row = baseline()
            (row['rounds'][0]['final'] if target == 'final' else row['teardown'])[key] = value
            with self.subTest(target=target, key=key): self.reject(row)
        row = baseline(); row['resources_closed'] = False
        self.reject(row, contains='resources_closed')

    def test_fault_requires_real_corrupted_value_and_poison(self):
        for key, value in [('values', [16, 32, 48, 64]), ('state', 1), ('active', 1), ('epoch', 2)]:
            row = fault_report(); row['poisoned'][key] = value
            with self.subTest(key=key): self.reject(row, fault=True, contains='poisoned')

    def test_fault_errnos_and_retry_rejections_are_independent_checks(self):
        for key, value in [('fault_errno', 110), ('fault_rc', 0), ('operation_errno', 0),
                           ('reset_retry_errno', 5), ('after_teardown_reset_rc', 0),
                           ('fresh_close_rc', False)]:
            row = fault_report(); row[key] = value
            with self.subTest(key=key): self.reject(row, fault=True, contains=key)

    def test_fault_fresh_open_must_reset_epoch_values_and_operation(self):
        row = fault_report(); row['fresh_status']['epoch'] = 2
        self.reject(row, fault=True, contains='fresh_status')
        row = fault_report(); row['fresh_operation_after'] = 0
        self.reject(row, fault=True, contains='fresh_operation_after')
        row = fault_report(); row['poison_after_teardown'] = False
        self.reject(row, fault=True, contains='poison_after_teardown')

    def test_malformed_nested_shapes_fail_without_crashing(self):
        mutations = [lambda x: x.update(rounds=None),
                     lambda x: x['rounds'].__setitem__(0, None),
                     lambda x: x['rounds'][0].update(operations=[None, []]),
                     lambda x: x['rounds'][0].update(initial=False),
                     lambda x: x.update(teardown=[])]
        for mutate in mutations:
            row = baseline(); mutate(row)
            self.reject(row)


if __name__ == '__main__':
    unittest.main()

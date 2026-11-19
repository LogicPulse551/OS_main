"""Synthetic boundary tests, not evidence of a real kernel execution.

Reuse the accepted K06 lifecycle fixture and K07 interval fixtures. Placeholder
raw words exercise export framing, not independent decoding of KCOV bytes.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analysis = load('k08_analysis', REPO / 'adapters/maccconc/k08_analysis.py')
rmw_fixture = load('k08_rmw_fixture', REPO / 'tests/k06/test_analysis.py')
mutex_fixture = load('k08_mutex_fixture', REPO / 'tests/k07/test_oracle.py')


class AnalysisTests(unittest.TestCase):
    def fixture(self, family='rmw', order='ab', case=None, mode=None):
        f = rmw_fixture.AnalysisTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.family, f.order = family, order
        roles = {'A': 'A', 'B': 'B'} if order == 'ab' else {'A': 'B', 'B': 'A'}
        f.meta.update(baseline_order=order, slot_to_logical_role=roles,
            logical_role_to_callback=analysis.CALLBACKS, raw_trace_namespace='execution_slot',
            sampling_only=True, automatic_candidates_executed=0, slot_tids={'A': 200, 'B': 201},
            roles={slot: analysis.CALLBACKS[role] for slot, role in roles.items()})
        tids = (200, 201) if order == 'ab' else (201, 200)
        if family == 'rmw':
            case, mode = case or 'disjoint-bits', mode or 'split'
            spec = analysis.k06.oracle.case_spec(case)
            f.phases[0].update(case_id=case, mode=mode, **spec)
            f.phases[1]['values'] = list(spec['initial'])
            values = list(spec['initial'])
            for role in ((0, 1) if order == 'ab' else (1, 0)):
                op = spec['operations'][role]
                before = values[op['reg']]
                values = analysis.k06.oracle.apply_update(values, op)
                f.phases[2]['results'][role].update(op, mode=analysis.k06.oracle.MODES[mode],
                    values_valid=int(mode == 'split'), before=before if mode == 'split' else 0,
                    after=values[op['reg']] if mode == 'split' else 0,
                    kernel_pid=tids[role], caller_tid=tids[role])
            f.phases[3]['values'] = values
            f.sync_slots()
            if mode == 'update-bits':
                f.mapping[f.ips[0]]['symbol'] = 'regmap_update_bits_base'
                for slot in ('A', 'B'):
                    f.events[slot] = [f.events[slot][2], f.events[slot][0], f.events[slot][1], f.events[slot][3]]
        else:
            case, mode = case or 'different-registers', mode or 'shared'
            spec = analysis.k07.oracle.case_spec(case)
            operations, final = mutex_fixture.observed(case, mode, 'A-B' if order == 'ab' else 'B-A', tids=tids)
            f.phases = [
                dict(phase='setup', passed=True, case_id=case, mode=mode, **spec,
                    reset=dict(abi=3, flags=0, epoch=1, initial=spec['initial'], reserved=0),
                    reset_rc=0, errno=0, fd=5, epoch=1, initial_fds=[0, 1, 2, 3, 4], fault='none', injected=False),
                dict(phase='initial_state', passed=True, status_rc=0, initial=mutex_fixture.idle(1),
                    fd_set_matches=True, expected_fds=[0, 1, 2, 3, 4, 5], actual_fds=[0, 1, 2, 3, 4, 5]),
                dict(phase='operations', passed=True, a_calls=1, b_calls=1, results=operations),
                dict(phase='property', passed=True, infrastructure_valid=True, oracle=analysis.k07.oracle.ORACLE,
                    allowed=True, final=final, status_rc=0, injected=False, caller_misuse_example=True, kernel_bug_claim=False),
                dict(phase='teardown', passed=True, ioctl_rc=0, errno=0, close_rc=0, resources_closed=True,
                    fd_set_restored=True, fd_snapshot_observed=True, expected_fds=[0, 1, 2, 3, 4],
                    actual_fds=[0, 1, 2, 3, 4], empty=mutex_fixture.idle(2, 0),
                    post_control_progress=mutex_fixture.round_fixture(case, mode, 'B-A', 2, tid=200))]
            f.mapping[f.ips[2]]['line'] = analysis.k07.marker_source()['line']
            f.mapping[f.ips[0]]['symbol'] = 'regmap_update_bits_base'
            for slot in ('A', 'B'):
                f.events[slot] = [f.events[slot][2], f.events[slot][0], f.events[slot][1], f.events[slot][3]]
        f.guest['phases'] = f.phases
        f.write()
        return f

    def result(self, fixture):
        return analysis.analyze(fixture.trace, fixture.mapping, fixture.guest, fixture.family, fixture.order)

    def test_all_28_finite_family_mode_case_order_samples(self):
        count = 0
        for family, base in analysis.FAMILIES.items():
            for case in base.oracle.CASES:
                for mode in base.oracle.MODES:
                    for order in analysis.ORDERS:
                        with self.subTest(family=family, case=case, mode=mode, order=order):
                            f = self.fixture(family, order, case, mode)
                            r = self.result(f)
                            self.assertTrue(r['passed'], r)
                            self.assertFalse(r['candidate_execution_performed'])
                            self.assertFalse(r['coverage_claimed'])
                            self.assertEqual(r['unobserved_branches'], 'unknown')
                            self.assertFalse(r['runtime_identity_bound'])
                            count += 1
        self.assertEqual(count, 28)

    def test_ba_keeps_inputs_and_logical_roles_while_switching_physical_slot(self):
        f = self.fixture(order='ba')
        r = self.result(f)
        self.assertTrue(r['passed'], r)
        o = r['observations']
        self.assertEqual(o['target']['logical_role'], 'B')
        self.assertEqual(o['target']['physical_slot'], 'A')
        self.assertEqual(o['target']['event']['thread'], 'A')
        self.assertEqual(o['phases'][0]['operations'][0]['mask'], 1)
        self.assertEqual(o['phases'][0]['operations'][1]['mask'], 2)
        self.assertEqual(o['markers']['A'][0]['physical_slot'], 'B')
        self.assertEqual(o['observed_prefix']['events'], o['trace_events']['B'][:2])

    def test_prefix_preserves_nonmemory_events_and_counts_exact_occurrences(self):
        f = self.fixture()
        entry = dict(kind='ENTRY', thread='A', record_type='0x1000000000000000',
            ip=f.ips[0], caller_ip='0xffffffff81858000')
        repeated = copy.deepcopy(f.events['A'][0])
        f.events['A'][0:0] = [entry, repeated]
        f.write()
        r = self.result(f)
        self.assertTrue(r['passed'], r)
        o = r['observations']
        self.assertEqual(o['observed_prefix']['events'][0]['kind'], 'ENTRY')
        self.assertEqual(o['projection']['A'][1]['same_ip_occurrence'], 2)
        self.assertEqual(o['projection']['A'][1]['full_stack_occurrence'], 2)
        self.assertEqual(o['target']['access_index'], 3)
        self.assertEqual(o['target']['call_depth'], 2)
        self.assertEqual(len(o['observed_prefix']['events']), 4)
        self.assertEqual(sum(analysis.k03._WIDTH[e['kind']] for e in o['observed_prefix']['events']), o['target']['event']['word_index'])

    def test_ba_ab_outcome_mismatch_rejected_for_noncommuting_updates(self):
        f = self.fixture(order='ba', case='overlap-bits')
        f.phases[3]['values'][0] = 2  # legal A-B final, but contradicts this B-A sample
        f.write()
        r = self.result(f)
        self.assertFalse(r['passed'])
        self.assertFalse(r['checks']['schedule_outcome.final_matches_serial_order'])

    def test_mutex_boundary_order_cannot_be_relabelled(self):
        f = self.fixture('mutex', 'ba')
        ops, final = mutex_fixture.observed(pattern='A-B', tids=(201, 200))
        f.phases[2]['results'], f.phases[3]['final'] = ops, final
        f.write()
        self.assertFalse(self.result(f)['passed'])

    def test_contract_rejects_swapped_callback_role_or_tid(self):
        mutations = [('baseline_order', 'ab'), ('slot_to_logical_role', {'A': 'A', 'B': 'B'}),
            ('roles', {'A': 'test_thread1', 'B': 'test_thread2'}),
            ('slot_tids', {'A': 201, 'B': 200}), ('slot_tids', {'A': True, 'B': 201}),
            ('logical_role_to_callback', {'A': 'test_thread2', 'B': 'test_thread1'}),
            ('raw_trace_namespace', 'logical_role'), ('sampling_only', False),
            ('automatic_candidates_executed', True), ('automatic_candidates_executed', 1)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                f = self.fixture(order='ba')
                f.meta[key] = value
                f.write()
                self.assertFalse(self.result(f)['passed'])

    def test_raw_overflow_waits_words_and_stats_fail_closed(self):
        for damage in ('overflow', 'words', 'stats', 'wait'):
            with self.subTest(damage=damage):
                f = self.fixture()
                if damage == 'overflow':
                    f.meta['overflow'] = True
                if damage == 'wait':
                    f.events['A'].insert(0, dict(kind='WAIT', record_type='0x4000000000000000',
                        thread='A', flagidx=1, timed_out=False))
                f.write()
                if damage == 'words':
                    (f.trace / 'A.words').write_text('0000000000000000\n')
                if damage == 'stats':
                    f.meta['A']['events'] += 1
                    (f.trace / 'run.json').write_text(json.dumps(f.meta))
                self.assertFalse(self.result(f)['passed'])

    def test_source_marker_stack_and_unique_occurrence_fail_closed(self):
        for damage in ('lookup', 'line', 'duplicate', 'stack', 'missing_bus'):
            with self.subTest(damage=damage):
                f = self.fixture('mutex', 'ba')
                if damage == 'lookup': f.mapping[f.ips[2]]['lookup_ip'] = f.ips[2]
                if damage == 'line': f.mapping[f.ips[2]]['line'] = 1
                if damage == 'duplicate': f.events['A'].append(copy.deepcopy(f.events['A'][0]))
                if damage == 'stack': f.events['A'][0]['stack'][-1]['ip'] = f.ips[1]
                if damage == 'missing_bus': f.mapping[f.ips[1]]['file'] = '/fake.c'
                f.write()
                self.assertFalse(self.result(f)['passed'])

    def test_declared_inputs_initial_calls_and_cleanup_reused(self):
        for family in analysis.FAMILIES:
            for damage in ('input', 'initial', 'calls', 'cleanup', 'progress'):
                if family == 'rmw' and damage == 'progress': continue
                with self.subTest(family=family, damage=damage):
                    f = self.fixture(family)
                    if damage == 'input': f.phases[0]['operations'][0]['mask'] = 123
                    if damage == 'initial':
                        if family == 'rmw': f.phases[1]['values'][0] = 9
                        else: f.phases[1]['initial']['values'][0] = 9
                    if damage == 'calls': f.phases[2]['b_calls'] = 2
                    if damage == 'cleanup': f.phases[4]['actual_fds'].append(9)
                    if damage == 'progress': f.phases[4]['post_control_progress']['reset']['epoch'] = 1
                    f.write()
                    self.assertFalse(self.result(f)['passed'])

    def test_invalid_prefix_is_never_labelled_verified(self):
        f = self.fixture()
        f.guest['local_cleanup']['confirmed'] = False
        r = self.result(f)
        self.assertFalse(r['passed'])
        self.assertEqual(r['observations']['observed_prefix']['basis'], 'invalid-sample-not-candidate-evidence')

    def test_duplicate_json_keys_are_rejected(self):
        f = self.fixture()
        path = f.trace / 'A.events.jsonl'
        path.write_text(path.read_text().replace('"thread": "A"', '"thread": "B", "thread": "A"', 1))
        self.assertFalse(self.result(f)['passed'])

    def test_missing_phases_and_bad_parameters_return_failed_report(self):
        f = self.fixture()
        (f.trace / 'testcase.stdout.txt').write_text('')
        self.assertFalse(self.result(f)['passed'])
        self.assertFalse(analysis.analyze(f.trace, f.mapping, f.guest, [], 'ab')['passed'])

    def test_source_evidence_is_not_mutated(self):
        f = self.fixture('mutex', 'ba')
        before = copy.deepcopy((f.mapping, f.guest))
        hashes = {name: analysis.k06.digest(f.trace / name) for name in analysis.TRACE_FILES}
        self.assertTrue(self.result(f)['passed'])
        self.assertEqual(before, (f.mapping, f.guest))
        self.assertEqual(hashes, {name: analysis.k06.digest(f.trace / name) for name in analysis.TRACE_FILES})

    def test_cli_preserves_existing_reports_and_records_failed_evidence(self):
        f = self.fixture(order='ba')
        mapping, guest, output = (f.base / name for name in ('mapping.jsonl', 'guest.json', 'report.json'))
        mapping.write_text(''.join(json.dumps(row) + '\n' for row in f.mapping.values()))
        guest.write_text(json.dumps(f.guest))
        arguments = ['--trace', str(f.trace), '--mapping', str(mapping), '--guest', str(guest),
            '--family', 'rmw', '--order', 'ba', '--output', str(output)]
        self.assertEqual(analysis.main(arguments), 0)
        first = output.read_bytes()
        with self.assertRaises(FileExistsError):
            analysis.main(arguments)
        self.assertEqual(first, output.read_bytes())
        f.guest['local_cleanup']['confirmed'] = False
        guest.write_text(json.dumps(f.guest))
        arguments[-1] = str(f.base / 'failed.json')
        self.assertEqual(analysis.main(arguments), 1)
        self.assertFalse(json.loads(Path(arguments[-1]).read_text())['passed'])


if __name__ == '__main__':
    unittest.main()

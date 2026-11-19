"""Synthetic export fixtures for K06 rejection logic, not kernel execution.

Raw placeholder words exercise the accepted K03 length/format boundary; these
tests do not independently reimplement the upstream KCOV binary decoder.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('k06_analysis', Path(__file__).resolve().parents[2] / 'adapters/maccconc/k06_analysis.py')
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='k06-analysis-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.trace = self.base / 'trace'
        self.trace.mkdir()
        self.ips = ['0xffffffff81858010', '0xffffffff81858020', '0xffffffff81858030', '0xffffffff81858040']
        sources = [('drivers/base/regmap/regmap.c', 'regmap_read', 2870),
                   ('drivers/base/regmap/regmap-ram.c', 'regmap_ram_read', 33),
                   ('drivers/base/regmap/kconc-regmap.c', 'kconc_regmap_checkpoint', analysis.marker_source()['line']),
                   ('drivers/base/regmap/regmap-ram.c', 'regmap_ram_write', 23)]
        self.mapping = {ip: {'found': True, 'raw_ip': ip, 'lookup_ip': f'0x{int(ip,16)-1:016x}',
            'file': '/source/linux/' + filename, 'line': line, 'symbol': symbol,
            'exact_line': True, 'mapping_kind': 'exact_line'} for ip, (filename, symbol, line) in zip(self.ips, sources)}
        self.events = {}
        for role, offset in [('A', 0), ('B', 40)]:
            self.events[role] = [{'kind': 'MEMORY', 'record_type': '0x3000000000000000', 'thread': role,
                'ip': ip, 'address': f'0x{0xffff800000001000 + offset + index * 4:016x}',
                'size': 4, 'flags': 0x110 if index in (2, 3) else 0x100,
                'value': '0x0000000000000000', 'timestamp': '0x0000000000000001',
                'stack': [{'ip': '0xffffffff81858000', 'parent_idx': 0}, {'ip': ip, 'parent_idx': index + 1}]}
                for index, ip in enumerate(self.ips)]
        self.meta = {'schema_version': 1, 'roles': {'A': 'test_thread1', 'B': 'test_thread2'},
            'sequential_A_B': True, 'plan_loaded_from_file': False, 'spin_limit': 1000000,
            'child_status': 0, 'child_ok': True, 'a_done': True, 'b_done': True,
            'overflow': False, 'raw_words_well_formed': True, 'control_valid': True,
            'safe_to_continue': True, 'buffer_words': 1000}
        for key in ('gate0', 'a_completed_wake0', 'b_completed_wake1', 'reset'):
            self.meta[key] = {'called': True, 'rc': 0, 'errno': 0}
        self.phases = [
            {'phase': 'setup', 'passed': True, 'fault': 'none', 'injected': False, 'fd': 5,
             'reset_rc': 0, 'errno': 0, 'epoch': 1, 'initial_fds': [0, 1, 2, 3, 4]},
            {'phase': 'initial_state', 'passed': True, 'epoch': 1, 'regmap_ready': True,
             'context_state': 1, 'snapshot_valid': 1, 'values': [0, 0, 0, 0], 'active': 0,
             'completed_mask': 0, 'roles_zero': True, 'fd_set_matches': True},
            {'phase': 'operations', 'passed': True, 'a_calls': 1, 'b_calls': 1,
             'results': [{'role': role, 'reg': role, 'rc': 0, 'errno': 0, 'status': 0,
               'epoch': 1, 'before': 0, 'after': 1 << role, 'caller_tid': 200 + role,
               'kernel_pid': 200 + role, 'checkpoint': 1, 'preempt_count': 0, 'irqs_disabled': 0}
               for role in range(2)]},
            {'phase': 'property', 'passed': True, 'oracle': 'regmap-disjoint-registers',
             'natural_passed': True, 'injected': False, 'kernel_bug_claim': False,
             'status_rc': 0, 'epoch': 1, 'values': [1, 2, 0, 0], 'context_state': 1,
             'snapshot_valid': 1, 'active': 0, 'completed_mask': 3},
            {'phase': 'teardown', 'passed': True, 'ioctl_rc': 0, 'errno': 0, 'map_empty': True,
             'context_state': 0, 'snapshot_valid': 1, 'values': [0, 0, 0, 0], 'active': 0,
             'completed_mask': 0, 'roles_zero': True, 'resources_closed': True,
             'fd_set_restored': True, 'fd_snapshot_observed': True,
             'expected_fds': [0, 1, 2, 3, 4], 'actual_fds': [0, 1, 2, 3, 4]}]
        self.guest = {'schema_version': 1, 'kind': 'kconc.guest', 'outcome': 'completed',
            'exit_code': 0, 'remaining_pids': [], 'local_cleanup': {'confirmed': True, 'errors': []},
            'phase_errors': [], 'fault': 'none', 'phases': self.phases}
        self.phases[0].update(case_id='disjoint-bits', mode='split', **analysis.oracle.case_spec('disjoint-bits'))
        self.phases[1]['status_rc'] = 0
        for role, row in enumerate(self.phases[2]['results']):
            row.update(abi=2, reg=0, mask=1 << role, value=1 << role,
                       mode=0, values_valid=1, reserved=0,
                       before=role, after=1 if role == 0 else 3)
        self.phases[3].update(oracle='regmap-two-masked-updates', infrastructure_valid=True,
                             caller_misuse_example=True, allowed=True, values=[3, 0, 0, 0])
        self.sync_slots()
        self.write()

    def sync_slots(self):
        keys = ('reg', 'before', 'after', 'checkpoint', 'preempt_count', 'irqs_disabled', 'status', 'mode', 'values_valid')
        self.phases[3]['roles'] = [dict({key: row[key] for key in keys}, pid=row['kernel_pid'], started=1, completed=1)
                                  for row in self.phases[2]['results']]

    def controlled(self):
        binding = analysis.make_plan(self.trace, self.mapping, self.base / 'binding')
        (self.trace / 'plan.txt').write_bytes(Path(binding['plan_path']).read_bytes())
        self.meta.update(sequential_A_B=False, plan_loaded_from_file=True)
        signals = [{'kind': kind, 'record_type': rec, 'flagidx': bit, 'timed_out': False, 'thread': 'A'}
            for kind, rec, bit in [('WAKE', '0x5000000000000000', 0), ('WAIT', '0x4000000000000000', 1)]]
        marker_index = next(i for i, event in enumerate(self.events['A']) if event.get('ip') == self.ips[2])
        self.events['A'][marker_index:marker_index] = signals
        spec = self.phases[0]
        after_b = analysis.oracle.apply_update(spec['initial'], spec['operations'][1])
        if spec['mode'] == 'split':
            b = spec['operations'][1]
            self.phases[2]['results'][1].update(before=spec['initial'][b['reg']], after=after_b[b['reg']])
            final = list(after_b)
            a_reg = spec['operations'][0]['reg']
            final[a_reg] = self.phases[2]['results'][0]['after']
        else:
            final = analysis.oracle.apply_update(after_b, spec['operations'][0])
        allowed = analysis.oracle.evaluate(spec['initial'], spec['operations'], final)['allowed']
        self.phases[3].update(values=final, allowed=allowed, natural_passed=allowed)
        self.sync_slots()
        self.write(replay=True)

    def write(self, replay=False):
        target = next(row['stack'] for row in self.events['A'] if row.get('ip') == self.ips[2]) if replay else None
        for role, rows in self.events.items():
            offset = 0
            for row in rows:
                row['word_index'] = offset
                offset += analysis.k03._WIDTH[row['kind']]
            self.meta[role + '_words'] = offset
            self.meta[role] = analysis.k03._stats(rows, target if role == 'A' else None)
            (self.trace / (role + '.events.jsonl')).write_text(''.join(json.dumps(row) + '\n' for row in rows))
            (self.trace / (role + '.words')).write_text('0000000000000000\n' * offset)
        (self.trace / 'run.json').write_text(json.dumps(self.meta))
        (self.trace / 'testcase.stdout.txt').write_text(''.join('KCONC_PHASE ' + json.dumps(row) + '\n' for row in self.phases))

    def result(self, replay=False):
        return analysis.analyze(self.trace, self.mapping, self.guest, replay=replay)

    def test_baseline_checks_real_core_and_bus_mapping(self):
        result = self.result()
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['groups']['mapping'])
        self.assertTrue(result['groups']['initial'])
        self.assertTrue(result['groups']['cleanup'])

    def test_pre_access_zero_is_not_mistaken_for_failed_epoch_store(self):
        result = self.result()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['observations']['markers']['A'][0]['event']['value'], '0x0000000000000000')
        self.assertIn('pre-access', result['observations']['write_value_semantics'])

    def test_make_plan_binds_exact_observed_marker_and_artifacts(self):
        result = analysis.make_plan(self.trace, self.mapping, self.base / 'binding')
        saved = analysis.k03.read_plan(result['plan_path'])
        self.assertEqual(saved['stack'], self.events['A'][2]['stack'])
        self.assertEqual(saved['sha256'], result['plan_sha256'])
        self.assertFalse(result['runtime_identity_bound'])
        self.assertIn('A.words', result['trace_sha256'])

    def test_make_plan_refuses_existing_output(self):
        out = self.base / 'existing'
        out.mkdir()
        (out / 'keep').write_text('original')
        with self.assertRaises(FileExistsError):
            analysis.make_plan(self.trace, self.mapping, out)
        self.assertEqual((out / 'keep').read_text(), 'original')

    def test_marker_replay_checks_real_control_and_saved_target(self):
        self.controlled()
        result = self.result(replay=True)
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['property_violation'])
        self.assertFalse(result['property']['allowed'])
        self.events['A'][3]['timed_out'] = True
        self.write(replay=True)
        self.assertFalse(self.result(replay=True)['passed'])

    def test_cannot_bind_a_store_in_other_marker_source_line(self):
        self.mapping[self.ips[2]]['line'] -= 1
        self.assertFalse(self.result()['passed'])
        with self.assertRaises(ValueError):
            analysis.make_plan(self.trace, self.mapping, self.base / 'bad-plan')
        self.assertFalse((self.base / 'bad-plan').exists())

    def test_marker_requires_write_access_of_four_bytes(self):
        for key, value in [('size', 8), ('flags', 0x100), ('flags', 0x130)]:
            original = self.events['A'][2][key]
            self.events['A'][2][key] = value
            self.write()
            self.assertFalse(self.result()['passed'], (key, value))
            self.events['A'][2][key] = original

    def test_duplicate_marker_does_not_pick_first(self):
        self.events['A'].append(copy.deepcopy(self.events['A'][2]))
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_source_map_return_address_binding_is_checked(self):
        self.mapping[self.ips[2]]['lookup_ip'] = self.ips[2]
        self.assertFalse(self.result()['passed'])

    def test_function_only_marker_is_insufficient(self):
        self.mapping[self.ips[2]].update(line=0, exact_line=False, mapping_kind='function_only')
        self.assertFalse(self.result()['passed'])

    def test_missing_real_regmap_bus_is_rejected(self):
        self.mapping[self.ips[1]]['file'] = '/source/linux/kernel/k05/fake.c'
        self.assertFalse(self.result()['passed'])

    def test_initial_state_dirtiness_not_hidden_by_passed(self):
        self.phases[1]['values'][2] = 9
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_kernel_operation_must_run_in_recorded_caller_thread(self):
        self.phases[2]['results'][1]['kernel_pid'] = 999
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_two_roles_cannot_claim_same_thread(self):
        self.phases[2]['results'][1].update(kernel_pid=200, caller_tid=200)
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_epoch_and_atomic_context_are_rejected(self):
        for key, value in [('checkpoint', 0), ('epoch', 2), ('preempt_count', 1), ('irqs_disabled', 1)]:
            original = self.phases[2]['results'][0][key]
            self.phases[2]['results'][0][key] = value
            self.write()
            self.assertFalse(self.result()['passed'], (key, value))
            self.phases[2]['results'][0][key] = original

    def test_property_values_and_idle_snapshot_are_checked(self):
        self.phases[3]['completed_mask'] = 1
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_cleanup_requires_actual_empty_state_and_fd_equality(self):
        self.phases[4]['actual_fds'].append(9)
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_supervisor_must_match_collected_phase_records(self):
        self.guest['phases'] = copy.deepcopy(self.phases)
        self.guest['phases'][1]['epoch'] = 3
        self.assertFalse(self.result()['passed'])

    def test_guest_process_cleanup_must_be_confirmed(self):
        self.guest['local_cleanup']['confirmed'] = False
        self.assertFalse(self.result()['passed'])

    def test_boolean_integer_aliases_are_rejected(self):
        self.phases[2]['results'][0]['status'] = False
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_raw_truncation_overflow_and_stats_spoofing_rejected(self):
        (self.trace / 'A.words').write_text('0000000000000000\n')
        self.assertFalse(self.result()['passed'])
        self.write()
        self.meta['overflow'] = True
        self.write()
        self.assertFalse(self.result()['passed'])
        self.meta['overflow'] = False
        self.write()
        self.meta['A']['waits'] = False
        (self.trace / 'run.json').write_text(json.dumps(self.meta))
        self.assertFalse(self.result()['passed'])

    def test_missing_phase_and_duplicate_phase_keys_are_rejected(self):
        self.phases.pop()
        self.write()
        self.assertFalse(self.result()['passed'])
        path = self.trace / 'testcase.stdout.txt'
        path.write_text('KCONC_PHASE {"phase":"setup","phase":"setup","passed":true}\n')
        self.assertFalse(self.result()['passed'])

    def test_jsonl_mapping_loader_rejects_duplicate_ips(self):
        path = self.base / 'mapping.jsonl'
        rows = list(self.mapping.values())
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows + rows[:1]))
        self.assertFalse(analysis.analyze(self.trace, path, self.guest)['passed'])

    def test_jsonl_mapping_loader_accepts_real_helper_shape(self):
        path = self.base / 'mapping.jsonl'
        path.write_text(''.join(json.dumps(row) + '\n' for row in self.mapping.values()))
        self.assertTrue(analysis.analyze(self.trace, path, self.guest)['passed'])

    def test_native_verdict_cannot_hide_lost_update(self):
        self.controlled()
        self.phases[3].update(allowed=True, natural_passed=True)
        self.write(replay=True)
        self.assertFalse(self.result(replay=True)['passed'])

    def test_invalid_control_does_not_count_property_detection(self):
        self.controlled()
        self.events['A'][3]['timed_out'] = True
        self.write(replay=True)
        result = self.result(replay=True)
        self.assertFalse(result['control_valid'])
        self.assertFalse(result['property_evaluated'])
        self.assertFalse(result['property_violation'])

    def test_case_and_mode_bound_in_plan(self):
        binding = analysis.make_plan(self.trace, self.mapping, self.base / 'binding')
        self.assertEqual(binding['case_id'], 'disjoint-bits')
        self.assertEqual(binding['mode'], 'split')
        self.assertEqual(len(binding['oracle_sha256']), 64)

    def test_case_cannot_be_relabelled_or_masks_changed(self):
        self.phases[0]['operations'][0]['mask'] = 3
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_missing_operation_observation_returns_failed_result(self):
        self.phases[2]['results'].pop()
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_fixed_noop_may_have_no_ram_write(self):
        self.phases[0].update(case_id='zero-mask', mode='update-bits', **analysis.oracle.case_spec('zero-mask'))
        self.mapping[self.ips[0]]['symbol'] = 'regmap_update_bits_base'
        for role, name in enumerate(('A', 'B')):
            self.events[name] = [self.events[name][2], self.events[name][0], self.events[name][1]] + ([] if role == 0 else [self.events[name][3]])
            self.phases[2]['results'][role].update(mode=1, values_valid=0, before=0, after=0,
                mask=0 if role == 0 else 2, value=0 if role == 0 else 2)
        self.phases[3]['values'] = [2, 0, 0, 0]
        self.sync_slots()
        self.write()
        result = self.result()
        self.assertTrue(result['passed'], result)
        self.assertFalse(result['property_violation'])

    def test_fixed_marker_must_precede_real_regmap_accesses(self):
        self.phases[0]['mode'] = 'update-bits'
        self.mapping[self.ips[0]]['symbol'] = 'regmap_update_bits_base'
        for row in self.phases[2]['results']:
            row.update(mode=1, values_valid=0, before=0, after=0)
        self.sync_slots()
        self.write()
        self.assertFalse(self.result()['passed'])

    def test_fixed_marker_replay_checks_repaired_order(self):
        self.phases[0]['mode'] = 'update-bits'
        self.mapping[self.ips[0]]['symbol'] = 'regmap_update_bits_base'
        for name in ('A', 'B'):
            self.events[name] = [self.events[name][2], self.events[name][0], self.events[name][1], self.events[name][3]]
        for row in self.phases[2]['results']:
            row.update(mode=1, values_valid=0, before=0, after=0)
        self.sync_slots()
        self.write()
        self.controlled()
        result = self.result(replay=True)
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['property']['allowed'])
        self.assertEqual(result['property']['observed'], [3, 0, 0, 0])

    def test_overlap_controlled_final_writer_is_allowed(self):
        self.phases[0].update(case_id='overlap-bits', **analysis.oracle.case_spec('overlap-bits'))
        for role, row in enumerate(self.phases[2]['results']):
            row.update(mask=3, value=role + 1, after=role + 1)
        self.phases[3]['values'] = [2, 0, 0, 0]
        self.sync_slots()
        self.write()
        self.controlled()
        result = self.result(replay=True)
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['property']['allowed'])
        self.assertEqual(result['property']['matching_orders'], ['B-A'])


if __name__ == '__main__':
    unittest.main()

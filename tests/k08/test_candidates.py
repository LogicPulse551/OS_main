"""Synthetic schema/identity regressions, not substitutes for kernel evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from kconc import candidates as c


def fixture(family='rmw', case='disjoint-bits', mode='split', order='ab'):
    entry = c.get_input(c.load_catalog(), family, case, mode)
    first = order[0].upper()
    ip, caller, other = ('0xffffffff81000010', '0xffffffff81000020', '0xffffffff81000030')
    stack = [dict(ip=caller, parent_idx=0), dict(ip=ip, parent_idx=1)]
    prefix = [dict(thread='A', kind='ENTRY', word_index=0, record_type='0x0000000000000000', ip=caller, caller_ip=caller),
              dict(thread='A', kind='MEMORY', word_index=2, record_type='0x3000000000000000', ip=other,
                   address='0xffff888100000004', size=4, flags=256, value='0x0000000000000000',
                   timestamp='0x0000000000000001', stack=[dict(ip=caller, parent_idx=0), dict(ip=other, parent_idx=0)])]
    event = dict(thread='A', kind='MEMORY', word_index=7, record_type='0x3000000000000000', ip=ip,
                 address='0xffff888100000000', size=4, flags=272, value='0x0000000000000000',
                 timestamp='0x0000000000000002', stack=stack)
    marker_source = dict(file='drivers/base/regmap/kconc-regmap.c', symbol='kconc_regmap_checkpoint',
                         line=98 if family == 'rmw' else 124, source_sha256='a' * 64)
    target = dict(event=event, source=dict(marker_source, exact_line=True), physical_slot='A', logical_role=first,
                  access_index=1, same_ip_occurrence=1, full_stack_occurrence=1, call_depth=2)
    initial = dict(phase='initial_state', passed=True, values=entry['initial'], epoch=1, active=0,
                   completed_mask=0, snapshot_valid=1, context_state=1, roles_zero=True)
    initial_phase = initial
    if family == 'mutex':
        initial = dict(abi=3, values=entry['initial'], epoch=1, active=0, completed_mask=0, state=1)
        initial_phase = dict(phase='initial_state', passed=True, initial=initial)
    source = dict(trace_path='/external/sample', analysis_sha256='b' * 64,
                  trace_sha256={name: 'c' * 64 for name in c.TRACE_FILES})
    obs = dict(family=family, case_id=case, mode=mode, order=order,
               phases=[dict(case_id=case, mode=mode, initial=entry['initial'], operations=entry['operations']),
                       initial_phase, {}, {}, {}], slot_to_role=dict(zip(('A', 'B'), order.upper())),
               markers={first: [target]}, marker_source=marker_source,
               observed_prefix=dict(physical_slot='A', logical_role=first, events=prefix,
                                    completed_logical_roles=[], observed_baseline_order=order,
                                    basis='verified-sequential-baseline'), trace_events={first: prefix + [event]})
    analysis = dict(passed=True, checks={'synthetic': True}, errors=[], observations=obs,
                    artifacts=dict(source['trace_sha256']))
    return [entry, dict(kernel='d' * 64, executor='e' * 64), initial, analysis, source]


class CandidateTests(unittest.TestCase):
    def test_catalog_matches_all_accepted_inputs(self):
        catalog = c.load_catalog()
        self.assertEqual(len(catalog['inputs']), 14)
        self.assertEqual(sum(x['family'] == 'rmw' for x in catalog['inputs']), 10)
        self.assertEqual(sum(x['family'] == 'mutex' for x in catalog['inputs']), 4)

    def test_all_28_directions_preserve_logical_operations(self):
        for entry in c.load_catalog()['inputs']:
            for order in ('ab', 'ba'):
                with self.subTest(input=entry['input_id'], order=order):
                    row = c.make_candidate(*fixture(entry['family'], entry['case_id'], entry['mode'], order))
                    identity = row['identity']
                    self.assertEqual(identity['input']['operations'], entry['operations'])
                    self.assertEqual(identity['target']['logical_role'], order[0].upper())
                    self.assertEqual(identity['schedule']['pattern'], 'A-B-A' if order == 'ab' else 'B-A-B')
                    self.assertEqual(identity['logical_roles']['A']['role'], 0)
                    self.assertEqual(identity['logical_roles']['B']['callback'], 'test_thread2')
                    self.assertFalse(identity['support']['coverage_claim'])
                    self.assertEqual(identity['support']['candidate_execution'], 'not-executed')

    def test_analysis_to_candidate_contract_for_all_28_samples(self):
        spec = importlib.util.spec_from_file_location('candidate_analysis_fixtures', Path(__file__).with_name('test_analysis.py'))
        fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
        helper = fixtures.AnalysisTests(); self.addCleanup(helper.doCleanups)
        for entry in c.load_catalog()['inputs']:
            for order in ('ab', 'ba'):
                with self.subTest(input=entry['input_id'], order=order):
                    f = helper.fixture(entry['family'], order, entry['case_id'], entry['mode'])
                    report = helper.result(f)
                    self.assertTrue(report['passed'], report)
                    source = dict(trace_path=str(f.trace), analysis_sha256=c.fingerprint(report),
                                  trace_sha256={name: report['artifacts'][name] for name in c.TRACE_FILES})
                    row = c.make_candidate(entry, {'synthetic_build': 'f' * 64}, c.observed_initial_state(report), report, source)
                    self.assertEqual(row['identity']['observed_prefix'], report['observations']['observed_prefix'])
                    self.assertEqual(row['identity']['target'], report['observations']['target'])
                    self.assertEqual(row['identity']['baseline_order'], order)

    def test_actual_initial_shapes_are_retained(self):
        for family, case, mode in [('rmw', 'disjoint-bits', 'split'), ('mutex', 'shared-register', 'shared')]:
            args = fixture(family, case, mode)
            self.assertEqual(c.observed_initial_state(args[3]), args[2])
            row = c.make_candidate(*args)
            self.assertEqual(row['identity']['initial_state'], args[2])
            self.assertEqual('abi' in row['identity']['initial_state'], family == 'mutex')

    def test_only_exact_identity_merges_and_every_source_is_retained(self):
        a = c.make_candidate(*fixture())
        b = copy.deepcopy(a); b['sources'][0]['trace_path'] = '/copied/evidence'
        rows = c.merge_candidates([a, b, a])
        self.assertEqual(len(rows), 1)
        self.assertEqual([s['trace_path'] for s in rows[0]['sources']], ['/external/sample', '/copied/evidence', '/external/sample'])
        self.assertEqual(len(a['sources']), 1)

    def test_full_raw_prefix_differences_never_merge(self):
        a = c.make_candidate(*fixture())
        for field, value in [('timestamp', '0x0000000000000009'), ('value', '0x0000000000000007'),
                             ('address', '0xffff888100000008'), ('flags', 257)]:
            args = fixture(); args[3]['observations']['observed_prefix']['events'][1][field] = value
            b = c.make_candidate(*args)
            with self.subTest(field=field):
                self.assertEqual(len(c.merge_candidates([a, b])), 2)

    def test_different_build_initial_input_and_direction_never_merge(self):
        a = c.make_candidate(*fixture())
        build = fixture(); build[1]['executor'] = 'f' * 64
        initial = fixture(); initial[2]['epoch'] = 2
        variants = [build, initial, fixture(mode='update-bits'), fixture(order='ba'), fixture(case='zero-mask')]
        for args in variants:
            self.assertEqual(len(c.merge_candidates([a, c.make_candidate(*args)])), 2)

    def test_target_address_stack_and_timestamp_never_merge(self):
        a = c.make_candidate(*fixture())
        for field, value in [('address', '0xffff888100000008'), ('timestamp', '0x0000000000000022'),
                             ('value', '0x0000000000000011')]:
            args = fixture(); args[3]['observations']['markers']['A'][0]['event'][field] = value
            self.assertEqual(len(c.merge_candidates([a, c.make_candidate(*args)])), 2)
        args = fixture(); args[3]['observations']['markers']['A'][0]['event']['stack'][0]['parent_idx'] = 4
        self.assertEqual(len(c.merge_candidates([a, c.make_candidate(*args)])), 2)

    def test_occurrence_metadata_is_recomputed_from_complete_prefix(self):
        args = fixture(); obs = args[3]['observations']; target = obs['markers']['A'][0]
        previous = obs['observed_prefix']['events'][1]
        previous['ip'] = target['event']['ip']; previous['stack'] = copy.deepcopy(target['event']['stack'])
        with self.assertRaises(ValueError):
            c.make_candidate(*args)
        target['same_ip_occurrence'] = target['full_stack_occurrence'] = 2
        row = c.make_candidate(*args)
        self.assertEqual(row['identity']['target']['full_stack_occurrence'], 2)

    def test_candidate_does_not_alias_mutable_evidence(self):
        args = fixture(); row = c.make_candidate(*args)
        args[3]['observations']['markers']['A'][0]['event']['value'] = '0x0000000000000099'
        self.assertEqual(row['identity']['target']['event']['value'], '0x0000000000000000')

    def test_refuses_invalid_or_unchecked_analysis(self):
        for field, value in [('passed', False), ('passed', 1), ('checks', {}), ('checks', {'x': 1}), ('errors', ['bad'])]:
            args = fixture(); args[3][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                c.make_candidate(*args)

    def test_refuses_mismatched_input_and_role_identity(self):
        for mutate in [lambda o: o.update(case_id='zero-mask'), lambda o: o.update(slot_to_role={'A': 'B', 'B': 'A'}),
                       lambda o: o['phases'][0]['operations'][0].update(role=1)]:
            args = fixture(); mutate(args[3]['observations'])
            with self.assertRaises(ValueError):
                c.make_candidate(*args)

    def test_refuses_unobserved_or_transplanted_prefix(self):
        for mutate in [lambda o: o['observed_prefix'].update(basis='another-execution'),
                       lambda o: o['observed_prefix'].update(completed_logical_roles=['B']),
                       lambda o: o['observed_prefix'].update(observed_baseline_order='ba'),
                       lambda o: o.update(trace_events={'A': []}),
                       lambda o: o['observed_prefix'].update(events=[]),
                       lambda o: o['observed_prefix']['events'][0].update(kind='WAIT')]:
            args = fixture(); mutate(args[3]['observations'])
            with self.assertRaises(ValueError):
                c.make_candidate(*args)

    def test_refuses_non_marker_access_even_with_passing_report(self):
        for field, value in [('symbol', 'arbitrary_spinlocked_access'), ('file', 'kernel/locking/mutex.c'),
                             ('line', 99), ('exact_line', False)]:
            args = fixture(); args[3]['observations']['markers']['A'][0]['source'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.make_candidate(*args)

    def test_refuses_wrong_target_occurrence_depth_flags_or_slot(self):
        for field, value in [('access_index', 2), ('same_ip_occurrence', 0), ('full_stack_occurrence', True),
                             ('call_depth', 3), ('physical_slot', 'B'), ('logical_role', 'B')]:
            args = fixture(); args[3]['observations']['markers']['A'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.make_candidate(*args)
        for field, value in [('flags', 256), ('flags', 304), ('size', True), ('word_index', 8), ('thread', 'B')]:
            args = fixture(); args[3]['observations']['markers']['A'][0]['event'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.make_candidate(*args)

    def test_refuses_initial_snapshot_and_provenance_mismatch(self):
        args = fixture(); args[2] = copy.deepcopy(args[2]); args[2]['epoch'] += 1
        with self.assertRaises(ValueError): c.make_candidate(*args)
        args = fixture(); args[4]['trace_sha256']['A.words'] = 'f' * 64
        with self.assertRaises(ValueError): c.make_candidate(*args)
        args = fixture(); del args[4]['trace_sha256']['run.json']
        with self.assertRaises(ValueError): c.make_candidate(*args)

    def test_tampered_serialized_candidate_rejected(self):
        a = c.make_candidate(*fixture())
        a['identity']['build_identity']['kernel'] = 'f' * 64
        with self.assertRaises(ValueError): c.merge_candidates([a])

    def test_cannot_claim_execution_or_coverage_by_rehashing(self):
        for field, value in [('coverage_claim', True), ('candidate_execution', 'hit'), ('unobserved_branches', 'covered')]:
            a = c.make_candidate(*fixture()); a['identity']['support'][field] = value
            a['candidate_id'] = c.fingerprint(a['identity'])
            with self.assertRaises(ValueError): c.merge_candidates([a])

    def test_catalog_rejects_omissions_duplicates_and_relabelled_operations(self):
        a = c.load_catalog(); a['inputs'].pop()
        with self.assertRaises(ValueError): c.validate_catalog(a)
        a = c.load_catalog(); a['inputs'][-1] = copy.deepcopy(a['inputs'][0])
        with self.assertRaises(ValueError): c.validate_catalog(a)
        a = c.load_catalog(); a['inputs'][0]['operations'][0]['role'] = False
        with self.assertRaises(ValueError): c.validate_catalog(a)
        a = c.load_catalog(); a['logical_roles']['A']['callback'] = 'test_thread2'
        with self.assertRaises(ValueError): c.validate_catalog(a)

    def test_catalog_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'bad.json'; p.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError): c.load_catalog(p)

    def test_identity_rejects_float_nan_and_nonstring_keys(self):
        for item in [float('nan'), 1.0, {1: 'x'}]:
            with self.assertRaises(ValueError): c.fingerprint(item)

    def test_export_lists_missing_samples_without_coverage_claim(self):
        a = c.make_candidate(*fixture())
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'pool.json'
            pool = c.export_candidates(p, [a, a])
            self.assertEqual(pool['summary']['expected_baselines'], 28)
            self.assertEqual(pool['summary']['observed_baselines'], 1)
            self.assertEqual(len(pool['summary']['unobserved_baselines']), 27)
            self.assertEqual(pool['summary']['unique_candidates'], 1)
            self.assertEqual(pool['summary']['source_records'], 2)
            self.assertEqual(pool['summary']['executed_candidates'], 0)
            self.assertIsNone(pool['summary']['interleavings_covered'])
            self.assertFalse(pool['summary']['complete_search'])
            self.assertEqual(json.loads(p.read_text(encoding='utf-8')), pool)
            with self.assertRaises(FileExistsError): c.export_candidates(p, [a])

    def test_export_full_matrix_is_sampling_only(self):
        rows = [c.make_candidate(*fixture(e['family'], e['case_id'], e['mode'], order))
                for e in c.load_catalog()['inputs'] for order in ('ab', 'ba')]
        with tempfile.TemporaryDirectory() as folder:
            pool = c.export_candidates(Path(folder) / 'matrix.json', rows)
        self.assertEqual(pool['summary']['observed_baselines'], 28)
        self.assertEqual(pool['summary']['unobserved_baselines'], [])
        self.assertEqual(pool['summary']['unobserved_branches'], 'unknown')
        self.assertEqual(pool['summary']['executed_candidates'], 0)

    def test_evidence_cannot_be_exported_into_code_repository(self):
        with self.assertRaises(ValueError):
            c.export_candidates(c.REPO / 'tests/k08/forbidden-evidence.json', [])


if __name__ == '__main__':
    unittest.main()

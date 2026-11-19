"""Synthetic orchestration failures; actual QEMU evidence is kept outside repo."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from kconc import candidates as c, witness_reduction as policy
from kconc.reduction import ReductionRuntime, observation
from kconc.lifecycle import persist, read, guard_legacy
from kconc.cli import OperationError
from kconc.manifest import normalize_manifest, ManifestError


class Fake(ReductionRuntime):
    def __init__(self, root, family='rmw', order='ab', budget=4):
        self.out = root; self.statepath = root/'state.json'; persist(self.statepath, dict(state='ready'))
        self.task = dict(operation='kernel.reduce', scenario=dict(max_trials=budget, replay_repetitions=2))
        self.entry = c.get_input(c.load_catalog(), family, 'disjoint-bits' if family=='rmw' else 'same-bit',
            'split' if family=='rmw' else 'per-role')
        self.candidate = dict(candidate_id='original', identity=dict(input=self.entry, baseline_order=order))
        self.prop = policy.RMW_PROPERTY if family=='rmw' else policy.MUTEX_PROPERTY
        self.fail_label = None; self.diverge_label = None; self.dirty_label = None; self.miss_label = None
        self.calls = []

    def reference(self):return dict(candidate=self.candidate, _directory='/immutable/original'), dict(id='original')

    def execute_candidate(self, candidate, directory):
        self.calls.append(directory.name)
        persist(directory/'execution-launch.json', dict(guest_started=True))
        if directory.name == self.fail_label:raise RuntimeError('synthetic interruption')
        changed = candidate['candidate_id'] != 'original'
        violation = not changed or self.candidate['identity']['baseline_order'] == 'ab'
        hit = directory.name != self.miss_label; dirty = directory.name == self.dirty_label
        a = dict(control_valid=True, schedule_valid=True, candidate_hit=hit,
            property_evaluated=hit, property_violation=violation and hit,
            observed_property=dict(error_type=self.prop if violation else None))
        signature = dict(id=candidate['candidate_id'] if directory.name != self.diverge_label else 'different')
        persist(directory/'analysis.json', a); persist(directory/'signature.json', signature)
        if dirty:persist(self.statepath, dict(state='dirty'))
        return dict(analysis=a, signature=signature, actual_execution=True, cleanup_verified=not dirty, recovery_required=dirty)

    def execute_sample(self, entry, order, directory):
        self.calls.append(directory.name)
        persist(directory/'execution-launch.json', dict(guest_started=True))
        if directory.name == self.fail_label:raise RuntimeError('synthetic interruption')
        a = dict(control_valid=True, groups=dict(schedule_outcome=True), property_evaluated=True,
                 property_violation=False, property=dict(error_type=None))
        persist(directory/'analysis.json', a)
        return dict(passed=True, analysis=a, actual_execution=True, cleanup_verified=True, recovery_required=False,
                    candidate=dict(candidate_id='changed', identity=dict(input=entry)))


class Workflow(unittest.TestCase):
    def fixture(self, **kw):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        return Fake(Path(folder.name), **kw)

    def test_ab_keeps_reduced_witness_and_rejected_serial_trial(self):
        r = self.fixture(); result = r.execute(); ledger = read(r.out/'ledger.json')
        self.assertEqual(result['summary'], dict(actual_candidates=5, serial_trials=2, execution_slots=7,
            accepted=1, rejected=1, failed=0, unattempted=0, launch_unknown=0, completed_executions=7))
        self.assertEqual(ledger['retained_witness']['cost_after'], 1)
        self.assertEqual(ledger['trials'][1]['decision']['reason'], 'violation-not-preserved')
        self.assertEqual(ledger['original_input']['operations'][0]['mask'], 1)

    def test_ba_retains_original_when_bit_edit_loses_violation(self):
        r = self.fixture(order='ba'); result = r.execute(); ledger = read(r.out/'ledger.json')
        self.assertEqual(result['reduction_status'], 'not-reduced')
        self.assertEqual(result['summary']['actual_candidates'], 3)
        self.assertEqual(result['summary']['rejected'], 2)
        self.assertEqual(ledger['retained_witness']['kind'], 'original')

    def test_zero_budget_launches_nothing_and_retains_unattempted(self):
        r = self.fixture(budget=0); result = r.execute()
        self.assertEqual(r.calls, [])
        self.assertEqual(result['summary']['unattempted'], 2)

    def test_one_trial_budget_preserves_other_slot(self):
        r = self.fixture(budget=1); result = r.execute()
        self.assertEqual(result['summary']['accepted'], 1)
        self.assertEqual(result['summary']['unattempted'], 1)

    def test_original_path_difference_stops_before_edits(self):
        r = self.fixture(); r.diverge_label = 'original-01'
        with self.assertRaises(OperationError):r.execute()
        self.assertEqual(r.calls, ['original-01'])
        self.assertEqual(read(r.out/'ledger.json')['summary']['unattempted'], 2)

    def test_original_miss_is_not_a_valid_seed(self):
        r = self.fixture(); r.miss_label = 'original-02'
        with self.assertRaises(OperationError):r.execute()
        self.assertEqual(len(r.calls), 2)

    def test_failed_sample_keeps_exception_and_unattempted_slot(self):
        r = self.fixture(); r.fail_label = 'trial-01-sample'
        with self.assertRaises(RuntimeError):r.execute()
        ledger = read(r.out/'ledger.json')
        self.assertEqual(ledger['trials'][0]['status'], 'failed-execution')
        self.assertEqual(ledger['trials'][1]['status'], 'unattempted-interruption')
        self.assertTrue((r.out/'trial-01-sample/exception.json').is_file())
        self.assertEqual(ledger['summary']['serial_trials'], 1)
        self.assertEqual(ledger['summary']['completed_executions'], 2)

    def test_invalid_variant_is_failure_not_effective_rejection(self):
        r = self.fixture(); r.miss_label = 'trial-01-candidate'
        with self.assertRaises(OperationError):r.execute()
        summary = read(r.out/'ledger.json')['summary']
        self.assertEqual(summary['rejected'], 0)
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['actual_candidates'], 3)

    def test_reduced_confirmation_difference_rejects_without_retry(self):
        r = self.fixture(); r.diverge_label = 'trial-01-confirm-01'
        result = r.execute(); ledger = read(r.out/'ledger.json')
        self.assertEqual(result['summary']['accepted'], 0)
        self.assertEqual(ledger['trials'][0]['status'], 'rejected-confirmation')
        self.assertEqual(len(ledger['trials'][0]['confirmations']), 2)
        self.assertEqual(ledger['retained_witness']['kind'], 'original')
        self.assertEqual(result['summary']['failed'], 0)
        self.assertEqual(result['summary']['rejected'], 2)
        self.assertTrue(result['passed'])

    def test_confirmation_exception_revokes_provisional_acceptance(self):
        r = self.fixture(); r.fail_label = 'trial-01-confirm-02'
        with self.assertRaises(RuntimeError):r.execute()
        trial = read(r.out/'ledger.json')['trials'][0]
        self.assertEqual(trial['status'], 'failed-execution')
        self.assertIs(trial['decision']['accepted'], False)
        self.assertEqual(len(trial['confirmations']), 1)

    def assert_failed_confirmation(self, runtime, confirmation_number, recovery_required):
        with self.assertRaises(OperationError) as raised:runtime.execute()
        self.assertEqual(raised.exception.code, 'reduction_confirmation_invalid')
        result = read(runtime.out/'reduction-result.json'); ledger = read(runtime.out/'ledger.json')
        self.assertFalse(result['passed'])
        self.assertEqual(result['reduction_status'], 'incomplete')
        self.assertIs(result['recovery_required'], recovery_required)
        self.assertEqual(result['summary'], dict(actual_candidates=3+confirmation_number, serial_trials=1,
            execution_slots=4+confirmation_number, completed_executions=4+confirmation_number,
            accepted=0, rejected=0, failed=1, unattempted=1, launch_unknown=0))
        trial = ledger['trials'][0]
        self.assertEqual(trial['status'], 'failed-confirmation')
        self.assertFalse(trial['decision']['accepted'])
        self.assertEqual(trial['decision']['reason'], 'confirmation-execution-invalid')
        self.assertEqual(len(trial['confirmations']), confirmation_number)
        self.assertEqual(ledger['trials'][1]['status'], 'unattempted-interruption')
        self.assertEqual(ledger['retained_witness'], dict(kind='original', bundle='/immutable/original'))
        label = 'trial-01-confirm-%02d' % confirmation_number
        self.assertEqual(runtime.calls[-1], label)
        self.assertEqual(len(runtime.calls), 4+confirmation_number)
        # The unsuccessful confirmation remains an actual attempt in the ledger.
        self.assertEqual(ledger['executions'][-1]['label'], label)
        self.assertIs(ledger['executions'][-1]['guest_started'], True)
        self.assertEqual(read(runtime.out/label/'reduction-observation.json'), trial['confirmations'][-1]['observation'])
        return trial['confirmations'][-1]['observation']

    def test_confirmation_miss_is_failed_and_preserves_attempt_denominator(self):
        for number in (1, 2):
            with self.subTest(confirmation=number):
                r = self.fixture(); r.miss_label = 'trial-01-confirm-%02d' % number
                obs = self.assert_failed_confirmation(r, number, recovery_required=False)
                self.assertFalse(obs['candidate_hit'])
                self.assertFalse(obs['property_evaluated'])
                self.assertTrue(obs['cleanup_verified'])

    def test_dirty_confirmation_is_failed_and_requires_recovery(self):
        for number in (1, 2):
            with self.subTest(confirmation=number):
                r = self.fixture(); r.dirty_label = 'trial-01-confirm-%02d' % number
                obs = self.assert_failed_confirmation(r, number, recovery_required=True)
                self.assertTrue(obs['candidate_hit'])
                self.assertFalse(obs['cleanup_verified'])
                self.assertEqual(read(r.statepath)['state'], 'dirty')

    def test_observation_cannot_derive_violation_from_missing_evaluation(self):
        r = self.fixture(); path = r.out/'one'; path.mkdir()
        data = r.execute_candidate(r.candidate, path); data['analysis']['property_evaluated'] = False
        self.assertFalse(observation(data, r.prop)['property_violation'])

    def test_dirty_reduction_blocks_legacy_bypass(self):
        r = self.fixture(); (r.out/'run').mkdir(); persist(r.out/'run/k13-state.json', dict(state='dirty'))
        with self.assertRaises(OperationError):guard_legacy(dict(lab_dir=str(r.out)), 'env.check')


class Manifest(unittest.TestCase):
    def task(self):
        return dict(schema_version=1, operation='kernel.reduce', runtime=dict(lab_dir='/tmp/os-concurrency-k13-rmw',
            ssh_port=2253, build_lab='/tmp/build', kernel_build='/tmp/build/kernel',
            scenario_guest_build='/home/lab/k03/build-01', sample_guest_build='/home/lab/k08/build-01',
            search_guest_build='/home/lab/k10-control/build-01'),
            inputs=dict(bundle='/tmp/original', source_mapper='/tmp/mapper'),
            scenario=dict(max_trials=4, replay_repetitions=2))

    def test_valid_zero_and_positive(self):
        for n in (0, 4, 64):
            t = self.task(); t['scenario']['max_trials'] = n
            self.assertEqual(normalize_manifest(t, REPO)['scenario'], t['scenario'])

    def test_bad_budget_and_extra_fields_rejected(self):
        for key, values in [('max_trials', [-1, True, 65, 1.5]), ('replay_repetitions', [0, True, 6])]:
            for v in values:
                t = self.task(); t['scenario'][key] = v
                with self.assertRaises(ManifestError):normalize_manifest(t, REPO)
        for key in self.task()['scenario']:
            t = self.task(); del t['scenario'][key]
            with self.assertRaises(ManifestError):normalize_manifest(t, REPO)
        t = self.task(); t['scenario']['pretend_success'] = True
        with self.assertRaises(ManifestError):normalize_manifest(t, REPO)


if __name__ == '__main__':unittest.main()

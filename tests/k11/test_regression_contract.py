"""K11 acceptance-contract negatives; mocks do not claim a guest execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import candidates, regression
from kconc.cli import OperationError


def good_row(**changes):
    row = dict(classification='hit', candidate_hit=True, property_evaluated=True,
               property_violation=False, cleanup_verified=True, recovery_required=False)
    row.update(changes)
    return row


class SummaryContractTests(unittest.TestCase):
    def test_all_five_valid_clean_hits_are_bounded_only(self):
        result = regression.summarize([good_row() for _ in range(5)], 5)
        self.assertEqual(result['classification'], 'bounded-pass')
        self.assertFalse(result['complete_search'])
        self.assertFalse(result['source_correctness_proved'])

    def test_one_property_violation_is_regression_failure(self):
        rows = [good_row() for _ in range(5)]
        rows[2]['property_violation'] = True
        result = regression.summarize(rows, 5)
        self.assertEqual(result['classification'], 'regression-failed')
        self.assertEqual(result['property_violations'], 1)
        self.assertEqual(result['attempts'], 5)

    def test_every_incomplete_evidence_dimension_prevents_acceptance(self):
        for change in ({'candidate_hit': False}, {'property_evaluated': False},
                       {'property_violation': None}, {'cleanup_verified': False},
                       {'recovery_required': True}):
            with self.subTest(change=change):
                rows = [good_row() for _ in range(5)]
                rows[2].update(change)
                self.assertEqual(regression.summarize(rows, 5)['classification'], 'inconclusive')

    def test_nonhit_classification_cannot_be_overridden_by_true_flags(self):
        for classification in ('miss', 'timeout', 'invalid', 'infrastructure-error', 'running'):
            with self.subTest(classification=classification):
                rows = [good_row() for _ in range(5)]
                rows[2]['classification'] = classification
                result = regression.summarize(rows, 5)
                self.assertFalse(result['bounded_pass'])
                self.assertEqual(result['attempts'], 5)

    def test_remaining_attempts_are_explicit_and_never_success(self):
        result = regression.summarize([good_row()], 5)
        self.assertEqual(result['classification'], 'inconclusive')
        self.assertEqual(result['unattempted'], 4)

    def test_unexecuted_budget_is_not_a_repair_verdict(self):
        result = regression.summarize([], 5)
        self.assertEqual(result['classification'], 'inconclusive')
        self.assertEqual(result['unattempted'], 5)
        self.assertEqual(result['valid_property_evaluations'], 0)

    def test_property_violation_survives_partial_batch(self):
        result = regression.summarize([good_row(property_violation=True)], 5)
        self.assertEqual(result['classification'], 'regression-failed')
        self.assertEqual(result['unattempted'], 4)


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='k11-contract-')
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        self.state = self.out / 'state.json'
        self.state.write_text(json.dumps({'state': 'ready', 'boot_id': 'new-boot'}))
        self.entry = candidates.get_input(candidates.load_catalog(), 'rmw', 'disjoint-bits', 'split')
        self.bundle = dict(bundle_id='old-bundle', runtime_identity={'kernel': 'old'},
            source={'property_violation': True},
            candidate={'candidate_id': 'old-candidate', 'identity': {'input': copy.deepcopy(self.entry), 'baseline_order': 'ab'}})
        self.identity = {'kernel': 'new'}
        self.runtime = SimpleNamespace(
            task={'inputs': {'bundle': 'old-reference'}, 'scenario': {'repetitions': 5}},
            out=self.out, labdir=Path('/home/xzf/os-concurrency-k11-rmw'), statepath=self.state,
            ready_profile=lambda: ({'identity': self.identity}, {'state': 'ready', 'boot_id': 'new-boot'}),
        )
        def mark(state, **rest):
            self.state.write_text(json.dumps(dict(state=state, **rest)))
        self.runtime.mark = mark
        self.factory_calls = []
        self.executions = []
        self.fresh = {'candidate_id': 'new-candidate', 'identity': {'input': copy.deepcopy(self.entry)}}
        self.runtime.validate_fresh_sample = lambda *args: self.fresh
        def factory(task, out):
            self.factory_calls.append(out)
            def run_candidate(candidate):
                self.executions.append(candidate)
                analysis = good_row()
                (out / 'analysis.json').write_text(json.dumps(analysis))
                (out / 'attempt-result.json').write_text(json.dumps({'analysis': analysis}))
                return {'analysis': analysis}
            return SimpleNamespace(out=out, guest_started=True, run_candidate=run_candidate)
        self.factory = factory

    def execute(self, sample_ok=True):
        def sample(runner):
            result = {'passed': sample_ok}
            (runner.out / 'sample-result.json').write_text(json.dumps(result))
            (runner.out / 'candidate.json').write_text(json.dumps({'candidates': [self.fresh]}))
            return result
        method = regression.RegressionRuntime.regress
        with patch.object(regression, 'load_reference', return_value=self.bundle), \
             patch.object(regression, 'RegressionRuntime', side_effect=self.factory), \
             patch.object(regression.SampleRuntime, 'execute', side_effect=sample):
            return method(self.runtime)

    def test_sample_failure_retains_all_five_unattempted_and_never_runs_old_plan(self):
        with self.assertRaises(OperationError) as caught:
            self.execute(sample_ok=False)
        self.assertEqual(caught.exception.code, 'regression_sample_failed')
        result = json.loads((self.out / 'regression-result.json').read_text())
        self.assertEqual(result['summary']['unattempted'], 5)
        self.assertEqual(result['summary']['classification'], 'inconclusive')
        self.assertEqual(self.executions, [])
        self.assertFalse(result['passed'])
        self.assertEqual(len(self.factory_calls), 1)

    def test_old_mapping_invalid_and_old_bug_are_not_new_regression_failure(self):
        result = self.execute()
        cross = json.loads((self.out / 'cross-build.json').read_text())
        self.assertEqual(cross['old_location_status'], 'mapping-invalid')
        self.assertFalse(cross['mapping_invalid_is_repair_failure'])
        self.assertFalse(cross['old_schedule_executed'])
        self.assertTrue(cross['old_property_violation'])
        self.assertTrue(result['passed'])
        self.assertEqual(result['summary']['classification'], 'bounded-pass')
        self.assertEqual(len(self.executions), 5)
        self.assertTrue(all(c['candidate_id'] == 'new-candidate' for c in self.executions))

    def test_same_build_cannot_masquerade_as_cross_build_regression(self):
        self.identity.clear()
        self.identity.update(self.bundle['runtime_identity'])
        with self.assertRaises(OperationError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, 'repair_build_required')
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self.executions, [])

    def test_changed_logical_input_cannot_be_a_repair(self):
        self.fresh['identity']['input']['operations'][0]['mask'] = 255
        with self.assertRaises(OperationError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, 'regression_input_mismatch')
        self.assertEqual(self.executions, [])
        result = json.loads((self.out / 'regression-result.json').read_text())
        self.assertEqual(result['summary']['unattempted'], 5)


if __name__ == '__main__':
    unittest.main()

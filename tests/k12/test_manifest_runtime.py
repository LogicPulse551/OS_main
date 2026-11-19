"""K12 public contract checks; VM evidence is collected separately."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from kconc.manifest import normalize_manifest, ManifestError, CATALOG
from kconc.feedback import FeedbackRuntime
from kconc.lifecycle import guard_legacy

def task():
    return dict(schema_version=1,operation='kernel.explore',runtime=dict(lab_dir='/tmp/os-concurrency-k12-rmw',
        ssh_port=2251,build_lab='/tmp/build-lab',kernel_build='/tmp/build-lab/build/test',
        scenario_guest_build='/home/lab/k03/build-01',sample_guest_build='/home/lab/k11/build-03',search_guest_build='/home/lab/k11/build-03'),
        inputs=dict(samples='/tmp/samples.json',history='/tmp/history.json',source_mapper='/tmp/source-map'),
        scenario=dict(family='rmw',feedback=True,total_budget=4,pool_limit=4,per_input_budget=2,rotation_interval=2))

class Contracts(unittest.TestCase):
    def test_explicit_switch_and_three_budgets(self):
        normalized=normalize_manifest(task(),REPO)
        self.assertEqual(normalized['scenario'],task()['scenario'])
        self.assertEqual(CATALOG['kernel.explore']['project_task'],'K12')

    def test_reject_missing_unknown_and_bool_budgets(self):
        for key in task()['scenario']:
            value=task();value['scenario'].pop(key)
            with self.assertRaises(ManifestError):normalize_manifest(value,REPO)
        for key in ('total_budget','pool_limit','per_input_budget','rotation_interval'):
            for bad in (-1,True,4097,1.5):
                value=task();value['scenario'][key]=bad
                with self.assertRaises(ManifestError):normalize_manifest(value,REPO)
        value=task();value['scenario']['feedback']=1
        with self.assertRaises(ManifestError):normalize_manifest(value,REPO)

    def test_zero_budgets_and_feedback_disabled_are_valid(self):
        value=task();value['scenario'].update(feedback=False,total_budget=0,pool_limit=0,per_input_budget=0)
        self.assertFalse(normalize_manifest(value,REPO)['scenario']['feedback'])

    def test_reuses_real_regression_executor_and_matching(self):
        from kconc.regression import RegressionRuntime
        self.assertIs(FeedbackRuntime.run_candidate,RegressionRuntime.run_candidate)
        self.assertIs(FeedbackRuntime.analyze_candidate,RegressionRuntime.analyze_candidate)
        self.assertIs(FeedbackRuntime.identity,RegressionRuntime.identity)
        self.assertEqual(FeedbackRuntime.lab_prefix,'os-concurrency-k12')

    def test_dirty_feedback_cannot_bypass_through_legacy(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'run').mkdir();(root/'run/k12-state.json').write_text('{"state":"dirty"}')
            from kconc.cli import OperationError
            with self.assertRaises(OperationError):guard_legacy(dict(lab_dir=folder),'env.check')
            guard_legacy(dict(lab_dir=folder),'env.status')

if __name__=='__main__':unittest.main()

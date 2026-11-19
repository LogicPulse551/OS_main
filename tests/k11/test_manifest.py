import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from kconc.manifest import normalize_manifest, ManifestError


class RegressionManifestTests(unittest.TestCase):
    def setUp(self):
        self.task=dict(schema_version=1,operation='kernel.regress',runtime=dict(
            lab_dir='/home/test/os-concurrency-k11-rmw',ssh_port=2243,
            build_lab='/home/test/os-concurrency-lab',kernel_build='/home/test/build',
            scenario_guest_build='/home/lab/k03/build-01',sample_guest_build='/home/lab/k11/build-02',
            search_guest_build='/home/lab/k11/build-02'),inputs=dict(bundle='/tmp/bundle',source_mapper='/tmp/map'),
            scenario=dict(repetitions=5))

    def test_complete_manifest(self):
        self.assertEqual(normalize_manifest(self.task,Path('/tmp'))['scenario'],dict(repetitions=5))

    def test_budget_must_be_positive_finite_integer(self):
        for value in (0,-1,1001,True,2.5,'5'):
            task=copy.deepcopy(self.task);task['scenario']['repetitions']=value
            with self.subTest(value=value),self.assertRaises(ManifestError):normalize_manifest(task,Path('/tmp'))

    def test_old_plan_or_source_mode_override_rejected(self):
        for field,value in [('scenario',dict(repetitions=5,mode='shared')),('inputs',dict(plan='/tmp/old',source_mapper='/tmp/map'))]:
            task=copy.deepcopy(self.task);task[field]=value
            with self.subTest(field=field),self.assertRaises(ManifestError):normalize_manifest(task,Path('/tmp'))

    def test_guest_build_must_be_direct_child(self):
        task=copy.deepcopy(self.task);task['runtime']['search_guest_build']='/home/lab/k11/build-02/nested'
        with self.assertRaises(ManifestError):normalize_manifest(task,Path('/tmp'))

    def test_initialize_needs_no_old_bundle(self):
        task=copy.deepcopy(self.task);task['operation']='regression.initialize';del task['inputs'];del task['scenario']
        self.assertEqual(normalize_manifest(task,Path('/tmp'))['inputs'],{})

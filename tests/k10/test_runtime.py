"""Host accounting and failure gates without guest or kernel execution."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'src'))
import kconc
from kconc import replay
from kconc.cli import OperationError
from kconc.manifest import ManifestError,normalize_manifest

class SummaryTests(unittest.TestCase):
    def rows(self,matches,total):return [dict(classification='matched' if i<matches else 'path-diverged',matched=i<matches,property_reproduced=True) for i in range(total)]
    def test_threshold_is_19_of_20_not_any_error_reproduction(self):
        self.assertTrue(replay.summarize(self.rows(19,20),20)['stability_accepted'])
        self.assertFalse(replay.summarize(self.rows(18,20),20)['stability_accepted'])
    def test_less_than_twenty_or_unattempted_cannot_pass(self):
        self.assertFalse(replay.summarize(self.rows(19,19),19)['stability_accepted'])
        self.assertFalse(replay.summarize(self.rows(19,19),20)['stability_accepted'])
    def test_failed_attempt_kept_in_denominator(self):
        rows=self.rows(19,20);rows[-1].update(classification='timeout',property_reproduced=False)
        r=replay.summarize(rows,20);self.assertEqual(r['attempts'],20);self.assertEqual(r['full_matches'],19)
        self.assertEqual(r['classification']['timeout'],1);self.assertFalse(r['future_probability_claimed'])
    def test_exact_ratio_and_running_state(self):
        self.assertFalse(replay.summarize(self.rows(19,21),21)['stability_accepted'])
        rows=self.rows(20,20);rows[-1]['classification']='running'
        self.assertFalse(replay.summarize(rows,20)['stability_accepted'])

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.base=Path(t.name)
        self.out=self.base/'output';self.out.mkdir();self.pack=self.base/'bundle';self.pack.mkdir();(self.pack/'bundle.json').write_text('{}')
        self.state=self.base/'state.json';self.state.write_text('{"state":"ready"}')
        self.rt=object.__new__(replay.ReplayRuntime);r=self.rt
        r.task=dict(operation='replay.run',runtime={},inputs={'bundle':str(self.pack),'source_mapper':'/mapper'},scenario={'repetitions':20})
        r.out=self.out;r.statepath=self.state;r.labdir=self.base/'os-concurrency-k10-rmw'
        self.identity={'fixed_build':'sha256'}
        r.ready_profile=Mock(return_value=({'identity':self.identity},{'boot_id':'initial'}))
        r.mark=Mock(side_effect=lambda state,**kw:self.state.write_text(json.dumps(dict(state=state,**kw))))
        self.bundle=dict(_directory=str(self.pack),runtime_identity=self.identity,candidate=dict(candidate_id='c'*64,identity={'input':{'family':'rmw'}}))
        self.match=True;self.fail_at=None;self.count=0;self.recovery=False
        self.bundles=SimpleNamespace(load_bundle=Mock(return_value=self.bundle),compare=Mock(side_effect=self.compare))
        p=patch.object(kconc,'replay_bundle',self.bundles,create=True);p.start();self.addCleanup(p.stop)
        p=patch.object(replay,'ReplayRuntime',side_effect=self.runner);p.start();self.addCleanup(p.stop)
    def runner(self,task,out):
        self.count+=1;n=self.count
        def execute(candidate):
            if self.fail_at==n:raise OSError('lost host transport')
            value=dict(classification='hit',passed=True,recovery_required=self.recovery)
            (out/'attempt-result.json').write_text(json.dumps(value));return value
        return SimpleNamespace(run_candidate=execute,guest_started=True)
    def compare(self,bundle,directory):
        return dict(full_match=self.match,property_reproduced=True,classification='matched' if self.match else 'path-diverged')
    def test_twenty_attempts_each_new_directory_and_frozen_reference(self):
        result=self.rt.replay();self.assertTrue(result['passed']);self.assertTrue(result['summary']['stability_accepted'])
        self.assertEqual(len(list(self.out.glob('attempt-*'))),20);self.assertEqual(self.bundles.compare.call_count,20)
        self.assertEqual([x['ordinal'] for x in result['attempts']],list(range(1,21)))
    def test_same_property_but_path_difference_fails_stability(self):
        self.match=False;r=self.rt.replay();self.assertTrue(r['passed'])
        self.assertEqual(r['summary']['property_reproduced'],20);self.assertEqual(r['summary']['full_matches'],0);self.assertFalse(r['summary']['stability_accepted'])
    def test_lost_transport_retains_failed_attempt_and_unattempted(self):
        self.fail_at=3
        with self.assertRaises(OSError):self.rt.replay()
        r=json.loads((self.out/'replay-result.json').read_text())
        self.assertEqual(r['summary']['attempts'],3);self.assertEqual(r['summary']['unattempted'],17)
        self.assertEqual(r['attempts'][-1]['classification'],'infrastructure-error');self.assertFalse(r['summary']['stability_accepted'])
        self.assertEqual(json.loads(self.state.read_text())['state'],'dirty')
    def test_recovery_required_stops_no_implicit_retry(self):
        self.recovery=True;r=self.rt.replay();self.assertFalse(r['passed']);self.assertEqual(len(r['attempts']),1)
    def test_foreign_native_build_rejected_before_attempt(self):
        self.bundle['runtime_identity']={'other':'build'}
        with self.assertRaises(OperationError):self.rt.replay()
        self.assertEqual(self.count,0);self.assertFalse((self.out/'replay-result.json').exists())
    def test_wrong_kernel_family_vm_rejected_before_attempt(self):
        self.bundle['candidate']['identity']['input']['family']='mutex'
        with self.assertRaises(OperationError):self.rt.replay()
        self.assertEqual(self.count,0)
    def test_comparison_exception_cannot_leave_ready_state(self):
        self.bundles.compare.side_effect=ValueError('missing evidence')
        with self.assertRaises(ValueError):self.rt.replay()
        self.assertEqual(json.loads(self.state.read_text())['state'],'dirty')
    def check_invalid_comparison_stops(self,classification,errors):
        self.bundles.compare.side_effect=lambda *_:dict(full_match=False,property_reproduced=False,classification=classification,errors=errors)
        result=self.rt.replay();self.assertFalse(result['passed']);self.assertTrue(result['recovery_required'])
        self.assertEqual(result['summary']['attempts'],1);self.assertEqual(result['summary']['unattempted'],19)
        row=result['attempts'][0];self.assertEqual(row['classification'],'invalid');self.assertFalse(row['matched'])
        self.assertEqual(row['candidate_classification'],'hit');self.assertTrue(row['recovery_required'])
        self.assertEqual(json.loads(self.state.read_text())['state'],'dirty')
        self.assertTrue((self.out/'attempt-001/attempt-result.json').is_file());self.assertTrue(row['attempt_result_sha256'])
        self.assertEqual(json.loads((self.out/'attempt-001/comparison.json').read_text())['errors'],errors)
        self.assertTrue(row['comparison_sha256']);self.assertEqual(self.bundles.compare.call_count,1)
    def test_comparison_invalid_return_cannot_leave_ready_state(self):
        self.check_invalid_comparison_stops('invalid',[])
    def test_comparison_error_return_preserves_candidate_and_stops(self):
        self.check_invalid_comparison_stops('path-diverged',['Saved K09 analysis does not reproduce from its evidence'])

class ManifestTests(unittest.TestCase):
    def test_bind_has_no_runtime_requirement(self):
        r=normalize_manifest(dict(schema_version=1,operation='replay.bind',inputs={'attempt':'/external/k09'}),REPO)
        self.assertEqual(r['runtime'],{})
    def test_exact_bounded_repetitions_and_inputs(self):
        runtime=dict(lab_dir='/home/xzf/os-concurrency-k10-rmw',ssh_port=2233,build_lab='/build',kernel_build='/kernel',scenario_guest_build='/home/lab/k03/build-01',sample_guest_build='/home/lab/k08/build-01',search_guest_build='/home/lab/k09/build-01')
        t=dict(schema_version=1,operation='replay.run',runtime=runtime,inputs=dict(bundle='/bundle',source_mapper='/mapper'),scenario=dict(repetitions=20))
        normalize_manifest(t,REPO)
        for x in (0,True,1001,20.0):
            t['scenario']['repetitions']=x
            with self.assertRaises(ManifestError):normalize_manifest(t,REPO)
        t['scenario']={'repetitions':20,'threshold':.5}
        with self.assertRaises(ManifestError):normalize_manifest(t,REPO)

if __name__=='__main__':unittest.main()

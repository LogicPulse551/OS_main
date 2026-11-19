"""K09 host lifecycle rejection tests; no VM is launched by these fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'src'))
from kconc import search
from kconc.cli import OperationError
from kconc.manifest import normalize_manifest,ManifestError

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

old=load('k09_old_host_fixture',REPO/'tests/k08/test_runtime.py')
queue_fixtures=load('k09_queue_fixture',Path(__file__).with_name('test_queue.py'))

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        h=self.h=old.RuntimeTests();h.setUp();self.addCleanup(h.doCleanups)
        rt=self.rt=h.rt;rt.__class__=search.SearchRuntime
        h.fields['search_guest_build']='/home/lab/k09/build-01'
        h.task['operation']='kernel.check';h.task['scenario']={'family':'rmw','max_candidates':2}
        h.profile['runtime']=h.fields;old.save(rt.profilepath,h.profile)
        self.candidate=queue_fixtures.candidate();self.plan=search.queue.make_plan(self.candidate)
        h.analysis_value.update(classification='hit',candidate_hit=True,cleanup_verified=True,recovery_required=False)
        rt.poll_guest=Mock(side_effect=self.poll);rt.collect=Mock(side_effect=self.collect)
        self.guest_changes={};self.bad_plan=False
        for target,kw in [('load',{'return_value':h.analysis}),('queue.eligibility',{'return_value':{'supported':True}})]:
            p=patch('kconc.search.'+target,**kw);p.start();self.addCleanup(p.stop)

    def poll(self,remote):
        req=json.loads((self.rt.out/'guest-request.json').read_text())
        value=dict(self.h.guest,run_id=req['run_id'],boot_id='boot-a',fault='none',command=[req['executable'],req['scenario_library'],'--k09-execute',self.candidate['identity']['baseline_order'],req['plan_path'],remote+'/trace'])
        value.update(self.guest_changes);return value

    def collect(self,remote):
        directory=self.rt.out/'guest';directory.mkdir(exist_ok=True)
        old.save(directory/'guest-result.json',self.poll(remote))
        trace=directory/'trace';trace.mkdir(exist_ok=True)
        for name in ('A.events.jsonl','B.events.jsonl'):(trace/name).write_text('synthetic fixture')
        (trace/'plan.txt').write_bytes(b'wrong' if self.bad_plan else self.plan)

    def run_one(self):return self.rt.run_candidate(self.candidate)

    def test_exact_plan_submitted_and_ready_only_after_matching_and_cleanup(self):
        r=self.run_one();self.assertTrue(r['passed']);self.assertEqual(self.h.state()['state'],'ready')
        self.assertEqual((self.rt.out/'input-plan.txt').read_bytes(),self.plan)
        self.assertTrue(r['analysis']['checks']['executed_plan_matches_submitted'])

    def test_clean_miss_retained_without_property_claim(self):
        self.h.analysis_value.update(classification='miss',candidate_hit=False,property_evaluated=False,property_violation=False)
        r=self.run_one();self.assertEqual(r['classification'],'miss');self.assertEqual(self.h.state()['state'],'ready')

    def test_different_executed_plan_cannot_count_hit(self):
        self.bad_plan=True;r=self.run_one();self.assertEqual(r['classification'],'invalid')
        self.assertFalse(r['analysis']['property_evaluated']);self.assertEqual(self.h.state()['state'],'dirty')

    def test_dirty_rejects_before_guest_launch(self):
        old.save(self.rt.statepath,dict(state='dirty',boot_id='boot-a'))
        with self.assertRaises(OperationError):self.run_one()
        self.rt.guest.assert_not_called()

    def test_changed_boot_rejects_and_persists_dirty(self):
        self.rt.boot_id.return_value='different'
        with self.assertRaises(OperationError):self.run_one()
        self.assertEqual(self.h.state()['state'],'dirty');self.rt.guest.assert_not_called()

    def test_incompatible_binding_does_not_launch(self):
        with patch.object(search.queue,'eligibility',return_value={'supported':False}):
            with self.assertRaises(OperationError):self.run_one()
        self.rt.guest.assert_not_called()

    def test_supervisor_identity_or_command_mismatch_retains_dirty(self):
        for key,value in [('boot_id','bad'),('run_id','bad'),('command',['bad']),('fault','setup')]:
            self.h.ready();self.guest_changes={key:value}
            with self.assertRaises(OperationError):self.run_one()
            self.assertEqual(self.h.state()['state'],'dirty');self.h.analysis.analyze.assert_not_called()

    def test_poll_failure_collects_and_does_not_clear_dirty(self):
        self.rt.poll_guest.side_effect=OSError('lost transport')
        with self.assertRaises(OSError):self.run_one()
        self.rt.collect.assert_called_once();self.assertEqual(self.h.state()['state'],'dirty')

    def test_collection_failure_does_not_clear_dirty(self):
        self.rt.collect.side_effect=OSError('incomplete archive')
        with self.assertRaises(OperationError):self.run_one()
        self.assertEqual(self.h.state()['state'],'dirty')

    def test_cancel_collects_records_and_requires_recovery(self):
        self.rt.poll_guest.side_effect=KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):self.run_one()
        self.rt.ssh.assert_called_once();self.rt.collect.assert_called_once();self.assertEqual(self.h.state()['state'],'dirty')

    def test_host_timeout_does_not_become_success(self):
        self.rt.poll_guest.side_effect=None;self.rt.poll_guest.return_value=None
        with patch.object(search.time,'monotonic',side_effect=[0,100]):
            with self.assertRaises(OperationError):self.run_one()
        self.assertEqual(self.h.state()['state'],'dirty')

    def test_timeout_analysis_requires_recovery(self):
        self.h.analysis_value.update(passed=False,classification='timeout',candidate_hit=False,recovery_required=True,property_evaluated=False)
        r=self.run_one();self.assertFalse(r['passed']);self.assertEqual(self.h.state()['state'],'dirty')

class ManifestTests(unittest.TestCase):
    def task(self):
        return dict(schema_version=1,name='k09',operation='kernel.check',runtime=dict(lab_dir='/home/xzf/os-concurrency-k09-rmw',ssh_port=2231,build_lab='/home/xzf/os-concurrency-lab',kernel_build='/home/xzf/os-concurrency-lab/build/linux-k06-01',scenario_guest_build='/home/lab/k03/build-01',sample_guest_build='/home/lab/k08/build-01',search_guest_build='/home/lab/k09/build-01'),scenario=dict(family='rmw',max_candidates=21),inputs=dict(pool='/external/pool.json',source_mapper='/external/mapper'))
    def test_search_contract_and_zero_budget(self):
        t=self.task();normalize_manifest(t,REPO);t['scenario']['max_candidates']=0;normalize_manifest(t,REPO)
    def test_no_hidden_sampling_or_plan_substitution(self):
        for field,value in [('max_candidates',True),('max_candidates',-1),('family','all'),('plan','other')]:
            t=self.task();t['scenario'][field]=value
            with self.assertRaises(ManifestError):normalize_manifest(t,REPO)
        t=self.task();t['inputs']['plan']='other'
        with self.assertRaises(ManifestError):normalize_manifest(t,REPO)

if __name__=='__main__':unittest.main()

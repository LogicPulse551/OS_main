"""Evidence-integrity tests with synthetic exports; no real guest claims."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from kconc import feedback_evidence as e, candidates as c

spec = importlib.util.spec_from_file_location('feedback_k11_fixtures',REPO/'tests/k11/test_analysis.py')
fixtures = importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='k12-evidence-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name)
        self.helper=fixtures.AnalysisTests();self.addCleanup(self.helper.doCleanups)
        self.module=fixtures.a
        self.patcher=patch.object(self.module,'verify_profile',side_effect=lambda binding:self.profile)
        self.patcher.start();self.addCleanup(self.patcher.stop)
        self.load_patch=patch.object(e,'analyzer',return_value=self.module)
        self.load_patch.start();self.addCleanup(self.load_patch.stop)

    def archive(self, family='rmw', order='ab', name='sample'):
        root=self.base/name;root.mkdir()
        f=self.helper.fixture(family,order)
        trace=root/'guest/trace/baseline';trace.parent.mkdir(parents=True)
        shutil.move(f.trace,trace);f.trace=trace
        self.profile=f.profile
        identity=dict(repair_profile=f.profile.identity)
        f.guest.update(run_id='synthetic-sample-'+name)
        save(root/'guest/guest-result.json',f.guest)
        report=self.module.analyze_sample(trace,f.mapping,f.guest,f.family,f.order,f.profile)
        scenario=dict(family=f.family,case_id=f.phases[0]['case_id'],mode=f.phases[0]['mode'],order=f.order)
        report['checks']['submitted_scenario_matches']=True
        task=dict(operation='regression.sample',scenario=scenario)
        save(root/'task.json',task);save(root/'analysis.json',report)
        save(root/'runtime-identity.json',identity);save(root/'repair-binding.json',dict(test_only=True))
        (root/'source-map.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in f.mapping.values()),encoding='utf-8')
        extra=dict(source_map_sha256=e.digest(root/'source-map.jsonl'),runtime_identity_sha256=e.digest(root/'runtime-identity.json'),
            guest_sha256=e.digest(root/'guest/guest-result.json'),task_sha256=e.digest(root/'task.json'),run_id=f.guest['run_id'])
        candidate=e.candidate_from_analysis(report,trace,identity,root/'analysis.json',extra)
        save(root/'candidate.json',e._pool([candidate]))
        save(root/'sample-result.json',dict(passed=True,recovery_required=False,candidate_execution_performed=False,
            candidate_sha256=e.digest(root/'candidate.json'),analysis=report))
        return root,candidate,f

    def history(self, name='history'):
        sample,candidate,f=self.archive()
        root=self.base/name;root.mkdir()
        attempt=root/'attempt-001';attempt.mkdir()
        actual=self.helper.fixture()
        self.helper.execute(actual)
        trace=attempt/'guest/trace';trace.parent.mkdir(parents=True)
        shutil.move(actual.trace,trace);actual.trace=trace
        identity=candidate['identity']['build_identity'];self.profile=actual.profile
        request=dict(run_id='synthetic-guest',executable='/home/lab/k11/build-03/bin/kcov-execute-k09-ab',
            scenario_library='/home/lab/k11/build-03/bin/'+candidate['identity']['input']['native_so'],
            plan_path='/home/lab/k09/run-synthetic/plan.txt',fault='none')
        actual.guest.update(run_id=request['run_id'],command=[request['executable'],request['scenario_library'],
            '--k09-execute','ab',request['plan_path'],'/home/lab/k09/run-synthetic/trace'])
        save(attempt/'guest/guest-result.json',actual.guest);save(attempt/'guest-request.json',request)
        save(attempt/'candidate.json',candidate);save(attempt/'runtime-identity.json',identity)
        save(attempt/'repair-binding.json',dict(test_only=True))
        save(attempt/'task.json',dict(attempt_id='attempt-one',candidate_id=candidate['candidate_id']))
        (attempt/'input-plan.txt').write_bytes(e.make_plan(candidate))
        (attempt/'source-map.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in actual.mapping.values()),encoding='utf-8')
        report=self.module.analyze_execution(trace,actual.mapping,actual.guest,candidate,actual.profile)
        report['checks']['executed_plan_matches_submitted']=True
        report.update(runtime_identity_bound=True,runtime_identity_sha256=e.digest(attempt/'runtime-identity.json'),
            candidate_file_sha256=e.digest(attempt/'candidate.json'),plan_sha256=e.digest(attempt/'input-plan.txt'))
        save(attempt/'analysis.json',report)
        save(attempt/'attempt-result.json',dict(candidate_id=candidate['candidate_id'],guest_started=True,guest=actual.guest,
            analysis=report,classification=report['classification'],recovery_required=report['recovery_required'],passed=report['passed']))
        row=dict(ordinal=1,attempt_id='attempt-one',candidate_id=candidate['candidate_id'],outcome=report['classification'],
            guest_started=True,cleanup_confirmed=report['cleanup_verified'],property_evaluated=report['property_evaluated'],
            candidate_hit=report['candidate_hit'],recovery_required=report['recovery_required'],
            property_violation=report['property_violation'] if report['property_evaluated'] else None,
            evidence=dict(directory=str(attempt),analysis_sha256=e.digest(attempt/'analysis.json'),result_sha256=e.digest(attempt/'attempt-result.json')))
        row['observed_feature']=e.execution_feature(attempt,candidate,report)
        pool=e._pool([candidate]);save(root/'imported-pool.json',pool);save(root/'runtime-identity.json',identity)
        save(root/'history-validation.json',dict(passed=True,attempts=0))
        save(root/'ledger.json',dict(finalized=True,pool_sha256=c.fingerprint(pool),attempts=[row]))
        result=dict(kind='kconc.feedback-search',passed=True,ledger_sha256=e.digest(root/'ledger.json'),
            runtime_identity_sha256=e.digest(root/'runtime-identity.json'),imported_pool_sha256=e.digest(root/'imported-pool.json'),
            history_validation_sha256=e.digest(root/'history-validation.json'))
        save(root/'feedback-result.json',result);save(root/'result.json',dict(operation='kernel.explore',status='passed',data=result))
        return root,pool,candidate

    def test_sample_recomputed_and_duplicate_sources_preserved(self):
        root,candidate,_=self.archive()
        pool,record=e.load_samples([str(root),str(root)])
        self.assertEqual(pool['candidates'][0]['identity'],candidate['identity'])
        self.assertEqual(len(pool['candidates']),1);self.assertEqual(record['source_records'],2)
        self.assertEqual(len(pool['candidates'][0]['sources']),2)
        self.assertFalse(record['candidate_executed'])

    def test_all_raw_file_changes_fail_even_with_passed_summary(self):
        for name in c.TRACE_FILES:
            with self.subTest(name=name):
                root,_,_=self.archive(name='s-'+name.replace('.','-'))
                path=root/'guest/trace/baseline'/name;path.write_bytes(path.read_bytes()+b'changed')
                with self.assertRaisesRegex(ValueError,'raw trace changed'):e.verify_sample(root,self.module)

    def test_each_bound_sample_file_change_rejected(self):
        for name in ('analysis.json','source-map.jsonl','runtime-identity.json','guest/guest-result.json','task.json'):
            with self.subTest(name=name):
                root,_,_=self.archive(name='s-'+name.replace('/','-').replace('.','-'))
                path=root/name;path.write_bytes(path.read_bytes()+b' ')
                with self.assertRaisesRegex(ValueError,'source binding changed'):e.verify_sample(root,self.module)

    def test_profile_checker_is_mandatory(self):
        root,_,_=self.archive()
        with patch.object(self.module,'verify_profile',side_effect=ValueError('wrong build')):
            with self.assertRaisesRegex(ValueError,'wrong build'):e.verify_sample(root,self.module)

    def test_both_families_and_directions_keep_logical_and_physical_roles(self):
        for family in ('rmw','mutex'):
            for order in ('ab','ba'):
                with self.subTest(family=family,order=order):
                    root,candidate,_=self.archive(family,order,name=family+'-'+order)
                    pool,record=e.load_samples([str(root)])
                    self.assertEqual(pool['candidates'][0]['identity'],candidate['identity'])
                    self.assertEqual(record['features'][candidate['candidate_id']]['candidate_id'],candidate['candidate_id'])

    def test_source_path_cannot_be_rebound(self):
        root,candidate,_=self.archive()
        candidate['sources'][0]['trace_path']=str(self.base/'another/guest/trace/baseline')
        save(root/'candidate.json',e._pool([candidate]))
        with self.assertRaisesRegex(ValueError,'trace path differs'):e.verify_sample(root,self.module)

    def test_sample_completion_is_checked(self):
        root,_,_=self.archive();r=e.read(root/'sample-result.json');r['candidate_execution_performed']=True
        save(root/'sample-result.json',r)
        with self.assertRaisesRegex(ValueError,'completion'):e.verify_sample(root,self.module)

    def test_old_k08_operation_is_not_silently_relabelled(self):
        root,_,_=self.archive();task=e.read(root/'task.json');task['operation']='sample.run';save(root/'task.json',task)
        with self.assertRaisesRegex(ValueError,'regression.sample'):e.verify_sample(root,self.module)

    def test_history_raw_recomputed_and_duplicate_attempt_not_double_counted(self):
        root,pool,_=self.history()
        records,result=e.load_history([str(root),str(root)],pool)
        self.assertEqual(result['attempts'],1);self.assertEqual(result['verified_hits'],1)
        self.assertEqual(result['duplicate_attempt_records'],1)
        self.assertEqual(records[0]['attempt_id'],'attempt-one')

    def test_forged_aggregate_or_raw_history_rejected(self):
        root,pool,_=self.history();r=e.read(root/'attempt-001/analysis.json');r['property_violation']=True
        save(root/'attempt-001/analysis.json',r)
        with self.assertRaisesRegex(ValueError,'no longer reproduces'):e.load_history([str(root)],pool)

    def test_history_ledger_hash_cannot_be_rewritten_alone(self):
        root,pool,_=self.history();r=e.read(root/'ledger.json');r['attempts']=[];save(root/'ledger.json',r)
        with self.assertRaisesRegex(ValueError,'binding changed'):e.load_history([str(root)],pool)

    def test_history_cannot_omit_unrecorded_attempt_folder(self):
        root,pool,_=self.history();(root/'attempt-002').mkdir()
        with self.assertRaisesRegex(ValueError,'unrecorded attempts'):e.load_history([str(root)],pool)

    def test_empty_history_is_explicit_and_does_not_run_guest(self):
        _,candidate,_=self.archive();records,result=e.load_history([],e._pool([candidate]))
        self.assertEqual(records,[]);self.assertEqual(result['current_guest_executions'],0)

    def test_missing_relative_or_in_repo_paths_rejected(self):
        for path in ('relative',REPO):
            with self.assertRaises(ValueError):e.directory(path)

    def reseal(self,root,ledger=None,passed=None):
        if ledger is not None:save(root/'ledger.json',ledger)
        result=e.read(root/'feedback-result.json');result['ledger_sha256']=e.digest(root/'ledger.json')
        if passed is not None:result['passed']=passed
        save(root/'feedback-result.json',result)
        save(root/'result.json',dict(operation='kernel.explore',status='passed' if result['passed'] else 'failed',data=result))

    def test_observed_feature_cannot_be_replaced_with_sample_or_aggregate(self):
        root,pool,_=self.history();ledger=e.read(root/'ledger.json')
        ledger['attempts'][0]['observed_feature']['pairs']=[]
        ledger['attempts'][0]['observed_feature']['projection_fingerprint']='f'*64
        self.reseal(root,ledger)
        with self.assertRaisesRegex(ValueError,'observed feature differs'):e.load_history([str(root)],pool)

    def test_resealed_false_cleanup_or_recovery_claim_rejected(self):
        root,pool,_=self.history();ledger=e.read(root/'ledger.json')
        ledger['attempts'][0]['recovery_required']=True
        self.reseal(root,ledger)
        with self.assertRaisesRegex(ValueError,'aggregate differs'):e.load_history([str(root)],pool)

    def test_finalized_infrastructure_failure_kept_for_rotation_without_seen(self):
        root,pool,_=self.history();attempt=root/'attempt-001'
        exception=dict(guest_started=False,type='OSError',message='synthetic launch failure')
        save(attempt/'exception.json',exception)
        ledger=e.read(root/'ledger.json');row=ledger['attempts'][0]
        row.update(outcome='infrastructure-error',guest_started=False,cleanup_confirmed=False,
            candidate_hit=False,recovery_required=True,property_evaluated=False,property_violation=None,
            observed_feature=None,evidence=dict(directory=str(attempt),exception_sha256=e.digest(attempt/'exception.json')))
        self.reseal(root,ledger,passed=False)
        rows,result=e.load_history([str(root)],pool)
        self.assertEqual(result['outcomes'],{'infrastructure-error':1})
        self.assertEqual(result['verified_hits'],0);self.assertTrue(rows[0]['recovery_required'])


if __name__=='__main__':unittest.main()

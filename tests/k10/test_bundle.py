"""Portable replay evidence and rejection tests; synthetic traces are not kernel runs."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from kconc import candidates as c, replay_bundle as b

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

fixtures=load('bundle_k09_fixture',REPO/'tests/k09/test_analysis.py')
queue=load('bundle_queue_fixture',REPO/'tests/k09/test_queue.py')

def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

class BundleTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='k10-bundle-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name)

    def fixture(self,family='rmw',order='ab',mode='split'):
        helper=fixtures.AnalysisTests();self.addCleanup(helper.doCleanups)
        case='disjoint-bits' if family=='rmw' else 'different-registers'
        f=helper.fixture(family,order,case,mode)
        if mode=='split':
            ip='0xffffffff81859990'
            f.mapping[ip]=dict(f.mapping[f.ips[0]],raw_ip=ip,lookup_ip=f'0x{int(ip,16)-1:016x}',symbol='regmap_write')
            for slot in ('A','B'):
                e=copy.deepcopy(f.events[slot][-1]);e['ip']=ip;e['stack'][-1]['ip']=ip
                f.events[slot].insert(-1,e)
        original=queue.identity();f.candidate['identity']['build_identity']=original
        f.candidate['candidate_id']=c.fingerprint(f.candidate['identity']);f.write(True)
        root=self.base/('case-'+str(len(list(self.base.glob('case-*')))));p=root/'attempt-001';p.mkdir(parents=True)
        shutil.copytree(f.trace,p/'guest/trace')
        save(p/'candidate.json',f.candidate);save(p/'runtime-identity.json',queue.runtime(original))
        save(p/'task.json',dict(schema_version=1,operation='kernel.check',candidate_id=f.candidate['candidate_id'],attempt_id='attempt-id',runtime={'search_guest_build':'/home/lab/k09/build-01'}))
        (p/'input-plan.txt').write_bytes((f.trace/'plan.txt').read_bytes())
        (p/'source-map.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in f.mapping.values()))
        run_id='a'*32;remote='/home/lab/k09/run-'+run_id
        request=dict(run_id=run_id,executable='/home/lab/k09/build-01/bin/kcov-execute-k09-'+order,scenario_library='/home/lab/k09/build-01/bin/'+f.candidate['identity']['input']['native_so'],fault='none',plan_path=remote+'/plan.txt',timeout_seconds=60)
        save(p/'guest-request.json',request)
        f.guest.update(run_id=run_id,boot_id='boot-reference',started_utc='2026-11-13T00:00:00+00:00',finished_utc='2026-11-13T00:00:01+00:00',command=[request['executable'],request['scenario_library'],'--k09-execute',order,request['plan_path'],remote+'/trace'])
        save(p/'guest/guest-result.json',f.guest)
        self.reanalyze(p)
        analysis=json.loads((p/'analysis.json').read_text())
        self.assertEqual(analysis['classification'],'hit',analysis)
        ledger=dict(attempts=[dict(attempt_id='attempt-id',candidate_id=f.candidate['candidate_id'],outcome='hit',guest_started=True,cleanup_confirmed=True,property_evaluated=True,property_violation=analysis['property_violation'],evidence=dict(directory=str(p),analysis_sha256=b._sha(p/'analysis.json'),result_sha256=b._sha(p/'attempt-result.json')))])
        save(root/'ledger.json',ledger)
        return p

    def reanalyze(self,p):
        candidate=b._read(p/'candidate.json');guest=b._read(p/'guest/guest-result.json')
        a=b.k09.analyze(p/'guest/trace',b._mapping(p/'source-map.jsonl'),guest,candidate)
        a['checks']['executed_plan_matches_submitted']=True
        a.update(runtime_identity_bound=True,runtime_identity_sha256=b._sha(p/'runtime-identity.json'),candidate_file_sha256=b._sha(p/'candidate.json'),plan_sha256=b._sha(p/'input-plan.txt'))
        save(p/'analysis.json',a)
        save(p/'attempt-result.json',dict(kind='kconc.candidate-attempt',candidate_id=candidate['candidate_id'],guest_started=True,guest=guest,analysis=a,passed=a['passed'],classification=a['classification'],recovery_required=a['recovery_required']))

    def actual(self,p):
        out=p.parent/'actual';shutil.copytree(p,out)
        task=b._read(out/'task.json');task['operation']='replay.run';save(out/'task.json',task)
        request=b._read(out/'guest-request.json');old=request['run_id'];request['run_id']='b'*32;request['plan_path']=request['plan_path'].replace(old,request['run_id']);save(out/'guest-request.json',request)
        guest=b._read(out/'guest/guest-result.json');guest.update(run_id=request['run_id'],boot_id='boot-new',started_utc='2026-11-13T00:01:00+00:00',finished_utc='2026-11-13T00:01:01+00:00');guest['command']=[x.replace(old,request['run_id']) for x in guest['command']];save(out/'guest/guest-result.json',guest)
        self.reanalyze(out);return out

    def pack(self,p):return b.create_bundle(p,p.parent/'bundle')

    def edit_events(self,p,slot,edit):
        trace=p/'guest/trace';rows=[json.loads(line) for line in (trace/(slot+'.events.jsonl')).read_text().splitlines()];edit(rows)
        offset=0
        for event in rows:event['word_index']=offset;offset+=b.k09.k03._WIDTH[event['kind']]
        (trace/(slot+'.events.jsonl')).write_text(''.join(json.dumps(e)+'\n' for e in rows));(trace/(slot+'.words')).write_text('0000000000000000\n'*offset)
        meta=b._read(trace/'run.json');meta[slot+'_words']=offset;meta[slot]=b.k09.k03._stats(rows,b.k09.k03.read_plan(trace/'plan.txt')['stack'] if slot=='A' else None);save(trace/'run.json',meta)
        self.reanalyze(p)

    def test_all_eight_reference_kinds_and_directions_can_match(self):
        for family,modes in [('rmw',('split','update-bits')),('mutex',('per-role','shared'))]:
            for mode in modes:
                for order in ('ab','ba'):
                    with self.subTest(family=family,mode=mode,order=order):
                        p=self.fixture(family,order,mode);bundle=self.pack(p);actual=self.actual(p);r=b.compare(bundle,actual)
                        self.assertTrue(r['full_match'],r);self.assertEqual(r['classification'],'matched');self.assertTrue(r['property_reproduced'])

    def test_bundle_can_move_without_original_source_directory(self):
        p=self.fixture();bundle=self.pack(p);moved=self.base/'moved';shutil.move(bundle['_directory'],moved)
        shutil.rmtree(p)
        loaded=b.load_bundle(moved/'bundle.json');self.assertEqual(loaded['bundle_id'],bundle['bundle_id'])

    def test_binding_needs_original_ledger_and_hit(self):
        p=self.fixture();ledger=b._read(p.parent/'ledger.json');ledger['attempts'][0]['outcome']='miss';save(p.parent/'ledger.json',ledger)
        with self.assertRaises(ValueError):self.pack(p)
        self.assertFalse((p.parent/'bundle').exists())

    def test_matching_source_cannot_be_a_replay_or_unsupported_mode(self):
        p=self.fixture();task=b._read(p/'task.json');task['operation']='replay.run';save(p/'task.json',task)
        with self.assertRaises(ValueError):self.pack(p)

    def test_overwrite_is_rejected(self):
        p=self.fixture();self.pack(p)
        with self.assertRaises(ValueError):self.pack(p)

    def test_changed_raw_or_mapping_hash_is_rejected(self):
        for name in ('reference/guest/trace/A.words','reference/source-map.jsonl'):
            p=self.fixture();bundle=self.pack(p);file=Path(bundle['_directory'])/name;file.write_text(file.read_text()+'\n')
            with self.assertRaises(ValueError):b.load_bundle(bundle['_directory'])

    def test_rehashed_signature_or_policy_cannot_change_match_conditions(self):
        for name in ('signature','policy'):
            p=self.fixture();bundle=self.pack(p);root=Path(bundle['_directory']);record=b._read(root/'bundle.json')
            if name=='signature':
                signature=b._read(root/'signature.json');signature['control']={};save(root/'signature.json',signature);record['artifacts']['signature.json']=b._sha(root/'signature.json');record['signature_sha256']=c.fingerprint(signature)
            else:record['policy']['phase_comparison']='ignore values';record['policy_sha256']=c.fingerprint(record['policy'])
            record['bundle_id']=c.fingerprint({k:v for k,v in record.items() if k!='bundle_id'});save(root/'bundle.json',record)
            with self.assertRaises(ValueError):b.load_bundle(root)

    def test_path_traversal_and_missing_artifact_rejected(self):
        p=self.fixture();bundle=self.pack(p);root=Path(bundle['_directory']);record=b._read(root/'bundle.json');record['artifacts']['../outside']='0'*64;record['bundle_id']=c.fingerprint({k:v for k,v in record.items() if k!='bundle_id'});save(root/'bundle.json',record)
        with self.assertRaises(ValueError):b.load_bundle(root)

    def test_archive_playback_is_not_a_new_execution(self):
        p=self.fixture();r=b.compare(self.pack(p),p);self.assertFalse(r['full_match']);self.assertTrue(r['property_reproduced']);self.assertFalse(r['checks']['new_run_id'])

    def test_original_executor_identity_is_not_only_old_k08_bridge(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p);identity=b._read(actual/'runtime-identity.json');identity['binaries']['kcov-execute-k09-ab']='f'*64;save(actual/'runtime-identity.json',identity);self.reanalyze(actual)
        r=b.compare(bundle,actual);self.assertFalse(r['full_match']);self.assertFalse(r['checks']['original_complete_build'])

    def test_same_error_and_k09_hit_with_changed_suffix_is_path_diverged(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p)
        self.edit_events(actual,'B',lambda rows:rows[-1]['stack'][0].update(parent_idx=9))
        r=b.compare(bundle,actual);self.assertTrue(r['checks']['original_k09_match']);self.assertTrue(r['property_reproduced']);self.assertFalse(r['full_match']);self.assertIn('critical_paths',r['differences'])

    def test_k09_prefix_miss_cannot_count_full_match(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p)
        self.edit_events(actual,'A',lambda rows:rows[0]['stack'][0].update(parent_idx=9))
        r=b.compare(bundle,actual);self.assertFalse(r['checks']['original_k09_match']);self.assertFalse(r['full_match'])

    def test_dynamic_addresses_values_clocks_not_used_as_stored_rhs(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p)
        def change(rows):
            for e in rows:
                if e['kind']=='MEMORY':e.update(address='0xffff800000009000',value='0x0000000000009999',timestamp='0x0000000000000033')
        self.edit_events(actual,'A',change);r=b.compare(bundle,actual);self.assertTrue(r['full_match'],r)

    def test_unknown_memory_mapping_is_not_silently_excluded(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p);rows=[json.loads(x) for x in (actual/'source-map.jsonl').read_text().splitlines()];rows[0]['found']=False;(actual/'source-map.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows));self.reanalyze(actual)
        r=b.compare(bundle,actual);self.assertFalse(r['full_match'])

    def test_saved_analysis_claim_cannot_override_evidence(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p);a=b._read(actual/'analysis.json');a['prefix_matches']=False;save(actual/'analysis.json',a)
        r=b.compare(bundle,actual);self.assertFalse(r['full_match']);self.assertTrue(r['errors'])

    def test_missing_actual_artifact_preserved_as_invalid(self):
        p=self.fixture();bundle=self.pack(p);actual=self.actual(p);(actual/'guest/trace/A.events.jsonl').unlink()
        r=b.compare(bundle,actual);self.assertFalse(r['full_match']);self.assertEqual(r['classification'],'invalid');self.assertTrue(r['errors'])

    def test_epoch_values_and_fds_are_not_normalized_away(self):
        self.assertEqual(b._normalize_pids({'pid':200,'caller_tid':201,'kernel_pid':0,'epoch':200,'fd':200,'value':201},{200:'A',201:'B'}),{'pid':'logical-thread:A','caller_tid':'logical-thread:B','kernel_pid':0,'epoch':200,'fd':200,'value':201})

if __name__=='__main__':unittest.main()

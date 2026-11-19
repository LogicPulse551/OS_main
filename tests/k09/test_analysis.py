"""Synthetic matching boundaries; real KCOV decoding is an external acceptance check."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from kconc import candidates as c, search_queue as q

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

analysis=load('k09_test_analysis',REPO/'adapters/maccconc/k09_analysis.py')
fixtures=load('k09_sample_fixtures',REPO/'tests/k08/test_analysis.py')

class AnalysisTests(unittest.TestCase):
    def fixture(self,family='rmw',order='ab',case=None,mode=None):
        helper=fixtures.AnalysisTests();self.addCleanup(helper.doCleanups)
        f=helper.fixture(family,order,case,mode);report=helper.result(f)
        self.assertTrue(report['passed'],report)
        entry=c.get_input(c.load_catalog(),family,f.phases[0]['case_id'],f.phases[0]['mode'])
        source=dict(trace_path=str(f.trace),analysis_sha256=c.fingerprint(report),trace_sha256={n:report['artifacts'][n] for n in c.TRACE_FILES})
        f.candidate=c.make_candidate(entry,{'synthetic_build':'f'*64},c.observed_initial_state(report),report,source)
        (f.trace/'plan.txt').write_bytes(q.make_plan(f.candidate))
        f.meta.update(sequential_A_B=False,plan_loaded_from_file=True,sampling_only=False,k09_schema_version=1,
            candidate_execution_requested=True,requested_candidate_executions=1,candidate_pattern='A-B-A' if order=='ab' else 'B-A-B')
        at=next(i for i,e in enumerate(f.events['A']) if e['ip']==f.ips[2])
        f.events['A'][at:at]=[dict(kind=k,record_type=r,flagidx=b,timed_out=False,thread='A') for k,r,b in [('WAKE','0x5000000000000000',0),('WAIT','0x4000000000000000',1)]]
        first,peer=(0,1) if order=='ab' else (1,0)
        if family=='rmw':
            initial,ops=entry['initial'],entry['operations']
            values=analysis.k06.oracle.apply_update(initial,ops[peer])
            if entry['mode']=='split':
                for r in (0,1):
                    after=analysis.k06.oracle.apply_update(initial,ops[r])
                    f.phases[2]['results'][r].update(before=initial[ops[r]['reg']],after=after[ops[r]['reg']])
                values[ops[first]['reg']]=f.phases[2]['results'][first]['after']
            else:values=analysis.k06.oracle.apply_update(values,ops[first])
            allowed=analysis.k06.oracle.evaluate(initial,ops,values)['allowed']
            f.phases[3].update(values=values,allowed=allowed,natural_passed=allowed);f.sync_slots()
        else:
            ops,final=fixtures.mutex_fixture.observed(entry['case_id'],entry['mode'],'overlap' if entry['mode']=='per-role' else 'busy')
            if order=='ba':
                ops.reverse();final['roles'].reverse()
                for e in final['events'][:final['event_count']]:e['role']=1-e['role']
                for r,row in enumerate(ops):
                    row.update(entry['operations'][r]);row['result'].update(reg=entry['operations'][r]['reg'],gate_id=0 if entry['mode']=='shared' else r+1)
                    final['roles'][r]=copy.deepcopy(row['result'])
                final['values']=[0,0,0,0]
                for r,row in enumerate(ops):
                    if row['result']['outcome']==1:final['values'][row['reg']]|=row['value']
            f.phases[2]['results']=ops;f.phases[3].update(final=final,allowed=entry['mode']=='shared')
            if entry['mode']=='shared':
                e=copy.deepcopy(f.events['B'][1]);ip='0xffffffff81858999'
                f.mapping[ip]=dict(f.mapping[f.ips[0]],raw_ip=ip,lookup_ip=f'0x{int(ip,16)-1:016x}',file='/linux/drivers/base/regmap/kconc-regmap.c',symbol='kconc_operation',line=319)
                e['ip']=ip;e['stack'][-1]['ip']=ip;f.events['B']=[e]
        f.write(True)
        return f

    def result(self,f):return analysis.analyze(f.trace,f.mapping,f.guest,f.candidate)

    def test_all_28_directions_and_properties(self):
        for entry in c.load_catalog()['inputs']:
            for order in ('ab','ba'):
                with self.subTest(entry=entry['input_id'],order=order):
                    f=self.fixture(entry['family'],order,entry['case_id'],entry['mode']);r=self.result(f)
                    self.assertEqual(r['classification'],'hit',r);self.assertTrue(r['property_evaluated']);self.assertFalse(r['recovery_required'])
                    expected=(entry['family']=='mutex' and entry['mode']=='per-role') or (entry['family']=='rmw' and entry['mode']=='split' and (entry['case_id'] in ('disjoint-bits','high-bits') or entry['case_id']=='zero-mask' and order=='ab'))
                    self.assertEqual(r['property_violation'],expected)

    def test_control_hit_with_prefix_mismatch_is_miss_not_property_witness(self):
        f=self.fixture();f.events['A'][0]['stack'][0]['ip']='0xffffffff81858001';f.write(True);r=self.result(f)
        self.assertTrue(r['control_valid']);self.assertTrue(r['observed_property']['allowed'] is False)
        self.assertEqual(r['classification'],'miss',r);self.assertFalse(r['property_evaluated']);self.assertFalse(r['recovery_required'])

    def test_only_three_dynamic_fields_excluded(self):
        f=self.fixture()
        for e in f.events['A']:
            if e['kind']=='MEMORY':e.update(address='0xffff800000009999',value='0x0000000000000042',timestamp='0x0000000000000044')
        f.write(True);self.assertEqual(self.result(f)['classification'],'hit')
        for key,value in [('flags',273),('size',8)]:
            f=self.fixture();f.events['A'][0][key]=value;f.write(True)
            self.assertFalse(self.result(f)['candidate_hit'])

    def test_target_stack_occurrence_cannot_be_substituted(self):
        f=self.fixture();f.events['A'][4]['stack'][0]['parent_idx']=9;f.write(True)
        self.assertFalse(self.result(f)['candidate_hit'])

    def test_timeout_stays_in_denominator_and_requires_recovery(self):
        f=self.fixture();f.events['A'][3]['timed_out']=True;f.meta['control_valid']=False
        f.guest.update(outcome='execution_failed',exit_code=2);f.write(True);r=self.result(f)
        self.assertEqual(r['classification'],'timeout',r);self.assertFalse(r['property_evaluated']);self.assertTrue(r['recovery_required'])

    def test_actual_input_and_initial_snapshot_must_match_candidate(self):
        f=self.fixture();f.phases[1]['epoch']=2;f.write(True);self.assertFalse(self.result(f)['candidate_hit'])

    def test_logical_tid_and_callback_binding(self):
        for key,value in [('slot_tids',{'A':201,'B':200}),('roles',{'A':'test_thread1','B':'test_thread2'})]:
            f=self.fixture(order='ba');f.meta[key]=value;f.write(True);self.assertFalse(self.result(f)['candidate_hit'])

    def test_wrong_phase_value_cannot_be_explained_by_structural_match(self):
        f=self.fixture();f.phases[2]['results'][1]['before']=1;f.phases[2]['results'][1]['after']=3
        f.sync_slots();f.write(True);r=self.result(f)
        self.assertFalse(r['schedule_valid']);self.assertFalse(r['property_evaluated'])

    def test_cleanup_failure_is_not_clean_miss(self):
        f=self.fixture();f.guest['remaining_pids']=[123];r=self.result(f)
        self.assertFalse(r['passed']);self.assertTrue(r['recovery_required'])

    def test_inconsistent_native_stats_rejected(self):
        f=self.fixture();f.meta['A']['events']+=1;(f.trace/'run.json').write_text(json.dumps(f.meta))
        self.assertFalse(self.result(f)['execution_valid'])

    def test_missing_trace_or_bad_candidate_does_not_crash(self):
        f=self.fixture();(f.trace/'run.json').unlink();self.assertFalse(self.result(f)['passed'])
        f.candidate['candidate_id']='0'*64;self.assertFalse(self.result(f)['passed'])

    def test_phase_and_supervisor_disagreement_rejected(self):
        f=self.fixture();f.guest['phases']=copy.deepcopy(f.phases);f.guest['phases'][3]['values'][0]=3
        self.assertFalse(self.result(f)['execution_valid'])

if __name__=='__main__':unittest.main()

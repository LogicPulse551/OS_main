"""Synthetic exports test rejection logic; they are not real kernel traces."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from test_oracle import observed,idle,round_fixture

spec=importlib.util.spec_from_file_location('k07_analysis',Path(__file__).resolve().parents[2]/'adapters/maccconc/k07_analysis.py')
analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)

class AnalysisTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='k07-analysis-');self.addCleanup(t.cleanup);self.base=Path(t.name);self.trace=self.base/'trace';self.trace.mkdir()
        self.ips=['0xffffffff81858010','0xffffffff81858020','0xffffffff81858030','0xffffffff81858040','0xffffffff81858050']
        sources=[('drivers/base/regmap/kconc-regmap.c','kconc_regmap_checkpoint',analysis.marker_source()['line']),('drivers/base/regmap/regmap.c','regmap_update_bits_base',3333),('drivers/base/regmap/regmap-ram.c','regmap_ram_read',33),('drivers/base/regmap/regmap-ram.c','regmap_ram_write',23),('drivers/base/regmap/kconc-regmap.c','kconc_operation',300)]
        self.mapping={ip:dict(found=True,raw_ip=ip,lookup_ip=f'0x{int(ip,16)-1:016x}',file='/linux/'+f,symbol=s,line=l,exact_line=True,mapping_kind='exact_line') for ip,(f,s,l) in zip(self.ips,sources)}
        self.events={role:[dict(kind='MEMORY',record_type='0x3000000000000000',thread=role,ip=ip,address=f'0x{0xffff800000001000+40*idx+4*i:016x}',size=4,flags=0x110 if i in (0,3) else 0x100,value='0x0000000000000000',timestamp='0x0000000000000001',stack=[dict(ip='0xffffffff81858000',parent_idx=0),dict(ip=ip,parent_idx=i+1)]) for i,ip in enumerate(self.ips[:4])] for idx,role in enumerate(('A','B'))}
        self.meta=dict(schema_version=1,roles={'A':'test_thread1','B':'test_thread2'},sequential_A_B=True,plan_loaded_from_file=False,spin_limit=1000000,child_status=0,child_ok=True,a_done=True,b_done=True,overflow=False,raw_words_well_formed=True,control_valid=True,safe_to_continue=True,buffer_words=1000)
        for key in ('gate0','a_completed_wake0','b_completed_wake1','reset'):self.meta[key]=dict(called=True,rc=0,errno=0)
        self.case='different-registers';self.mode='shared';self.set_phases('A-B')
        self.write()
    def set_phases(self,pattern):
        spec=analysis.oracle.case_spec(self.case);ops,final=observed(self.case,self.mode,pattern)
        allowed=final['max_depth']<=1
        self.phases=[dict(phase='setup',passed=True,case_id=self.case,mode=self.mode,**spec,reset=dict(abi=3,flags=0,epoch=1,initial=spec['initial'],reserved=0),reset_rc=0,errno=0,fd=5,epoch=1,initial_fds=[0,1,2,3,4],fault='none',injected=False),
            dict(phase='initial_state',passed=True,status_rc=0,initial=idle(1),fd_set_matches=True,expected_fds=[0,1,2,3,4,5],actual_fds=[0,1,2,3,4,5]),
            dict(phase='operations',passed=True,a_calls=1,b_calls=1,results=ops),
            dict(phase='property',passed=True,infrastructure_valid=True,oracle=analysis.oracle.ORACLE,allowed=allowed,final=final,status_rc=0,injected=False,caller_misuse_example=True,kernel_bug_claim=False),
            dict(phase='teardown',passed=True,ioctl_rc=0,errno=0,close_rc=0,resources_closed=True,fd_set_restored=True,fd_snapshot_observed=True,expected_fds=[0,1,2,3,4],actual_fds=[0,1,2,3,4],empty=idle(2,0),post_control_progress=round_fixture(self.case,self.mode,'B-A',2))]
        self.guest=dict(schema_version=1,kind='kconc.guest',outcome='completed',exit_code=0,remaining_pids=[],local_cleanup=dict(confirmed=True,errors=[]),phase_errors=[],fault='none',phases=self.phases)
    def controlled(self):
        binding=analysis.make_plan(self.trace,self.mapping,self.base/'binding');(self.trace/'plan.txt').write_bytes(Path(binding['plan_path']).read_bytes())
        self.meta.update(sequential_A_B=False,plan_loaded_from_file=True)
        self.events['A'][0:0]=[dict(kind=k,record_type=r,flagidx=b,timed_out=False,thread='A') for k,r,b in [('WAKE','0x5000000000000000',0),('WAIT','0x4000000000000000',1)]]
        self.set_phases('overlap' if self.mode=='per-role' else 'busy')
        if self.mode=='shared':
            event=copy.deepcopy(self.events['B'][1]);event['ip']=self.ips[4];event['stack'][-1]['ip']=self.ips[4];self.events['B']=[event]
        self.write(True)
    def write(self,replay=False):
        target=next(e['stack'] for e in self.events['A'] if e.get('ip')==self.ips[0]) if replay else None
        for role,rows in self.events.items():
            offset=0
            for e in rows:e['word_index']=offset;offset+=analysis.k03._WIDTH[e['kind']]
            self.meta[role+'_words']=offset;self.meta[role]=analysis.k03._stats(rows,target if role=='A' else None)
            (self.trace/(role+'.events.jsonl')).write_text(''.join(json.dumps(e)+'\n' for e in rows));(self.trace/(role+'.words')).write_text('0000000000000000\n'*offset)
        (self.trace/'run.json').write_text(json.dumps(self.meta));(self.trace/'testcase.stdout.txt').write_text(''.join('KCONC_PHASE '+json.dumps(r)+'\n' for r in self.phases))
    def result(self,replay=False):return analysis.analyze(self.trace,self.mapping,self.guest,replay)
    def test_sequential_real_component_evidence(self):self.assertTrue(self.result()['passed'],self.result())
    def test_per_role_overlap_is_valid_detection(self):
        self.mode='per-role';self.set_phases('A-B');self.write();self.controlled();r=self.result(True)
        self.assertTrue(r['passed'],r);self.assertTrue(r['property_violation']);self.assertEqual(r['property']['observed_registers'],[1,2,0,0])
    def test_shared_busy_is_valid_controlled_result(self):
        self.controlled();r=self.result(True);self.assertTrue(r['passed'],r);self.assertFalse(r['property_violation']);self.assertEqual(r['property']['busy_roles'],[1])
    def test_busy_cannot_execute_real_regmap(self):
        self.controlled();self.events['B'][0]['ip']=self.ips[1];self.write(True);self.assertFalse(self.result(True)['passed'])
    def test_marker_is_before_regmap(self):
        self.events['A'][0],self.events['A'][1]=self.events['A'][1],self.events['A'][0];self.write();self.assertFalse(self.result()['passed'])
    def test_marker_line_size_flags_and_exact_mapping(self):
        for value in (0,analysis.marker_source()['line']-1):
            self.mapping[self.ips[0]]['line']=value;self.assertFalse(self.result()['passed'])
    def test_duplicate_marker_not_accepted(self):
        self.events['A'].append(copy.deepcopy(self.events['A'][0]));self.write();self.assertFalse(self.result()['passed'])
    def test_source_return_address_off_by_one(self):
        self.mapping[self.ips[0]]['lookup_ip']=self.ips[0];self.assertFalse(self.result()['passed'])
    def test_invalid_control_never_counts_overlap(self):
        self.mode='per-role';self.set_phases('A-B');self.write();self.controlled();self.events['A'][1]['timed_out']=True;self.write(True);r=self.result(True)
        self.assertFalse(r['passed']);self.assertFalse(r['property_evaluated']);self.assertFalse(r['property_violation'])
    def test_missing_observation_rejected_not_crashed(self):
        self.phases[2]['results'].pop();self.write();self.assertFalse(self.result()['passed'])
    def test_native_allowed_cannot_hide_overlap(self):
        self.mode='per-role';self.set_phases('A-B');self.write();self.controlled();self.phases[3]['allowed']=True;self.write(True);self.assertFalse(self.result(True)['passed'])
    def test_progress_epoch_is_distinct(self):
        self.phases[4]['post_control_progress']['reset']['epoch']=1;self.write();self.assertFalse(self.result()['passed'])
    def test_progress_may_reuse_a_tid_after_frozen_trace_boundary(self):
        self.phases[4]['post_control_progress']=round_fixture(self.case,self.mode,'B-A',2,tid=200)
        self.write();self.assertTrue(self.result()['passed'],self.result())
    def test_progress_wrong_case_rejected(self):
        self.phases[4]['post_control_progress']=round_fixture('shared-register',self.mode,'B-A',2);self.write();self.assertFalse(self.result()['passed'])
    def test_cleanup_failed_fd_or_locked_gate_rejected(self):
        self.phases[4]['empty']['gates_locked']=1;self.write();self.assertFalse(self.result()['passed'])
    def test_mismatched_raw_and_supervised_phases_rejected(self):
        self.guest['phases']=copy.deepcopy(self.phases);self.guest['phases'][3]['allowed']=False;self.assertFalse(self.result()['passed'])
    def test_marker_plan_bound_to_case_mode_and_sources(self):
        b=analysis.make_plan(self.trace,self.mapping,self.base/'binding');self.assertEqual(b['scenario'],'regmap-mutex-v1');self.assertEqual(b['case_id'],self.case);self.assertEqual(b['mode'],self.mode);self.assertEqual(len(b['oracle_sha256']),64);self.assertFalse(b['runtime_identity_bound'])
    def test_plan_output_not_overwritten(self):
        out=self.base/'binding';out.mkdir()
        with self.assertRaises(FileExistsError):analysis.make_plan(self.trace,self.mapping,out)
    def test_same_pid_for_two_logical_threads_rejected(self):
        self.phases[2]['results'][1]['caller_tid']=200;self.phases[2]['results'][1]['result']['pid']=200;self.phases[3]['final']['roles'][1]['pid']=200;self.write();self.assertFalse(self.result()['passed'])

if __name__=='__main__':unittest.main()

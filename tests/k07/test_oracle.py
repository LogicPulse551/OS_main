"""Independent protocol examples; fixtures are not real-kernel evidence."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from kconc import mutex_oracle as oracle

def idle(epoch,state=1,values=None):
    return dict(abi=3,epoch=epoch,state=state,active=0,completed_mask=0,snapshot_valid=1,
        values=list(values or [0,0,0,0]),roles=[dict.fromkeys(oracle.ROLE_FIELDS,0) for _ in range(2)],
        event_count=0,in_cs=0,max_depth=0,gates_locked=0,events=[dict.fromkeys(oracle.EVENT_FIELDS,0) for _ in range(4)])

def observed(case='different-registers',mode='shared',pattern='A-B',epoch=1,tids=(200,201)):
    patterns={'A-B':[(0,1,1),(0,2,0),(1,1,1),(1,2,0)],'B-A':[(1,1,1),(1,2,0),(0,1,1),(0,2,0)],
        'overlap':[(0,1,1),(1,1,2),(1,2,1),(0,2,0)],'busy':[(0,1,1),(1,3,1),(0,2,0)]}
    events=[dict(seq=i+1,role=r,kind=k,depth=d) for i,(r,k,d) in enumerate(patterns[pattern])]
    spec=oracle.case_spec(case);status=idle(epoch);status.update(completed_mask=3,event_count=len(events),max_depth=max(x['depth'] for x in events),events=events+[dict.fromkeys(oracle.EVENT_FIELDS,0)]*(4-len(events)))
    operations=[]
    for role in (0,1):
        e={x['kind']:x for x in events if x['role']==role};entered=1 in e;declared=spec['operations'][role]
        result=dict(pid=tids[role],checkpoint=epoch if entered else 0,preempt_count=0,irqs_disabled=0,reg=declared['reg'],started=1,completed=1,status=0 if entered else -16,mode=oracle.MODES[mode],gate_id=0 if mode=='shared' else role+1,acquired=int(entered),outcome=1 if entered else 2,enter_seq=e[1]['seq'] if entered else 0,enter_depth=e[1]['depth'] if entered else 0,exit_seq=e[2]['seq'] if entered else 0,exit_depth=e[2]['depth'] if entered else 0,busy_seq=0 if entered else e[3]['seq'],busy_depth=0 if entered else e[3]['depth'],api_calls=int(entered),released=int(entered))
        operations.append(dict(declared,abi=3,epoch=epoch,mode=oracle.MODES[mode],reserved=0,caller_tid=tids[role],rc=0 if entered else -1,errno=0 if entered else 16,result=result))
        status['roles'][role]=copy.deepcopy(result)
        if entered:status['values'][declared['reg']]|=declared['value']
    return operations,status

def round_fixture(case='different-registers',mode='shared',order='A-B',epoch=1,tid=999,index=0):
    spec=oracle.case_spec(case);ops,final=observed(case,mode,order,epoch,(tid,tid))
    if order=='B-A':ops.reverse()
    return dict(round=index,inputs=dict(case_id=case,**spec),mode=mode,order=order,caller_tid=tid,
        reset=dict(abi=3,flags=0,initial=spec['initial'],epoch=epoch,reserved=0),reset_rc=0,reset_errno=0,initial_rc=0,initial_passed=True,initial=idle(epoch,values=spec['initial']),operations=ops,final_rc=0,final=final,allowed=True,passed=True)

def matrix_fixture():
    rows=[]
    for case in oracle.CASES:
        for mode in oracle.MODES:
            for order in ('A-B','B-A'):rows.append(round_fixture(case,mode,order,len(rows)+1,index=len(rows)))
    return dict(schema_version=1,kind='kconc.mutex-matrix',requested_rounds=8,completed_rounds=8,caller_tid=999,rounds=rows,
        teardown_rc=0,close_rc=0,teardown=idle(8,0),resources_closed=True,passed=True,kernel_bug_claim=False,caller_misuse_example=True)

class OracleTests(unittest.TestCase):
    def test_sequential_ab_ba_allowed(self):
        for case in oracle.CASES:
            for mode in oracle.MODES:
                for order in ('A-B','B-A'):
                    ops,status=observed(case,mode,order)
                    self.assertTrue(oracle.check_observation(case,mode,ops,status,1)['allowed'])
    def test_real_property_independent_of_correct_register_final(self):
        ops,status=observed(mode='per-role',pattern='overlap')
        verdict=oracle.check_observation('different-registers','per-role',ops,status,1)
        self.assertFalse(verdict['allowed']);self.assertEqual(status['values'],[1,2,0,0]);self.assertEqual(verdict['max_depth'],2)
    def test_shared_busy_is_valid_but_never_entered(self):
        ops,status=observed(pattern='busy');v=oracle.check_observation('different-registers','shared',ops,status,1)
        self.assertTrue(v['allowed']);self.assertEqual(v['busy_roles'],[1]);self.assertEqual(status['values'],[1,0,0,0])
    def test_busy_may_be_logged_after_owner_exits(self):
        ops,status=observed(pattern='busy')
        status['events'][:3]=[dict(seq=1,role=0,kind=1,depth=1),dict(seq=2,role=0,kind=2,depth=0),dict(seq=3,role=1,kind=3,depth=0)]
        ops[0]['result']['exit_seq']=2;status['roles'][0]['exit_seq']=2
        ops[1]['result'].update(busy_seq=3,busy_depth=0);status['roles'][1].update(busy_seq=3,busy_depth=0)
        self.assertTrue(oracle.check_observation('different-registers','shared',ops,status,1)['allowed'])
    def test_shared_register_correct_value_can_overlap(self):
        ops,status=observed('shared-register','per-role','overlap')
        self.assertFalse(oracle.check_observation('shared-register','per-role',ops,status,1)['allowed']);self.assertEqual(status['values'],[3,0,0,0])
    def test_wrong_depth_or_sequence_rejected(self):
        for key,value in [('depth',0),('seq',2),('kind',9),('role',True)]:
            _,s=observed();s['events'][0][key]=value
            with self.assertRaises(ValueError):oracle.evaluate(s['events'],s['event_count'])
    def test_exit_before_enter_rejected(self):
        _,s=observed();s['events'][0]['kind']=2
        with self.assertRaises(ValueError):oracle.evaluate(s['events'],4)
    def test_incomplete_interval_rejected(self):
        _,s=observed();s['events'][3]=dict.fromkeys(oracle.EVENT_FIELDS,0)
        with self.assertRaises(ValueError):oracle.evaluate(s['events'],3)
    def test_unused_slot_must_be_zero(self):
        _,s=observed(pattern='busy');s['events'][3]['depth']=1
        with self.assertRaises(ValueError):oracle.evaluate(s['events'],3)
    def test_duplicate_enter_rejected(self):
        _,s=observed(mode='per-role',pattern='overlap');s['events'][1]['role']=0
        with self.assertRaises(ValueError):oracle.evaluate(s['events'],4)
    def test_busy_does_not_get_implicit_success(self):
        ops,s=observed(pattern='busy');ops[1]['rc']=0
        with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_busy_must_have_no_api_or_marker(self):
        for key,value in [('api_calls',1),('checkpoint',1),('acquired',1)]:
            ops,s=observed(pattern='busy');ops[1]['result'][key]=value;s['roles'][1][key]=value
            with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_final_snapshot_is_checked_separately(self):
        for key,value in [('gates_locked',1),('in_cs',1),('max_depth',2),('active',1),('snapshot_valid',False)]:
            ops,s=observed();s[key]=value
            with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_status_and_ioctl_cannot_disagree(self):
        ops,s=observed();s['roles'][0]['pid']=55
        with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_unrelated_register_corruption_is_invalid_execution(self):
        ops,s=observed();s['values'][3]=77
        with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_input_boolean_alias_rejected(self):
        ops,s=observed();ops[0]['mask']=True
        with self.assertRaises(ValueError):oracle.check_observation('different-registers','shared',ops,s,1)
    def test_case_unknown_or_changed_rejected(self):
        for case in ('unknown',[]):
            with self.assertRaises(ValueError):oracle.case_spec(case)
        spec=oracle.case_spec('different-registers');spec['operations'][0]['mask']=2
        with self.assertRaises(ValueError):oracle.validate_case('different-registers','shared',**spec)

class ClientTests(unittest.TestCase):
    def setUp(self):self.record=matrix_fixture()
    def test_complete_matrix(self):
        v=oracle.validate_client(self.record);self.assertTrue(v['passed'],v);self.assertEqual(len(v['verdicts']),8)
    def test_missing_rows_rejected(self):
        self.record['rounds'].pop();self.assertFalse(oracle.validate_client(self.record)['passed'])
    def test_wrong_case_order_mode_rejected(self):
        self.record['rounds'][0],self.record['rounds'][1]=self.record['rounds'][1],self.record['rounds'][0]
        self.assertFalse(oracle.validate_client(self.record)['passed'])
    def test_bad_reset_epoch_rejected(self):
        self.record['rounds'][1]['reset']['epoch']=1;self.assertFalse(oracle.validate_client(self.record)['passed'])
    def test_false_native_verdict_cannot_hide_boundary(self):
        self.record['rounds'][0]['final']['events'][0]['depth']=2;self.assertFalse(oracle.validate_client(self.record)['passed'])
    def test_final_cleanup_observations_not_flags_only(self):
        self.record['teardown']['event_count']=1;self.assertFalse(oracle.validate_client(self.record)['passed'])
    def test_missing_structure_is_failed_not_exception(self):
        for r in (None,{},dict(rounds=[None]),dict(rounds=[{}]*8)):
            self.assertFalse(oracle.validate_client(r)['passed'])

if __name__=='__main__':unittest.main()

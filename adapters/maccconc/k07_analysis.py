"""K07 evidence checks for the declared nonblocking critical region.

The control marker holds the tested sleeping mutex, but no observer or regmap
spinlock. The peer uses trylock. A controlled wait timeout is never a deadlock
or a mutual-exclusion witness. Observer boundaries, not KCOV clocks or final
register values, determine interval overlap.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
k03=module('k07_k03',Path(__file__).with_name('k03_analysis.py'))
oracle=module('k07_oracle',REPO/'src/kconc/mutex_oracle.py')
PHASES=('setup','initial_state','operations','property','teardown')
DRIVER=REPO/'kernel/k07/kconc-regmap.c'
MARKER_FILE='drivers/base/regmap/kconc-regmap.c'
MARKER_SYMBOL='kconc_regmap_checkpoint'
SCOPE='Constructed caller lock-domain misuse on real regmap; fixed nonblocking contract, not upstream bug discovery, general search or K10 stability'

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def _pairs(rows):
    result={}
    for key,value in rows:
        if key in result:raise ValueError('Duplicate evidence key: '+key)
        result[key]=value
    return result
def _json(text):
    def constant(value):raise ValueError('Non-finite evidence value: '+value)
    return json.loads(text,object_pairs_hook=_pairs,parse_constant=constant)
def _object(value):
    result=_json(Path(value).read_text()) if isinstance(value,(str,Path)) else value
    if not isinstance(result,dict):raise ValueError('Expected evidence object')
    return result
def _int(value,minimum=0,maximum=0xffffffff):return type(value) is int and minimum<=value<=maximum
def _eq(value,expected):return type(value) is int and value==expected
def _fds(value):return type(value) is list and all(_int(x) for x in value) and value==sorted(set(value))
def _source_ends(value,suffix):
    text=value.replace('\\','/');return text==suffix or text.endswith('/'+suffix)
def marker_source():
    lines=DRIVER.read_text().splitlines()
    found=[number for number,line in enumerate(lines,1) if 'WRITE_ONCE(role->checkpoint, epoch);' in line]
    if len(found)!=1:raise ValueError('Expected one declared marker store')
    return dict(file=MARKER_FILE,symbol=MARKER_SYMBOL,line=found[0],source_sha256=digest(DRIVER),context='Tested sleeping mutex held; observer/regmap spinlocks released, peer trylock is nonblocking')
def read_mapping(value):
    if isinstance(value,(str,Path)):
        path=Path(value);mapping={}
        for line in path.read_text().splitlines():
            if not line.strip():continue
            row=_json(line)
            if not isinstance(row,dict) or row.get('raw_ip') in mapping:raise ValueError('Invalid/duplicate source mapping')
            mapping[row.get('raw_ip')]=row
        return mapping,dict(path=str(path),sha256=digest(path))
    if not isinstance(value,dict):raise ValueError('Mapping must be a path or dictionary')
    return value,dict(canonical_sha256=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest())
def read_phases(trace):
    rows=[_json(line[len('KCONC_PHASE '):]) for line in (Path(trace)/'testcase.stdout.txt').read_text().splitlines() if line.startswith('KCONC_PHASE ')]
    if any(not isinstance(x,dict) for x in rows) or tuple(x.get('phase') for x in rows)!=PHASES or any(type(x.get('passed')) is not bool for x in rows):raise ValueError('Expected five ordered lifecycle phases')
    return rows

def phase_checks(rows, *, observation_checker=None, round_validator=None):
    setup,initial,operations,prop,teardown=rows
    case,mode=setup.get('case_id'),setup.get('mode');spec=oracle.case_spec(case);epoch=setup.get('epoch')
    oracle.validate_case(case,mode,setup.get('initial'),setup.get('operations'))
    oracle.require(_int(epoch,1),'Invalid setup epoch');oracle.check_reset(setup.get('reset'),spec,epoch)
    oracle.check_idle(initial.get('initial'),epoch,1,spec['initial'])
    observation_checker = oracle.check_observation if observation_checker is None else observation_checker
    round_validator = oracle.validate_round if round_validator is None else round_validator
    result=observation_checker(case,mode,operations.get('results'),prop.get('final'),epoch)
    calls=operations['results']
    progress=round_validator(teardown.get('post_control_progress'),case,mode,'B-A',epoch+1)
    oracle.check_idle(teardown.get('empty'),epoch+1,0,[0,0,0,0])
    startfds=setup.get('initial_fds');expected_fds=sorted(startfds+[setup['fd']]) if _fds(startfds) and _int(setup.get('fd')) else None
    return {'initial':{
        'setup_passed':setup['passed'],'setup_not_injected':setup.get('fault')=='none' and setup.get('injected') is False,
        'reset_succeeded':_eq(setup.get('reset_rc'),0) and _eq(setup.get('errno'),0),
        'device_fd':_int(setup.get('fd')) and _fds(startfds) and setup['fd'] not in startfds,
        'initial_passed':initial['passed'],'initial_status_succeeded':_eq(initial.get('status_rc'),0),
        'fd_set':initial.get('fd_set_matches') is True and _fds(initial.get('actual_fds')) and initial.get('actual_fds')==initial.get('expected_fds')==expected_fds,
        'initial_and_reset_observations_valid':True},
        'threads':{'operations_passed':operations['passed'],'once_per_role':_eq(operations.get('a_calls'),1) and _eq(operations.get('b_calls'),1),
            'logical_role_order':[x['role'] for x in calls]==[0,1], 'distinct_traced_callers':calls[0]['caller_tid']!=calls[1]['caller_tid'],
            'returned_roles_and_intervals_valid':True},
        'property':{'execution_passed':prop['passed'],'infrastructure_valid':prop.get('infrastructure_valid') is True,
            'oracle':prop.get('oracle')==oracle.ORACLE,'native_verdict_matches':prop.get('allowed') is result['allowed'],
            'not_injected':prop.get('injected') is False,'not_kernel_bug_claim':prop.get('kernel_bug_claim') is False,
            'caller_misuse_example':prop.get('caller_misuse_example') is True,'status_succeeded':_eq(prop.get('status_rc'),0)},
        # The executor saves each cover_n at its callback boundary, then calls
        # test_end on A's thread. A reused TID does not extend the saved trace.
        'post_control':{'separate_epoch_sequential_progress':progress['allowed']},
        'cleanup':{'passed':teardown['passed'],'teardown_succeeded':_eq(teardown.get('ioctl_rc'),0) and _eq(teardown.get('errno'),0),
            'closed':_eq(teardown.get('close_rc'),0) and teardown.get('resources_closed') is True,
            'fd_observed':teardown.get('fd_set_restored') is True and teardown.get('fd_snapshot_observed') is True,
            'fd_set_restored':_fds(teardown.get('actual_fds')) and teardown.get('actual_fds')==teardown.get('expected_fds')==startfds,
            'empty_object_and_logs':True}}

def schedule_checks(rows,replay):
    final=rows[3]['final'];events=final['events'][:final['event_count']]
    protocol=[(e['role'],e['kind'],e['depth']) for e in events]
    b_entered=rows[2]['results'][1]['result']['outcome']==1
    expected=([(0,1,1),(1,1,2),(1,2,1),(0,2,0)] if b_entered else [(0,1,1),(1,3,1),(0,2,0)]) if replay else [(0,1,1),(0,2,0),(1,1,1),(1,2,0)]
    return {'actual_boundary_order_matches_declared_protocol':protocol==expected}

def inspect_trace(trace,mapping,replay,entered, *, declared_marker=None):
    trace=Path(trace);metadata=_object(trace/'run.json');events={role:k03.read_events(trace,role) for role in ('A','B')}
    raw={role:k03._raw_consistency(trace,role,events[role],metadata) for role in events}
    checks={'raw':{'schema':_eq(metadata.get('schema_version'),1),'roles':metadata.get('roles')=={'A':'test_thread1','B':'test_thread2'},
        'no_overflow':metadata.get('overflow') is False,'well_formed':metadata.get('raw_words_well_formed') is True,
        **{role+'_raw_valid':x['valid'] for role,x in raw.items()}},'sequence':{},'control':{}}
    checks['raw']['strict_flags']=all(type(metadata.get(key)) is bool for key in ('sequential_A_B','plan_loaded_from_file','child_ok','a_done','b_done','overflow','raw_words_well_formed','control_valid','safe_to_continue'))
    for role in events:
        stats=metadata.get(role);checks['raw'][role+'_strict_stats']=isinstance(stats,dict) and bool(stats) and all(_int(v,0,0xffffffffffffffff) for v in stats.values())
    if replay:
        plan=k03.read_plan(trace/'plan.txt');checks['control']=k03._control_checks(metadata,events,plan)
        checks['control']['loaded_saved_plan']=metadata.get('plan_loaded_from_file') is True
        checks['sequence']['not_sequential']=metadata.get('sequential_A_B') is False
    else:
        checks['sequence']={'sequential_A_B':metadata.get('sequential_A_B') is True,'not_replay':metadata.get('plan_loaded_from_file') is False,
            'declared_valid':metadata.get('control_valid') is True,'safe_to_continue':metadata.get('safe_to_continue') is True,
            'child_zero':metadata.get('child_ok') is True and _eq(metadata.get('child_status'),0),
            'both_finished':metadata.get('a_done') is True and metadata.get('b_done') is True,
            **{key+'_succeeded':k03._call_ok(metadata,key) for key in ('gate0','a_completed_wake0','b_completed_wake1','reset')}}
        for role,rows in events.items():
            stats=k03._stats(rows,None);checks['sequence'][role+'_memory']=stats['memory_records']>0
            checks['sequence'][role+'_no_handoff']=stats['waits']==stats['wakes']==stats['timeouts']==0
            checks['sequence'][role+'_stats_match']=metadata.get(role)==stats
        checks['control']['not_requested_in_baseline']=True
    declared=marker_source() if declared_marker is None else declared_marker
    mapped={};markers={};projections={};marker_checks={}
    for index,role in enumerate(('A','B')):
        projection=[]
        for event in events[role]:
            if event['kind']!='MEMORY':continue
            source=k03._mapping(event['ip'],mapping)
            if source.get('raw_ip')!=event['ip'] or int(source.get('lookup_ip','0'),16)!=int(event['ip'],16)-1:raise ValueError('Source map does not bind raw return IP minus one')
            projection.append(dict(event=event,source=source))
        projections[role]=projection
        core=[x for x in projection if _source_ends(x['source']['file'],'drivers/base/regmap/regmap.c')]
        bus=[x for x in projection if _source_ends(x['source']['file'],'drivers/base/regmap/regmap-ram.c')]
        candidates=[x for x in projection if _source_ends(x['source']['file'],declared['file']) and x['source']['symbol']==declared['symbol'] and x['source']['line']==declared['line'] and x['source']['exact_line'] is True and x['event']['size']==4 and (x['event']['flags']&0x1f)==0x10 and not(x['event']['flags']&0x20)]
        markers[role]=candidates
        if entered[index]:
            mapped[role+'_locked_update_api']=any(x['source']['symbol']=='regmap_update_bits_base' for x in core)
            for operation in ('read','write'):mapped[role+'_real_ram_'+operation]=any(x['source']['symbol']=='regmap_ram_'+operation for x in bus)
            marker_checks[role+'_unique_declared_store']=len(candidates)==1
            if len(candidates)==1:
                marker_checks[role+'_marker_before_real_api']=bool(core and bus) and all(x['event']['word_index']>candidates[0]['event']['word_index'] for x in core+bus)
        else:
            mapped[role+'_busy_performs_no_regmap']=not core and not bus
            marker_checks[role+'_busy_has_no_marker']=not candidates
    if entered==[True,True] and all(len(markers[r])==1 for r in ('A','B')):marker_checks['distinct_role_storage']=markers['A'][0]['event']['address']!=markers['B'][0]['event']['address']
    if replay:marker_checks['plan_names_declared_A_store']=len(markers['A'])==1 and plan['stack']==markers['A'][0]['event']['stack']
    checks['mapping']=mapped;checks['marker']=marker_checks
    return checks,dict(raw=raw,markers=markers,projection=projections,marker_source=declared,
        write_value_semantics='KCOV pre-access snapshot; not the stored value or a reads-from proof',
        boundary_order_semantics='Short observer lock orders enter/exit/busy only; it is released during marker and real API')

def analyze(trace,mapping,guest,replay=False):
    trace=Path(trace);sections={};rows=None
    result=dict(schema_version=1,kind='kconc.mutex.analysis',passed=False,replay=replay,checks={},groups={},errors=[],observations={},artifacts={},scope=SCOPE)
    try:
        rows=read_phases(trace);result['observations']['phases']=rows;sections.update(phase_checks(rows))
        setup=rows[0];result['observations'].update(case_id=setup['case_id'],mode=setup['mode'])
        result['property']=oracle.check_observation(setup['case_id'],setup['mode'],rows[2]['results'],rows[3]['final'],setup['epoch'])
        sections['schedule_outcome']=schedule_checks(rows,replay)
    except (OSError,ValueError,KeyError,TypeError,IndexError) as error:
        result['errors'].append('phases: '+str(error));sections['phase_evidence']={'valid':False}
    try:
        entered=[x['result']['outcome']==1 for x in rows[2]['results']]
        if len(entered)!=2:raise ValueError('Two role admissions required for trace checking')
        source_map,map_record=read_mapping(mapping);result['artifacts']['source_map']=map_record
        traced,observed=inspect_trace(trace,source_map,replay,entered);sections.update(traced);result['observations'].update(observed)
    except (OSError,ValueError,KeyError,TypeError,IndexError) as error:
        result['errors'].append('trace: '+str(error));sections['trace_evidence']={'valid':False}
    try:
        guest=_object(guest);cleanup=guest.get('local_cleanup',{})
        sections['supervisor']={'schema':_eq(guest.get('schema_version'),1) and guest.get('kind')=='kconc.guest',
            'completed':guest.get('outcome')=='completed' and _eq(guest.get('exit_code'),0),
            'no_remaining_processes':type(guest.get('remaining_pids')) is list and guest['remaining_pids']==[],
            'cleanup':isinstance(cleanup,dict) and cleanup.get('confirmed') is True and cleanup.get('errors')==[],
            'phase_errors_absent':guest.get('phase_errors')==[],'phases_match':rows is not None and guest.get('phases')==rows,
            'not_fault_injection':guest.get('fault')=='none'}
    except (OSError,ValueError,KeyError,TypeError) as error:
        result['errors'].append('supervisor: '+str(error));sections['supervisor']={'valid':False}
    for group,checks in sections.items():
        result['groups'][group]=bool(checks) and all(x is True for x in checks.values())
        result['checks'].update({group+'.'+k:v is True for k,v in checks.items()})
    for name in ('run.json','testcase.stdout.txt','A.words','B.words','A.events.jsonl','B.events.jsonl','plan.txt'):
        if (trace/name).is_file():result['artifacts'][name]=digest(trace/name)
    result['passed']=bool(result['checks']) and all(result['checks'].values()) and not result['errors']
    result['execution_valid']=result['passed'];result['control_valid']=all(result['groups'].get(g) is True for g in ('raw','sequence','control','marker'))
    result['property_evaluated']=result['passed'] and 'property' in result
    result['property_violation']=result['property_evaluated'] and result['property']['allowed'] is False
    return result

def make_plan(trace,mapping,out):
    trace,out=Path(trace),Path(out);source_map,map_record=read_mapping(mapping);rows=read_phases(trace)
    checks=phase_checks(rows);traced,observations=inspect_trace(trace,source_map,False,[True,True]);checks.update(traced);checks['schedule_outcome']=schedule_checks(rows,False)
    failed=[g+'.'+k for g,values in checks.items() for k,v in values.items() if v is not True]
    if failed:raise ValueError('Cannot bind invalid baseline: '+', '.join(failed))
    marker=observations['markers']['A'][0];stack=marker['event']['stack']
    if not 2<=len(stack)<=32 or any(int(x['ip'],16)<0xffffffff80000000 for x in stack):raise ValueError('Observed marker stack outside executor format')
    text='MACCCONC_K03_PLAN_V1\nspin_limit 1000000\nrole A\ncount '+str(len(stack))+'\n'+''.join(x['ip'][2:]+' '+str(x['parent_idx'])+'\n' for x in stack)
    out.mkdir(parents=True,exist_ok=False);(out/'plan.txt').write_text(text,encoding='ascii');plan=k03.read_plan(out/'plan.txt')
    binding=dict(schema_version=1,kind='kconc.mutex.marker-binding',scenario='regmap-mutex-v1',case_id=rows[0]['case_id'],mode=rows[0]['mode'],plan_path=str(out/'plan.txt'),binding_path=str(out/'binding.json'),plan_sha256=plan['sha256'],source_map=map_record,marker=marker,marker_source=observations['marker_source'],
        trace_sha256={n:digest(trace/n) for n in ('run.json','testcase.stdout.txt','A.words','B.words','A.events.jsonl','B.events.jsonl')},analysis_sha256=digest(Path(__file__)),k03_analysis_sha256=digest(Path(__file__).with_name('k03_analysis.py')),oracle_sha256=digest(REPO/'src/kconc/mutex_oracle.py'),runtime_identity_bound=False,scope='One observed mutex-held marker for a nonblocking peer; caller must bind the exact runtime identity')
    (out/'binding.json').write_text(json.dumps(binding,indent=2)+'\n');return binding

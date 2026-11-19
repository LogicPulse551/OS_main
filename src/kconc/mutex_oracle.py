"""K07 interval oracle for the declared nonblocking regmap critical region.

Observer events describe boundaries, not a whole-kernel event order. Final
register values are checked separately and never decide mutual exclusion.
"""
from __future__ import annotations

U32 = 0xffffffff
MODES = {'shared': 0, 'per-role': 1}
ORACLE = 'regmap-critical-region'
CASES = {
    'different-registers': ([0, 0, 0, 0], [(0, 1, 1), (1, 2, 2)]),
    'shared-register': ([0, 0, 0, 0], [(0, 1, 1), (0, 2, 2)]),
}
ROLE_FIELDS = ('pid', 'checkpoint', 'preempt_count', 'irqs_disabled', 'reg', 'started',
    'completed', 'status', 'mode', 'gate_id', 'acquired', 'outcome', 'enter_seq',
    'enter_depth', 'exit_seq', 'exit_depth', 'busy_seq', 'busy_depth', 'api_calls', 'released')
EVENT_FIELDS = ('seq', 'role', 'kind', 'depth')


def uint(value, maximum=U32):
    return type(value) is int and 0 <= value <= maximum


def eq(value, expected):
    return type(value) is int and value == expected


def require(condition, message):
    if not condition:
        raise ValueError(message)


def vector(value):
    return type(value) is list and len(value) == 4 and all(uint(x) for x in value)


def case_spec(case_id):
    require(type(case_id) is str and case_id in CASES, 'Unknown K07 case')
    initial, operations = CASES[case_id]
    return {'initial': list(initial), 'operations': [dict(role=i, reg=r, mask=m, value=v)
        for i, (r, m, v) in enumerate(operations)]}


def validate_case(case_id, mode, initial, operations):
    require(type(mode) is str and mode in MODES, 'Unknown K07 mode')
    require(vector(initial), 'Initial values must be four uint32 registers')
    require(type(operations) is list and len(operations) == 2, 'Two logical inputs required')
    for role, op in enumerate(operations):
        require(isinstance(op, dict) and set(op) == {'role','reg','mask','value'}, 'Malformed operation input')
        require(eq(op['role'], role) and uint(op['reg'], 3) and uint(op['mask']) and uint(op['value']), 'Invalid input integer or logical role')
    require(dict(initial=initial, operations=operations) == case_spec(case_id), 'Input differs from bound case')


def evaluate(events, event_count):
    """Independently scan complete observer boundaries; reject malformed logs."""
    require(uint(event_count, 4) and event_count >= 2, 'Invalid event count')
    require(type(events) is list and len(events) == 4, 'Expected four fixed event slots')
    active, seen, intervals, overlaps, busy = set(), {}, {}, [], []
    maximum = 0
    for index, event in enumerate(events):
        require(isinstance(event, dict) and set(event) == set(EVENT_FIELDS), 'Malformed event slot')
        require(all(uint(v) for v in event.values()), 'Event fields must be uint32, not bool')
        if index >= event_count:
            require(all(v == 0 for v in event.values()), 'Nonzero unused event slot')
            continue
        seq, role, kind, depth = (event[x] for x in EVENT_FIELDS)
        require(seq == index + 1 and role in (0, 1) and kind in (1, 2, 3), 'Noncontiguous sequence or unknown role/kind')
        if kind == 1:
            require(role not in seen, 'Role entered twice or entered after busy')
            seen[role] = 'entered'; active.add(role); intervals[role] = {'role': role, 'enter_seq': seq}
        elif kind == 2:
            require(role in active and seen.get(role) == 'entered', 'Exit without active entry')
            active.remove(role); seen[role] = 'exited'; intervals[role]['exit_seq'] = seq
        else:
            require(role not in seen and role not in active, 'Busy after entry or duplicate busy')
            seen[role] = 'busy'; busy.append(role)
        require(depth == len(active), 'Observer depth differs from reconstructed occupancy')
        maximum = max(maximum, len(active))
        if len(active) > 1:
            overlaps.append({'after_seq': seq, 'roles': sorted(active)})
    require(not active and set(seen) == {0, 1} and all(x in ('exited','busy') for x in seen.values()), 'Incomplete critical intervals')
    return {'oracle': ORACLE, 'allowed': not overlaps, 'max_depth': maximum, 'final_depth': 0,
        'intervals': [intervals[r] for r in sorted(intervals)], 'busy_roles': busy, 'overlaps': overlaps,
        'events': [dict(x) for x in events[:event_count]],
        'error_type': 'mutual-exclusion-violation' if overlaps else None,
        'scope': 'Declared test critical region; not all kernel locks or a whole-machine total order'}


def check_reset(reset, spec, epoch):
    require(isinstance(reset, dict), 'Missing reset observation')
    for key, value in dict(abi=3, flags=0, epoch=epoch, reserved=0).items():
        require(eq(reset.get(key), value), 'Reset differs: '+key)
    require(vector(reset.get('initial')) and reset['initial'] == spec['initial'], 'Reset initial state differs')


def check_idle(status, epoch, state, values):
    require(isinstance(status, dict), 'Missing idle status')
    for key, value in dict(abi=3, epoch=epoch, state=state, active=0, completed_mask=0,
                          snapshot_valid=1, event_count=0, in_cs=0, max_depth=0, gates_locked=0).items():
        require(eq(status.get(key), value), 'Idle state differs: '+key)
    require(vector(status.get('values')) and status['values'] == values, 'Idle register values differ')
    slots = status.get('roles')
    require(type(slots) is list and len(slots) == 2, 'Idle roles absent')
    require(all(isinstance(s, dict) and set(s) == set(ROLE_FIELDS) and all(eq(s[k], 0) for k in ROLE_FIELDS) for s in slots), 'Idle roles not zero')
    events = status.get('events')
    require(type(events) is list and len(events) == 4, 'Idle events absent')
    require(all(isinstance(e, dict) and set(e) == set(EVENT_FIELDS) and all(eq(e[k], 0) for k in EVENT_FIELDS) for e in events), 'Idle events not zero')


def check_observation(case_id, mode, operations, final, epoch, caller_tid=None, *, effective_shared_gate=False):
    """Check actual operations/status, then return the separate property verdict."""
    require(type(effective_shared_gate) is bool, 'Invalid effective lock profile')
    spec = case_spec(case_id); validate_case(case_id, mode, spec['initial'], spec['operations'])
    require(uint(epoch) and epoch > 0, 'Invalid epoch')
    require(isinstance(final, dict), 'Missing final status')
    for key, value in dict(abi=3, epoch=epoch, state=1, active=0, completed_mask=3, snapshot_valid=1, in_cs=0, gates_locked=0).items():
        require(eq(final.get(key), value), 'Final status differs: '+key)
    verdict = evaluate(final.get('events'), final.get('event_count'))
    require(eq(final.get('max_depth'), verdict['max_depth']), 'Maximum depth disagrees with intervals')
    require(type(operations) is list and len(operations) == 2 and all(isinstance(x,dict) for x in operations), 'Two operation observations required')
    require(all(uint(x.get('role'), 1) for x in operations) and {x['role'] for x in operations} == {0,1}, 'Logical role identities missing/duplicated')
    require(type(final.get('roles')) is list and len(final['roles']) == 2, 'Final role slots absent')
    values = list(spec['initial']); results = {}
    for op in operations:
        role = op['role']; declared = spec['operations'][role]; result = op.get('result'); results[role] = result
        for key,value in dict(declared, abi=3, epoch=epoch, mode=MODES[mode], reserved=0).items():
            require(eq(op.get(key),value), 'Operation input differs: '+key)
        require(uint(op.get('caller_tid'), 0x7fffffff) and op['caller_tid'] > 0, 'Missing caller tid')
        if caller_tid is not None: require(eq(op['caller_tid'], caller_tid), 'Sequential caller tid differs')
        require(isinstance(result,dict) and set(result) == set(ROLE_FIELDS), 'Malformed returned role')
        require(all(type(v) is int for v in result.values()), 'Returned role fields must be integer')
        require(final['roles'][role] == result and all(type(v) is int for v in final['roles'][role].values()), 'Returned role differs from final status')
        by_kind = {e['kind']:e for e in verdict['events'] if e['role'] == role}
        entered = 1 in by_kind
        expected = dict(pid=op['caller_tid'], checkpoint=epoch if entered else 0, preempt_count=0, irqs_disabled=0,
            reg=declared['reg'], started=1, completed=1, status=0 if entered else -16, mode=MODES[mode],
            gate_id=0 if mode=='shared' or effective_shared_gate else role+1, acquired=int(entered), outcome=1 if entered else 2,
            enter_seq=by_kind[1]['seq'] if entered else 0, enter_depth=by_kind[1]['depth'] if entered else 0,
            exit_seq=by_kind[2]['seq'] if entered else 0, exit_depth=by_kind[2]['depth'] if entered else 0,
            busy_seq=0 if entered else by_kind[3]['seq'], busy_depth=0 if entered else by_kind[3]['depth'],
            api_calls=int(entered), released=int(entered))
        require(result == expected, 'Returned role disagrees with interval/API protocol')
        require(eq(op.get('rc'), 0 if entered else -1) and eq(op.get('errno'), 0 if entered else 16), 'ioctl result does not match admission outcome')
        if not entered:
            # trylock failure precedes the BUSY observer event. The winner may
            # cross its EXIT boundary before BUSY is logged, so depth may be 0.
            # The fixed replay's tighter A-enter/B-busy/A-exit order is checked
            # separately by the control analyzer, not assumed by this oracle.
            require(mode == 'shared' or effective_shared_gate, 'Private role gate unexpectedly busy')
        else:
            reg,mask,value = (declared[k] for k in ('reg','mask','value'))
            values[reg] = (values[reg] & (U32 ^ mask)) | (value & mask)
    require(vector(final.get('values')) and final['values'] == values, 'Actual regmap results differ from admitted operations')
    verdict.update(observed_registers=list(final['values']), expected_registers=values)
    return verdict


def validate_round(row, case_id, mode, order, epoch, caller_tid=None, *, effective_shared_gate=False):
    require(isinstance(row,dict), 'Missing sequential round')
    spec=case_spec(case_id); inputs=row.get('inputs')
    require(isinstance(inputs,dict), 'Missing declared inputs')
    validate_case(inputs.get('case_id'), row.get('mode'), inputs.get('initial'), inputs.get('operations'))
    require(inputs['case_id']==case_id and row['mode']==mode and row.get('order')==order, 'Sequential case/mode/order differs')
    require(row.get('passed') is True and row.get('initial_passed') is True, 'Sequential native checks failed')
    for key in ('reset_rc','reset_errno','initial_rc','final_rc'):require(eq(row.get(key),0),'Sequential call failed: '+key)
    check_reset(row.get('reset'),spec,epoch);check_idle(row.get('initial'),epoch,1,spec['initial'])
    tid=row.get('caller_tid');require(uint(tid,0x7fffffff) and tid>0,'Sequential caller tid missing')
    if caller_tid is not None:require(eq(tid,caller_tid),'Sequential owner differs')
    verdict=check_observation(case_id,mode,row.get('operations'),row.get('final'),epoch,tid,effective_shared_gate=effective_shared_gate)
    roles=(0,1) if order=='A-B' else (1,0)
    require([x['role'] for x in row['operations']]==list(roles),'Operation order differs')
    require([(e['role'],e['kind'],e['depth']) for e in verdict['events']]==[(roles[0],1,1),(roles[0],2,0),(roles[1],1,1),(roles[1],2,0)],'Sequential boundary log is not serialized')
    require(verdict['allowed'] and row.get('allowed') is True,'Sequential mutual exclusion falsely failed')
    return verdict


def validate_client(record):
    checks, verdicts = {}, []
    def check(name, action):
        try: action();checks[name]=True
        except (ValueError,TypeError,KeyError,IndexError): checks[name]=False
    if not isinstance(record,dict):record={}
    check('header',lambda:require(eq(record.get('schema_version'),1) and record.get('kind')=='kconc.mutex-matrix' and record.get('passed') is True and record.get('kernel_bug_claim') is False and record.get('caller_misuse_example') is True,'Invalid matrix header'))
    check('round_count',lambda:require(eq(record.get('requested_rounds'),8) and eq(record.get('completed_rounds'),8) and type(record.get('rounds')) is list and len(record['rounds'])==8,'Invalid matrix count'))
    tid=record.get('caller_tid');check('caller',lambda:require(uint(tid,0x7fffffff) and tid>0,'Invalid caller'))
    rounds=record.get('rounds') if type(record.get('rounds')) is list else []
    for index,(case,mode,order) in enumerate((c,m,o) for c in CASES for m in MODES for o in ('A-B','B-A')):
        def validate(index=index,case=case,mode=mode,order=order):
            row=rounds[index];require(isinstance(row,dict),'Missing sequential row');require(eq(row.get('round'),index),'Round number differs')
            verdicts.append(dict(round=index,case_id=case,mode=mode,order=order,**validate_round(row,case,mode,order,index+1,tid)))
        check('round'+str(index),validate)
    def teardown():
        require(eq(record.get('teardown_rc'),0) and eq(record.get('close_rc'),0) and record.get('resources_closed') is True,'Teardown failed')
        check_idle(record.get('teardown'),8,0,[0,0,0,0])
    check('teardown',teardown)
    return dict(passed=all(checks.values()),checks=checks,errors=[k for k,v in checks.items() if not v],verdicts=verdicts,
        scope='Eight sequential controls on one resettable object; not concurrent replay acceptance')

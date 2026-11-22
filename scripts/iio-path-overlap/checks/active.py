"""Recount one cold boot of the case-local software SPI readiness experiment."""
import argparse
from copy import deepcopy
import csv
from dataclasses import asdict, replace
import json
from pathlib import Path
import re

import inspect_overlap as obs


def control_receipt(control, first, peer):
    expected={'owner_axis':first['axis'],'owner_key':first['key'],'owner_tid':first['tid'],
              'peer_axis':peer['axis'],'peer_key':peer['key'],'peer_tid':peer['tid'],
              'state_before':0,'state_armed':1,'state_observed':2,'state_after':3,
              'owner_exit':0,'peer_exit':0}
    if any(control.get(key)!=str(val) for key,val in expected.items()):
        return False
    # This registered fake controller prepares the *submitting* reader's message.
    # A worker receipt without a message cookie would need separate association.
    if int(control['callback_tid'])!=first['spi']['submit'].tid:
        return False
    ts=[int(control[k]) for k in ('arm_ns','warming_seen_ns','peer_started_ns','joined_ns')]
    return all(0<a<b for a,b in zip(ts,ts[1:]))


def event_rows(first,peer):
    return [first['spi']['submit'],peer['entry'],first['spi']['start'],first['spi']['done']]


def normal_result(op, expected):
    return (all(op[key]==expected[key] for key in ('axis','regmap','size','rc','value','payload')) and
            op['spi']['length']==expected['spi']['length'])


def evaluate(first,peer,control):
    timed=obs.window(first,peer)
    controlled=control_receipt(control,first,peer)
    return {'window_matched':timed,'controller_matched':controlled,
            'readouts_matched':first['normal'] and peer['normal'],
            'passed':timed and controlled and first['normal'] and peer['normal']}


def inspect(args):
    slot=args.capture
    pkg=obs.js(args.package); cert=obs.js(args.reference); ref=obs.js(args.natural)
    obs.check(ref['phase']=='passive' and ref['order']==args.order and ref['active_attempts']==0,
              'incorrect natural reference')
    meta=obs.load_ids(slot,pkg,cert)
    obs.check(meta['boot_id']!=ref['boot'],'boot reused')
    obs.check(meta['board_build_id']!=cert['identity']['board_build_id'],'original passive board loaded')
    plan=obs.js(slot/'plan.json')
    obs.check(plan['package_sha256']==obs.sha(args.package),'wrong package for launch')
    argv=plan['argv']; append=argv[argv.index('-append')+1].split()
    obs.check(('iio.mode='+plan['mode']) in append and meta['mode']==plan['mode']==pkg['pair']['guest_mode'],
              'wrong launch mode')
    obs.check(pkg['pair']['axis_order']==args.order and pkg['pair']['initrd_plan'] is True and
              meta['board_read_order']==args.order and meta['reader_exit']=='0','ordered actor plan mismatch')
    obs.check(pkg['observation']['registry_sha256']==obs.sha(args.reference),'wrong registered axes')
    payload={Path(path).name:sha for sha,path in
             (line.split() for line in (slot/'guest-payload.sha256').read_text().splitlines())}
    obs.check(payload=={Path(k).name:v for k,v in pkg['guest'].items() if k.startswith('payload/')}
              and payload.get('board.ko')==pkg['board_sha256'],'loaded board/reader/observer digest mismatch')
    events=obs.load_events(slot)
    natural_hit=obs.once([row for row in ref['pairs'] if row['strict_window']],'natural reference')
    symbols=set()
    for op in natural_hit['rows']:
        m=re.match(r'\((\w+)[+)]',op['entry']['detail'])
        obs.check(m is not None,'cannot bind driver symbol')
        symbols.add(m[1])
    symbol=obs.once(sorted(symbols),'same driver source symbol')
    obs.check(any(s.endswith('::'+symbol) for s in cert['common_driver_functions']),
              'driver symbol outside frozen discovery')
    reads=obs.axis_reads(slot,events,cert,symbol)
    obs.check(len(reads)==2,'expected exactly one cold read of each axis')
    ops=[]
    for axis in args.order:
        key=obs.once([k for k,v in reads.items() if v['axis']==axis],'single active operation for axis')
        op=reads[key]
        # Some boards serve the Nth X read from a changing frame. Require the
        # original first X/Y after startup for cold-slot data, not pair N's value.
        initial=next(v for v in ref['pairs'][0]['rows'] if v['axis']==axis)
        op.update(key=key,normal=normal_result(op,initial))
        ops.append(op)
    obs.check(ops[0]['tid']!=ops[1]['tid'],'thread identities alias')
    with (slot/'control.tsv').open() as f:
        control=obs.once(list(csv.DictReader(f,delimiter='\t')),'single controller receipt')
    capture_sha={name:d for d,name in (line.split() for line in (slot/'capture.sha256').read_text().splitlines())}
    obs.check(capture_sha.get('control.tsv')==obs.sha(slot/'control.tsv'),'missing guest control receipt hash')
    result=evaluate(*ops,control)
    result.update(order=args.order,boot_id=meta['boot_id'],kernel_build_id=meta['kernel_build_id'],
                  board_build_id=meta['board_build_id'],reference_boot=ref['boot'],
                  trace_sha256=obs.sha(slot/'trace.txt'),package_sha256=plan['package_sha256'],
                  four_events=[asdict(e) for e in event_rows(*ops)],control=control,
                  operations=[obs.compact(o) for o in ops])
    if args.negative:
        obs.check(result['passed'],'no positive reference for offline controls')
        # In-memory perturbations leave both return values and payloads untouched.
        first,peer=deepcopy(ops)
        peer['entry']=replace(peer['entry'],ns=first['spi']['start'].ns+1)
        timing=evaluate(first,peer,control)
        wrong=dict(control,callback_tid=str(ops[1]['tid']))
        attribution=evaluate(*ops,wrong)
        wrong_state=dict(control,state_observed='1')
        inactive=evaluate(*ops,wrong_state)
        result.update(negative=True,tests={'peer_entry_after_start':timing,
                      'callback_assigned_to_peer':attribution,'arming_without_claim':inactive},
                      passed=not any(x['passed'] for x in (timing,attribution,inactive)))
    return result


def main():
    p=argparse.ArgumentParser()
    for name in ('capture','package','natural','reference','out'):
        p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--order',choices=('XY','YX'),required=True)
    p.add_argument('--negative',action='store_true')
    args=p.parse_args()
    try:
        result=inspect(args)
    except (KeyError,ValueError,TypeError,OSError,IndexError,StopIteration) as error:
        result={'passed':False,'diagnostic':str(error),'order':args.order}
    obs.output(args.out,result)
    print(json.dumps({k:v for k,v in result.items() if k in
          ('passed','diagnostic','order','boot_id','window_matched','controller_matched','readouts_matched')}))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())

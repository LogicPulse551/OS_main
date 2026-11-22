"""Independent reader for the bounded normal IIO/SPI experiment."""
from dataclasses import dataclass, asdict
from decimal import Decimal
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import uuid


def check(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def js(path):
    return json.loads(path.read_bytes())


@dataclass(frozen=True)
class Event:
    line: int
    ns: int
    tid: int
    name: str
    detail: str


ROW = re.compile(r"-(\d+)\s+(?:\([^)]*\)\s+)?\[\s*\d+\].*? (\d+\.\d+): (\w+): (.*)$")
MARKER = re.compile(r"IIO_(BEGIN|END) key=([\w-]+) axis=([XY])(?: rc=(-?\d+) value=(-?\d+))?$")
SPI = re.compile(r"(\S+) ([\da-fA-F]+)(?: len=(\d+)/(\d+))?$")


def note_id(path):
    data=path.read_bytes()
    offset=0
    while offset+12<=len(data):
        n,d,t=struct.unpack_from('<III',data,offset)
        offset+=12
        name=data[offset:offset+n]
        offset+=(n+3)&~3
        val=data[offset:offset+d]
        offset+=(d+3)&~3
        if name==b'GNU\0' and t==3 and len(val)==20:
            return val.hex()
    raise ValueError(f'GNU note absent: {path}')


def load_events(slot):
    trace=(slot/'trace.txt').read_text()
    ring=re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)',trace)
    check(ring and ring[1]==ring[2] and 'LOST EVENTS' not in trace, 'trace records lost')
    drops=re.findall(r'^(?:overrun|commit overrun|dropped events):\s*(\d+)',(slot/'stats.txt').read_text(),re.M)
    check(drops and all(int(n)==0 for n in drops),'trace CPU loss counters absent or nonzero')
    events=[]
    for line_no,line in enumerate(trace.splitlines(),1):
        if not line.strip() or line.startswith('#'):
            continue
        fields=ROW.search(line)
        check(fields is not None, f'cannot decode trace line {line_no}')
        tid,time,name,detail=fields.groups()
        events.append(Event(line_no,int(Decimal(time)*10**9),int(tid),name,detail))
    check(len(events)==int(ring[1]),'trace count mismatch')
    return events


def load_ids(slot,package,cert):
    meta=js(slot/'build.json')
    check(js(slot/'capture-result.json')['passed'] is True,'unsuccessful capture')
    keys=('kernel_build_id','board_build_id','kernel_sha256','board_sha256','config_sha256','vmlinux_sha256','initrd_sha256')
    check(all(meta.get(k)==package[k] for k in keys), 'package/guest identity mismatch')
    for key in ('kernel_build_id','config_sha256','vmlinux_sha256','kernel_sha256'):
        check(meta[key]==cert['identity'][key], 'original kernel reference mismatch')
    check(note_id(slot/'kernel.notes')==meta['kernel_build_id'] and
          note_id(slot/'board.notes')==meta['board_build_id'],'bad live kernel/board notes')
    boot=meta['boot_id']
    uuid.UUID(boot)
    serial=(slot/'serial.log').read_text()
    check(re.findall(r'^BOOT ([a-f\d-]{36})$',serial,re.M)==[boot] and
          re.search(r'^(?:IIO|K14)_SUPERVISOR_EXIT 0$',serial,re.M) and meta.get('cleaned')=='1','boot or cleanup mismatch')
    check(boot!=cert['training_boot_id'],'same boot as discovery')
    checks={}
    for line in (slot/'capture.sha256').read_text().splitlines():
        digest,name=line.split()
        check(Path(name).name==name and not name.startswith('.'),'invalid path in capture digest file')
        check(name not in checks and sha(slot/name)==digest,'artifact digest mismatch '+name)
        checks[name]=digest
    check({'trace.txt','ops.tsv','board.notes','kernel.notes','stats.txt','run.env'}<=checks.keys(),
          'capture digest list incomplete')
    return meta


def once(candidates, label):
    check(len(candidates)==1,f'{label}: expected 1, found {len(candidates)}')
    return candidates[0]


def strictly(*events):
    return all(a.line<b.line and a.ns<b.ns for a,b in zip(events,events[1:]))


def messages(events):
    # A cookie may be legitimately reused after completion. Pair within its single
    # outstanding lifetime; the controller worker can differ from the submitter.
    active={}
    completed=[]
    for e in events:
        if e.name not in ('spi_message_submit','spi_message_start','spi_message_done'):
            continue
        info=SPI.fullmatch(e.detail)
        check(info is not None,'malformed SPI event')
        dev,cookie,actual,want=info.groups()
        key=dev,cookie
        if e.name=='spi_message_submit':
            check(key not in active,'duplicate active message')
            active[key]={'dev':dev,'cookie':cookie,'submit':e}
        elif e.name=='spi_message_start':
            check(key in active and 'start' not in active[key],'unmatched message start')
            active[key]['start']=e
        else:
            m=active.pop(key,None)
            check(m and 'start' in m and actual and int(want)==int(actual)>0,'bad SPI completion')
            check(m['submit'].line<m['start'].line<e.line,'message order mismatch')
            m.update(done=e,length=int(actual))
            completed.append(m)
    check(not active,'incomplete SPI messages')
    return completed


def axis_reads(slot,events,cert,symbol):
    table={}
    for line in (slot/'ops.tsv').read_text().splitlines():
        key,axis,tid,bytes_read,err,value,count=line.split()
        check(key not in table and axis in ('X','Y') and int(bytes_read)>0 and int(err)==0 and
              int(count)>0 and (slot/(key+'.words')).stat().st_size==8*int(count),'incomplete normal read')
        table[key]=(axis,int(tid),int(bytes_read),int(value))
    by_key={}
    msgs=messages(events)
    used=set()
    for key,(axis,tid,size,value) in table.items():
        boundaries={}
        for e in events:
            if e.name!='tracing_mark_write':
                continue
            m=MARKER.fullmatch(e.detail)
            if m and m[2]==key:
                check(e.tid==tid and m[3]==axis and m[1] not in boundaries,'marker mismatch')
                boundaries[m[1]]=e
                if m[1]=='END':
                    check(int(m[4])==0 and int(m[5])==value,'return evidence mismatch')
        begin,end=boundaries['BEGIN'],boundaries['END']
        span=[e for e in events if e.tid==tid and begin.line<e.line<end.line]
        ent=once([e for e in span if e.name=='iio_learned_entry'],'driver entry')
        ret=once([e for e in span if e.name=='iio_learned_return'],'driver return')
        check(re.search(r'\('+re.escape(symbol)+r'(?:\+|\))',ent.detail) and
              ('<- '+symbol+')') in ret.detail,'driver symbol mismatch')
        m=once([msg for msg in msgs if msg['submit'].tid==tid and
                ent.line<msg['submit'].line<msg['done'].line<ret.line],'SPI message for axis')
        check(m['submit'].line not in used,'same SPI message assigned twice')
        used.add(m['submit'].line)
        reg=[e for e in span if e.name.startswith('regmap_')]
        geometry=[]
        for e in reg:
            check(e.detail.split()[0]==m['dev'],'regmap/SPI device mismatch')
            fields=dict(re.findall(r'\b(reg|register|count|len|length|bytes|nregs)=((?:0x)?[a-fA-F0-9]+)\b',e.detail))
            geometry.append([e.name,fields])
        recognized=[a for a,s in cert['signature'].items() if s['regmap']==geometry]
        check(recognized==[axis], 'original register signature mismatch '+key)
        check(ent.line<reg[0].line<m['submit'].line<m['done'].line<reg[-1].line<ret.line,
              'regmap and SPI span mismatch')
        payload=once([re.search(r'\bval=((?:[a-fA-F0-9]{2}\s*)+)$',e.detail)[1].strip()
                      for e in reg if re.search(r'\bval=((?:[a-fA-F0-9]{2}\s*)+)$',e.detail)],'register data')
        by_key[key]={'axis':axis,'tid':tid,'begin':begin,'end':end,'entry':ent,'return':ret,
                     'spi':m,'regmap':geometry,'payload':payload,'size':size,'rc':0,'value':value}
    check(len(used)==len(msgs), 'SPI messages outside recorded reads')
    stats=(slot/'probe-stats.txt').read_text()
    for ev in ('iio_learned_entry','iio_learned_return'):
        hit=once(re.findall(r'^\s*'+ev+r'\s+(\d+)\s+(\d+)\s*$',stats,re.M),ev+' counters')
        check(int(hit[0])==len(table) and int(hit[1])==0,'probe loss')
    return by_key


def window(first,second):
    m=first['spi']
    check(first['tid']!=second['tid'],'two operations share a thread')
    return strictly(m['submit'],second['entry'],m['start'],m['done'])


def compact(op):
    return {k:(asdict(v) if isinstance(v,Event) else v) for k,v in op.items() if k!='spi'} | {
        'spi':{k:(asdict(v) if isinstance(v,Event) else v) for k,v in op['spi'].items()}}


def natural(slot,package,cert,order):
    meta=load_ids(slot,package,cert)
    check(meta['mode']=='natural','wrong capture mode')
    events=load_events(slot)
    symbol=once(package['observation']['source_verification'],'source binding')['symbol']
    ops=axis_reads(slot,events,cert,symbol)
    groups=sorted({key[2:] for key in ops})
    rows=[]
    for n in groups:
        a,b=[ops['n'+axis.lower()+n] for axis in order]
        match=window(a,b)
        rows.append({'pair':n,'rows':[compact(a),compact(b)],'strict_window':match})
    return {'phase':'passive','boot':meta['boot_id'],'order':order,'pairs':rows,
            'strict_matches':sum(r['strict_window'] for r in rows),'examined':len(rows),
            'active_attempts':0,'trace_sha256':sha(slot/'trace.txt')}


def output(path,result):
    with path.open('x',encoding='utf-8') as f:
        json.dump(result,f,indent=2)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--package',type=Path,required=True)
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--order',choices=('XY','YX'),required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    output(a.out,natural(a.capture,js(a.package),js(a.reference),a.order))

"""Recompute one grant trace from kernel and tracefs records in one serial log."""
import argparse
import collections
import hashlib
import json
import re
import struct
import uuid
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def one(pattern, text):
    found = re.findall(pattern, text, re.M)
    require(len(found) == 1, f"expected one {pattern}, saw {len(found)}")
    return found[0]


def section(lines, name):
    start = [i for i,x in enumerate(lines) if x == name+"_BEGIN"]
    end = [i for i,x in enumerate(lines) if x == name+"_END"]
    require(len(start) == len(end) == 1 and start[0] < end[0], "invalid "+name+" section")
    return list(enumerate(lines[start[0]+1:end[0]],start[0]+2))


def note_id(text):
    blob = bytes.fromhex(text)
    pos = 0
    ids = []
    while pos + 12 <= len(blob):
        n, d, k = struct.unpack_from("<III", blob, pos)
        pos += 12
        name = blob[pos:pos+n]
        pos += (n+3)&~3
        value = blob[pos:pos+d]
        pos += (d+3)&~3
        require(len(name)==n and len(value)==d,"invalid ELF note extent")
        if name==b"GNU\0" and k==3 and d==20:
            ids.append(value.hex())
    require(len(ids)==1, "expected one GNU build ID note")
    return ids[0]


def parse_kernel(lines):
    events = []
    keys = {
        "BEGIN":"route wrong coord workers initial", "ROLE":"role tid", "WAIT":"role tid visits",
        "GRANT":"step issuer planned actual target", "TAKE":"step role tid visit",
        "DONE":"step role tid visit before after rc", "ACK":"step coord role tid rc",
        "END":"coord final rc","CLEAN":""}
    for number,line in lines:
        if "CENTRAL_" not in line:
            continue
        match=re.fullmatch(r"(?:<\d+>)?(?:\[\s*\d+\.\d+\]\s*)?CENTRAL_([A-Z]+)(?: (.*))?",line)
        require(match is not None, f"malformed dmesg record at {number}")
        tag, body=match.groups()
        fields={}
        for word in (body or "").split():
            k,sep,v=word.partition("=")
            require(sep and v and k not in fields,"invalid field in dmesg")
            fields[k]=int(v) if re.fullmatch(r"-?\d+",v) else v
        require(tag in keys and set(fields)==set(keys[tag].split()),f"wrong fields on {tag}")
        events.append(dict(fields,tag=tag,line=number))
    return events


def kernel_evidence(rows,expected,wrong):
    tags=[r['tag'] for r in rows]
    require(tags and tags[0]=="BEGIN" and tags[-2:]==["END","CLEAN"],"missing initialization, final read or teardown")
    require(tags.count("BEGIN")==tags.count("END")==tags.count("CLEAN")==1,"multiple lifecycle records")
    begin,end=rows[0],rows[-2]
    roles=set(expected)
    require((begin["route"],begin["wrong"],begin["workers"],begin["initial"])==(expected,int(wrong),len(roles),0),"plan/header differs")
    coord=begin['coord']
    role_rows=[r for r in rows if r['tag']=="ROLE"]
    tids={r['role']:r['tid'] for r in role_rows}
    require(set(tids)==roles and len(role_rows)==len(roles) and len(set(tids.values()))==len(roles),"worker identity count")
    require(coord>0 and coord not in tids.values() and min(tids.values())>0,"invalid coordinator or worker PID")
    operations=[r for r in rows if r['tag'] in ('GRANT','TAKE','DONE','ACK')]
    n=len(expected)
    require([r["tag"] for r in operations]==["GRANT","TAKE","DONE","ACK"]*n,"authorization, take, done, ack order")
    waits=[r for r in rows if r['tag']=='WAIT']
    grouped=collections.defaultdict(list)
    for w in waits:
        require(w['tid']==tids[w['role']],"WAIT is not from its worker")
        grouped[w['role']].append((w['visits'],w['line']))
    visits=collections.Counter()
    steps=[]
    value=0
    initial_grant=operations[0]['line']
    require(all(r['line']<initial_grant for r in role_rows),"role registered after first grant")
    for i in range(n):
        g,t,d,a=operations[i*4:i*4+4]
        require(all(r['step']==i for r in (g,t,d,a)),f"wrong authorization rank {i}")
        r=t['role']
        require(g['issuer']==coord and g['planned']==expected[i] and a['coord']==coord,"coordinator or intended grant differs")
        require(g['actual']==r==d['role']==a['role'] and
                g['target']==tids[r]==t['tid']==d['tid']==a['tid'],"grant recipient differs from actual worker")
        before=value;bit=1<<(ord(r)-ord('A'))
        visits[r]+=1
        value=(value|bit) if visits[r]==1 else (value&~bit)
        require((t['visit'],d['visit'],d['before'],d['after'],d['rc'],a['rc'])==
                (visits[r],visits[r],before,value,0,0),"wrong visit, register update or ack")
        steps.append(dict(step=i,planned=expected[i],role=r,tid=tids[r],visit=visits[r],before=before,after=value,
                          grant_line=g['line'],take_line=t['line'],done_line=d['line'],ack_line=a['line']))
    for r in roles:
        records=grouped[r]
        require([v for v,_ in records]==list(range(visits[r]+1)) and records[0][1]<initial_grant,"missing worker re-arm sequence")
        for s in (step for step in steps if step['role']==r):
            boundary=steps[s['step']+1]['grant_line'] if s['step']<n-1 else end['line']
            require(s['done_line']<records[s['visit']][1]<boundary,"worker did not return to wait before next grant")
    require(end['coord']==coord and end['final']==value and end['rc']==0,"independent final read differs")
    return coord,tids,steps,value


PREFIX=re.compile(r"^\s*(?P<comm>.+?)-(?P<pid>\d+)\s+(?:\([^)]*\)\s+)?\[(?P<cpu>\d+)\]\s+\S+\s+(?P<time>\d+\.\d+):\s+(?P<kind>\w+):\s*(?P<body>.+)$")


def trace_evidence(lines,coord,tids,steps,final):
    bus=[]; switches=[]; wakes=[]; waking=[]
    for number,line in lines:
        m=PREFIX.match(line)
        if not m:continue
        kind=m['kind'];body=m['body'];pid=int(m['pid'])
        if kind in ('regmap_reg_read','regmap_reg_write') and body.startswith('regmap_actors '):
            fields=re.fullmatch(r'regmap_actors reg=([\da-fA-F]+) val=([\da-fA-F]+)',body)
            require(fields and int(fields[1],16)==0,"wrong native register or malformed bus observation")
            bus.append((number,pid,'R' if kind.endswith('read') else 'W',int(fields[2],16)))
        elif kind=='sched_switch':
            f=re.search(r'prev_pid=(\d+).*?prev_state=(\S+)\s+==>.*?next_pid=(\d+)',body)
            if f:switches.append((number,int(f[1]),f[2],int(f[3])))
        elif kind in ('sched_waking','sched_wakeup'):
            f=re.search(r'\bpid=(\d+)\b',body)
            if f:(waking if kind=='sched_waking' else wakes).append((number,pid,int(f[1])))
    expected=[(coord,'R',0)]
    for s in steps:
        before,after=s['before'],s['after']
        expected.extend((s['tid'],k,v) for k,v in [('R',before),('R',before),('W',after),('R',after)])
    expected.append((coord,'R',final))
    require([b[1:] for b in bus]==expected,f"native regmap events differ: {bus!r}")
    for i,s in enumerate(steps):
        s['bus_lines']=[b[0] for b in bus[1+i*4:5+i*4]]
    ai=[i for i,s in enumerate(steps) if s['role']=='A']
    require(len(ai)==2 and ai[0]==0 and ai[1]>=2,"expected two visits from A separated by peer work")
    tid=tids['A']; b1=steps[ai[0]]['bus_lines'][-1];b2=steps[ai[1]]['bus_lines'][0]
    peer_end=steps[ai[1]-1]['bus_lines'][-1]
    candidates=[]
    thread_switches=[s for s in switches if s[1]==tid or s[3]==tid]
    for line,issuer,target in waking:
        if not (target==tid and issuer==coord and peer_end<line<b2):continue
        delivered=[(n,p) for n,p,t in wakes if t==tid and line<n<b2]
        if len(delivered)!=1:continue
        preceding=[s for s in thread_switches if b1<s[0]<line]
        following=[s for s in thread_switches if line<s[0]<b2]
        if not preceding or not following:continue
        slept=preceding[-1]; running=following[0]
        if slept[1]==tid and slept[2].startswith(('S','D')) and running[3]==tid and delivered[0][0]<running[0]:
            candidates.append((slept,line,delivered[0],running))
    require(len(candidates)==1,f"missing or ambiguous A switch-out / coordinator sched_waking / target sched_wakeup / A-switch-in sequence ({len(candidates)}), sched_switch={len(switches)} sched_waking={len(waking)} sched_wakeup={len(wakes)}")
    out,wake,(delivered_line,delivered_context),back=candidates[0]
    peers=[s['role'] for s in steps[1:ai[1]] if out[0]<s['bus_lines'][0] and s['bus_lines'][-1]<wake]
    if [s['role'] for s in steps]==list('ABCA'):
        require('C' in peers, "C did not finish its bus reads and write during the observed A sleep")
    between_wakes = {}
    for i,s in enumerate(steps):
        lower=steps[i-1]['bus_lines'][-1] if i else bus[0][0]
        lines_for_role=[n for n,from_pid,to_pid in waking if lower < n < s['bus_lines'][0]
                        and from_pid==coord and to_pid==s['tid']]
        between_wakes[str(i)] = lines_for_role
    return {"count":len(bus),"initial_line":bus[0][0],"final_line":bus[-1][0]},dict(
        tid=tid,state=out[2],switched_out_line=out[0],wake_issuer=coord,waking_line=wake,
        wakeup_line=delivered_line,wakeup_context_tid=delivered_context,
        switched_in_line=back[0],next_A_step=ai[1],seen=steps[ai[1]]['before'],fully_enclosed_peer_visits=peers,
        coordinator_wakes_before_each_visit=between_wakes)


def parse(path,case):
    raw=Path(path).read_bytes(); text=re.sub(r'\x1b\[[\d;]*m','',raw.decode('utf8',errors='replace')).replace('\r','')
    lines=text.splitlines(); data={"integrity":False,"matched":False,"steps":[],"case":case,
        "actor_tids":{},"coord":None,"boot":None,"sha256":hashlib.sha256(raw).hexdigest()}
    try:
        requested="ABCA" if case=="WRONG" else case
        require(one(r"^CASE_BEGIN (ABA|ABCA|WRONG)$",text)==case and
                one(r"^PARAMS (ABCA|ABA) ([01])$",text)==(requested,str(int(case=='WRONG'))),
                "guest parameter binding differs")
        for pattern in (r"^LOAD_EXIT (0)$",r"^UNLOAD_EXIT (0)$",r"^MODULE_ABSENT (1)$",
                        r"^CASE_END (0)$",r"^(?:IIO|K14)_SUPERVISOR_EXIT (0)$"):
            one(pattern,text)
        blocks=section(lines,'DMESG'); trace=section(lines,'TRACE')
        coord,tids,steps,value=kernel_evidence(parse_kernel(blocks),requested,case=='WRONG')
        actual=''.join(s['role'] for s in steps)
        data.update(steps=steps,actor_tids=tids,coord=coord,actual=actual,final=value)
        boot=one(r'^CENTRAL_BOOT ([0-9a-f-]{36}) readonly=1$',text)
        data['boot']=str(uuid.UUID(boot))
        data['kernel_id']=note_id(one(r'^KERNELNOTES ([0-9a-f]+)$',text))
        data['module_id']=note_id(one(r'^MODNOTES ([0-9a-f]+)$',text))
        data['module_sha256']=one(r'^MODULE_SHA256 ([0-9a-f]{64})$',text)
        data['bus'],data['A_resume']=trace_evidence(trace,coord,tids,steps,value)
        require(case!='WRONG' or (actual=='ABAC' and value==6), "wrong-grant control did not execute ABAC")
        stats=re.findall(r'^BUFFER cpu=(\d+) (overrun|commit overrun|dropped events):\s*(\d+)$',text,re.M)
        require(len(stats)==12 and len({(int(c),k) for c,k,v in stats})==12 and
                {int(c) for c,k,v in stats}==set(range(4)) and all(v=='0' for c,k,v in stats),"trace buffer loss or missing per-CPU statistics")
        data.update(integrity=True,matched=actual==requested and value==(2 if requested=='ABA' else 6),diagnostic=None)
        if not data['matched']:data['diagnostic']='issued and executed order differs from requested order'
    except (ValueError,KeyError,IndexError,struct.error) as e:
        data['diagnostic']=str(e)
    return data


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("serial",type=Path);ap.add_argument("case",choices=("ABA","ABCA","WRONG"))
    args=ap.parse_args(); result=parse(args.serial,args.case)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['integrity'] and result['matched']==(args.case!='WRONG') else 1)

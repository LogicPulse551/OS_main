"""Check actual original-algorithm outputs; this is not a proof of extraction."""
import json,sys,pathlib
def verify(rows):
    names=['cp','cse','dce','licm','cp-boundary','cse-boundary','dce-boundary','licm-boundary','licm-print-boundary']
    if [r['case'] for r in rows]!=names:raise ValueError('Missing, duplicate or reordered cases')
    results={r['case']:r for r in rows}
    for r in rows:
        if r['after'] is None:raise ValueError('Optimizer returned None: '+r['case'])
    def blocks(name,side='after'):
        p=results[name][side]
        if len(p)!=1 or p[0][:2]!=[1,1]:raise ValueError('Unexpected function/entry')
        bs=p[0][2]
        if len({b[0] for b in bs})!=len(bs):raise ValueError('Duplicate label')
        return dict(bs)
    expected={
      'cp':[[1,1,0,7],[1,2,0,12],[4,1,2],[9]],
      'cse':[[1,1,2,0,1,8,1,9],[1,2,1,1],[4,1,2],[9]],
      'dce':[[0],[1,2,0,12],[4,1,2],[9]]}
    checks=[]
    def check(name,ok):
        checks.append(dict(name=name,passed=bool(ok)))
        if not ok:raise ValueError(name)
    for name,want in expected.items():
        check(name+' exact changed output',blocks(name)=={1:want} and results[name]['before']!=results[name]['after'])
    before=blocks('licm','before');after=blocks('licm')
    want=dict(before)
    want[1]=[[1,9,0,2],[10,6]]
    want[3]=[[1,1,1,10],[10,4]]
    want[6]=[[2,10,1,0],[10,2]]
    want[7]=[[2,11,1,0],[10,5]]
    want[8]=[[10,3]]
    want[9]=[[10,4]]
    check('licm exact load hoist and body reuse',after==want)
    for name in ['cp','cse','dce']:
        r=results[name+'-boundary'];check(name+' boundary preserved',r['before']==r['after'])
    before=blocks('licm-boundary','before');after=blocks('licm-boundary')
    check('licm acquire body preserved',after[3]==before[3])
    loads=lambda bs:[i for instructions in bs.values() for i in instructions if i[0]==2]
    check('licm acquire neither hoisted nor duplicated',loads(after)==loads(before))
    check('licm print invalidates reusable memory fact',blocks('licm-print-boundary')[3]==blocks('licm-print-boundary','before')[3])
    return checks
if __name__=='__main__':
    rows=[json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
    print(json.dumps(dict(passed=True,checks=verify(rows),cases=rows),ensure_ascii=False,indent=2))

"""K09 fixed-candidate execution, complete attempt ledger and fail-closed recovery."""
import json
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
from .lifecycle import REPO, read, persist, digest, fail, load, lab_environment
from .sampling import SampleRuntime
from . import candidates, search_queue as queue


class SearchRuntime(SampleRuntime):
    lab_prefix = 'os-concurrency-k09'
    state_file = 'run/k09-state.json'
    profile_file = 'k09-runtime.json'

    def candidate_eligibility(self, candidate, identity):
        return queue.eligibility(candidate, identity)

    def analyze_candidate(self, trace, mapping, guest, candidate):
        analyzer=load('k09_analysis',REPO/'adapters/maccconc/k09_analysis.py')
        return analyzer.analyze(trace,mapping,guest,candidate)

    def identity(self):
        old = super().identity()
        names = ['kcov-execute-k09-ab', 'kcov-execute-k09-ba'] + sorted(x['native_so'] for x in candidates.load_catalog()['inputs'])
        build = self.runtime['search_guest_build']
        value = self.guest(f"""import pathlib,json,hashlib
p=pathlib.Path({build!r});r=json.loads((p/'result.json').read_text());old=pathlib.Path({self.runtime['sample_guest_build']!r})
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
v={{'record':r,'hashes':{{n:sha(p/'bin'/n) for n in {names!r}}},
'old_result_sha256':sha(old/'result.json'),'old_manifest_sha256':sha(old/'effective-sources.json')}}
if r.get('kind')=='kconc.executor.control-build':
 parent=pathlib.Path(r['inputs']['accepted_k09']['path'])
 def source_hashes(base,rows):
  found={{}}
  for row in rows:
   f=base/'source-work'/row['path']
   assert f.is_file() and not f.is_symlink() and f.resolve().is_relative_to((base/'source-work').resolve())
   found[row['path']]=sha(f)
  return found
 sources=json.loads((p/'effective-sources.json').read_text())
 prior_sources=json.loads((parent/'effective-sources.json').read_text())
 v['control']={{'record':json.loads((parent/'result.json').read_text()),
  'hashes':{{n:sha(parent/'bin'/n) for n in {names!r}}},
  'current_hashes':v['hashes'],'parent_result_sha256':sha(parent/'result.json'),
  'parent_manifest_sha256':sha(parent/'effective-sources.json'),'parent_sources':prior_sources,
  'parent_sources_intact':source_hashes(parent,prior_sources)=={{r['path']:r['sha256'] for r in prior_sources}},
  'sources':sources,'manifest_sha256':sha(p/'effective-sources.json'),'source_hashes':source_hashes(p,sources)}}
print(json.dumps(v))
""")
        current_record,current_hashes=value['record'],value['hashes']
        parent=value.get('control')
        record,hashes=(parent['record'],parent['hashes']) if parent else (current_record,current_hashes)
        inputs = record['inputs'];accepted = inputs['accepted_k08']
        old_record = accepted['record'];copied = inputs.get('copied_scenarios',[])
        checks = dict(build_passed=record.get('passed') is True and record.get('kind')=='kconc.executor.build' and record.get('task')=='K09',
            binaries=len(record.get('binaries',[]))==16 and {r['name']:r['sha256'] for r in record['binaries']}==hashes,
            executor_entrypoints_same=hashes['kcov-execute-k09-ab']==hashes['kcov-execute-k09-ba'],
            original_k08_inputs=old_record.get('inputs')==old['inputs'],
            original_k08_binaries={r['name']:r['sha256'] for r in old_record['binaries']}==old['binaries'],
            original_record_hash=accepted['result_sha256']==value['old_result_sha256'],
            original_manifest_hash=accepted['effective_manifest_sha256']==value['old_manifest_sha256'],
            copied_scenarios=len(copied)==14 and {r['name']:r['sha256'] for r in copied}=={n:hashes[n] for n in names if n.endswith('.so')},
            original_scenario_bytes=all(hashes[n]==old['binaries'][n] for n in names if n.endswith('.so')),
            patch=inputs.get('executor_patch_sha256')==digest(REPO/'adapters/maccconc/k09-executor.patch'),
            build_script=inputs.get('build_script_sha256')==digest(REPO/'scripts/build-k09-guest.sh'))
        if parent:
            from .control_build import native_checks
            checks.update(native_checks(current_record,parent,record,hashes,
                digest(REPO/'adapters/maccconc/k10-control.patch'),digest(REPO/'scripts/build-k10-guest.sh')))
        identity=dict(kernel_and_k03=old['kernel_and_k03'],binaries=current_hashes,inputs=current_record['inputs'],catalog_sha256=old['catalog_sha256'])
        persist(self.out/'search-identity.json',dict(passed=all(checks.values()),checks=checks,identity=identity))
        if not all(checks.values()):fail('identity_mismatch','K09 executor or original K08 scenario bridge changed')
        return identity

    def ready_profile(self):
        profile=self.profile();state=read(self.statepath)
        if state.get('state')!='ready':fail('recovery_required','Recover the incomplete K09 runtime before another attempt')
        if self.boot_id()!=state.get('boot_id'):
            self.mark('dirty',reason='Unexpected guest boot identity');fail('recovery_required','Guest changed outside lifecycle')
        self.check_profile_identity(profile)
        return profile,state

    def run_candidate(self,candidate):
        profile,state=self.ready_profile()
        support=self.candidate_eligibility(candidate,profile['identity'])
        if not support['supported']:fail('candidate_binding_mismatch','Candidate is not bound to this original kernel and scenario build')
        identity=candidate['identity'];entry=identity['input'];order=identity['baseline_order']
        plan=queue.make_plan(candidate);(self.out/'input-plan.txt').write_bytes(plan)
        persist(self.out/'candidate.json',candidate);persist(self.out/'runtime-identity.json',profile['identity'])
        run_id=uuid.uuid4().hex;remote='/home/lab/k09/run-'+run_id;build=self.runtime['search_guest_build']
        request=dict(run_id=run_id,executable=build+'/bin/kcov-execute-k09-'+order,
            scenario_library=build+'/bin/'+entry['native_so'],plan_path=remote+'/plan.txt',timeout_seconds=60,fault='none')
        active=dict(run_id=run_id,remote=remote,request=remote+'/request.json',boot_id=state['boot_id'],operation='kernel.check',candidate_id=candidate['candidate_id'])
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K09 candidate started; cleanup and control not checked')
        persist(self.out/'guest-request.json',request)
        files={'request.json':json.dumps(request),'plan.txt':plan.decode(),
            'supervisor.py':(REPO/'adapters/maccconc/k09_guest.py').read_text(),'k04_guest.py':(REPO/'adapters/maccconc/k04_guest.py').read_text()}
        self.guest_started=False
        reply=self.guest(f"""import pathlib,json,subprocess
p=pathlib.Path({remote!r});p.mkdir(mode=0o700)
for name,data in {files!r}.items():
 f=p/name;f.write_text(data);f.chmod(0o600)
with (p/'supervisor.stdout').open('xb') as o,(p/'supervisor.stderr').open('xb') as e:
 c=subprocess.Popen(['python3',str(p/'supervisor.py'),'run','--request',str(p/'request.json')],stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
print(json.dumps({{'supervisor_pid':c.pid}}))
""")
        self.guest_started=True;active.update(reply)
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K09 supervisor active')
        guest=None;collected=False
        try:
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                guest=self.poll_guest(remote)
                if guest is not None:break
                time.sleep(.25)
        except KeyboardInterrupt:
            self.ssh(['sudo','-n','python3',remote+'/supervisor.py','cancel','--request',remote+'/request.json']);raise
        finally:
            try:self.collect(remote);collected=True
            except Exception as error:persist(self.out/'collection-error.json',dict(error=str(error)))
        if guest is None:fail('recovery_required','No guest completion; checkpoint recovery is required')
        if not collected:fail('collection_incomplete','Candidate records were not collected completely')
        command=[request['executable'],request['scenario_library'],'--k09-execute',order,request['plan_path'],remote+'/trace']
        if (guest.get('run_id')!=run_id or guest.get('boot_id')!=state['boot_id'] or guest.get('command')!=command
                or guest.get('fault')!='none' or read(self.out/'guest/guest-result.json')!=guest):
            fail('guest_result_mismatch','Guest result is not bound to the submitted candidate')
        trace=self.out/'guest/trace';mapping={}
        if (trace/'A.events.jsonl').is_file() and (trace/'B.events.jsonl').is_file():
            session=object.__new__(self.k03.Session);session.out,session.commands,session.lab=self.out,[],self.lab
            session.args=SimpleNamespace(source_mapper=Path(self.task['inputs']['source_mapper']),kernel_build=Path(self.runtime['kernel_build']))
            mapping=session.source_map([trace])
        result=self.analyze_candidate(trace,mapping,guest,candidate)
        matches=(trace/'plan.txt').is_file() and (trace/'plan.txt').read_bytes()==plan
        result['checks']['executed_plan_matches_submitted']=matches
        if not matches:
            result.update(passed=False,classification='invalid',candidate_hit=False,execution_valid=False,
                control_valid=False,property_evaluated=False,property_violation=False,recovery_required=True)
            result['errors'].append('Executed plan absent or different from submitted plan')
        result.update(runtime_identity_bound=True,runtime_identity_sha256=digest(self.out/'runtime-identity.json'),
            candidate_file_sha256=digest(self.out/'candidate.json'),plan_sha256=digest(self.out/'input-plan.txt'))
        persist(self.out/'analysis.json',result)
        data=dict(kind='kconc.candidate-attempt',candidate_id=candidate['candidate_id'],guest_started=True,guest=guest,
            analysis=result,passed=result['passed'],classification=result['classification'],recovery_required=result['recovery_required'])
        persist(self.out/'attempt-result.json',data);self.last_result=data
        self.mark('dirty' if result['recovery_required'] else 'ready',boot_id=state['boot_id'],result=str(self.out/'attempt-result.json'))
        return data

    def execute(self):
        profile,state=self.ready_profile();scenario=self.task['scenario'];family=scenario['family']
        if not self.labdir.name.endswith('-'+family):fail('search_family_mismatch','Use the dedicated VM for the selected kernel family')
        release=(Path(self.runtime['kernel_build'])/'include/config/kernel.release').read_text().strip()
        if ('-kconc-k06' if family=='rmw' else '-kconc-k07') not in release:
            fail('search_family_mismatch','Selected kernel does not implement this scenario ABI')
        pool=queue.load_pool(self.task['inputs']['pool'],verify_sources=False)
        source_validation=queue.revalidate_sources(pool)
        persist(self.out/'source-validation.json',source_validation)
        ledger=queue.make_queue(pool,family,scenario['max_candidates'],profile['identity'])
        ledger['pool_file_sha256']=digest(Path(self.task['inputs']['pool']))
        analyzer=load('k09_match_policy',REPO/'adapters/maccconc/k09_analysis.py')
        ledger['matching_policy_sha256']=analyzer.POLICY_SHA256
        persist(self.out/'matching-policy.json',analyzer.MATCH_POLICY)
        persist(self.out/'ledger.json',ledger);persist(self.out/'runtime-identity.json',profile['identity'])
        by_id={c['candidate_id']:c for c in pool['candidates']};interruption=None;error=None
        for row in ledger['candidates']:
            if row['status']!='pending':continue
            attempt_id=uuid.uuid4().hex;queue.begin_attempt(ledger,row['candidate_id'],attempt_id)
            directory=self.out/('attempt-%03d'%len(ledger['attempts']));directory.mkdir()
            persist(directory/'task.json',dict(self.task,candidate_id=row['candidate_id'],attempt_id=attempt_id))
            persist(self.out/'ledger.json',ledger)
            runner=None
            try:
                runner=SearchRuntime(self.task,directory)
                data=runner.run_candidate(by_id[row['candidate_id']]);result=data['analysis']
                queue.finish_attempt(ledger,attempt_id,result['classification'],guest_started=True,
                    cleanup_confirmed=result['cleanup_verified'],property_evaluated=result['property_evaluated'],
                    property_violation=result['property_violation'] if result['property_evaluated'] else None,
                    evidence=dict(directory=str(directory),analysis_sha256=digest(directory/'analysis.json'),result_sha256=digest(directory/'attempt-result.json')))
                if result['recovery_required']:interruption='Candidate requires checkpoint recovery'
            except BaseException as exc:
                error=exc;interruption='Candidate interrupted or infrastructure failed: '+str(exc)
                details=dict(type=type(exc).__name__,message=str(exc),guest_started=getattr(runner,'guest_started',False),
                    runtime_state=read(self.statepath) if self.statepath.exists() else None)
                persist(directory/'exception.json',details)
                queue.finish_attempt(ledger,attempt_id,'infrastructure-error',guest_started=details['guest_started'],
                    cleanup_confirmed=False,evidence=dict(directory=str(directory),exception_sha256=digest(directory/'exception.json')))
            persist(self.out/'ledger.json',ledger)
            if interruption:break
        queue.finalize(ledger,interruption);persist(self.out/'ledger.json',ledger)
        data=dict(kind='kconc.search',passed=interruption is None,ledger=str(self.out/'ledger.json'),
            ledger_sha256=digest(self.out/'ledger.json'),summary=ledger['summary'],recovery_required=read(self.statepath).get('state')!='ready',
            scope='Completed bounded candidate attempt accounting; passed does not imply all candidates hit or source correctness')
        persist(self.out/'search-result.json',data);self.last_result=data
        if error is not None:raise error
        return data


def dispatch(task,out,envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=SearchRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='search.initialize':data=runtime.initialize()
                    elif op=='search.status':
                        runtime.profile();data=dict(state=read(runtime.statepath),vm=runtime.lab.running(),execution_readiness_verified=False)
                    elif op=='search.recover':data=runtime.recover()
                    else:data=runtime.execute()
                    envelope['data']=data
                    if data.get('passed') is False:fail('search_incomplete','Search stopped with all attempted and unattempted candidates retained')
        except BaseException:
            if hasattr(runtime,'last_result'):envelope['data']=runtime.last_result
            elif runtime.statepath.exists():envelope['data']['runtime_state']=read(runtime.statepath)
            raise

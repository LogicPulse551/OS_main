"""Finite K08 sampling in isolated accepted-kernel VMs; no candidate execution."""
import json
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
from .lifecycle import Runtime, REPO, read, persist, digest, fail, load, lab_environment
from . import candidates


def candidate_from_analysis(analysis, trace, identity, report, provenance):
    catalog = candidates.load_catalog()
    obs = analysis['observations']
    entry = candidates.get_input(catalog, obs['family'], obs['case_id'], obs['mode'])
    source = dict(trace_path=str(trace), trace_sha256={n: digest(trace/n) for n in candidates.TRACE_FILES},
        analysis_sha256=digest(report), **provenance)
    return candidates.make_candidate(entry, identity, candidates.observed_initial_state(analysis), analysis, source)


class SampleRuntime(Runtime):
    lab_prefix = 'os-concurrency-k08'
    state_file = 'run/k08-state.json'
    profile_file = 'k08-runtime.json'

    def analyze_sample(self, trace, mapping, guest, family, order):
        analyzer = load('k08_analysis', REPO/'adapters/maccconc/k08_analysis.py')
        return analyzer.analyze(trace, mapping, guest, family, order)

    def identity(self):
        args = SimpleNamespace(output=self.out/('identity-'+uuid.uuid4().hex[:8]),
            guest_build=Path(self.runtime['scenario_guest_build']), build_lab=Path(self.runtime['build_lab']),
            kernel_build=Path(self.runtime['kernel_build']))
        original = self.k03.Session(args).identity()
        catalog = candidates.load_catalog()
        names = ['kcov-sample-k08-ab', 'kcov-sample-k08-ba'] + sorted(x['native_so'] for x in catalog['inputs'])
        build = self.runtime['sample_guest_build']
        value = self.guest(f"""import pathlib,json,hashlib
p=pathlib.Path({build!r});r=json.loads((p/'result.json').read_text())
print(json.dumps({{'record':r,'device':pathlib.Path('/dev/kconc-regmap').is_char_device(),
'hashes':{{n:hashlib.sha256((p/'bin'/n).read_bytes()).hexdigest() for n in {names!r}}}}}))
""")
        record, hashes = value['record'], value['hashes']
        inputs = record['inputs']
        copied = inputs.get('copied_scenarios', [])
        checks = {'native_build':record.get('passed') is True and record.get('kind')=='kconc.sampler.build',
            'device':value['device'] is True,
            'binaries':len(record.get('binaries',[]))==16 and {x['name']:x['sha256'] for x in record['binaries']}==hashes,
            'sampler_same_bytes':hashes['kcov-sample-k08-ab']==hashes['kcov-sample-k08-ba'],
            'copied_scenarios':len(copied)==14 and {x['name']:x['sha256'] for x in copied}=={n:hashes[n] for n in names if n.endswith('.so')},
            'old_executor':inputs.get('k03_executor_sha256')==original['binaries']['kcov-autorace-k03'],
            'patch':inputs.get('executor_patch_sha256')==digest(REPO/'adapters/maccconc/k08-executor.patch'),
            'script':inputs.get('build_script_sha256')==digest(REPO/'scripts/build-k08-guest.sh')}
        for stage in ('k06','k07'):
            accepted = inputs['accepted_builds'][stage]
            fields = {'scenario_sha256':f'scenarios/regmap-{stage}.c', 'client_sha256':f'scenarios/regmap-{stage}-client.c',
                'cases_sha256':f'scenarios/regmap-{stage}-cases.h', 'uapi_sha256':f'kernel/{stage}/kconc-regmap.h',
                'executor_patch_sha256':'adapters/maccconc/k05-executor.patch', 'build_script_sha256':f'scripts/build-{stage}-guest.sh'}
            checks.update({stage+'.'+k:accepted['inputs'].get(k)==digest(REPO/p) for k,p in fields.items()})
            accepted_hashes={x['name']:x['sha256'] for x in accepted['binaries']}
            checks[stage+'.copied_bytes']=all(hashes[n]==accepted_hashes.get(n) for n in names if n.startswith('regmap-'+stage+'-'))
        identity = dict(kernel_and_k03=original, binaries=hashes, inputs=inputs,
            catalog_sha256=digest(candidates.CATALOG))
        persist(self.out/'sample-identity.json',dict(passed=all(checks.values()),checks=checks,identity=identity))
        if not all(checks.values()): fail('identity_mismatch','K08 sampler, catalog or reused scenarios differ')
        return identity

    def execute(self):
        profile = self.profile();state = read(self.statepath);scenario = self.task['scenario']
        if state.get('state')!='ready': fail('recovery_required','Recover the incomplete K08 runtime first')
        if self.boot_id()!=state.get('boot_id'):
            self.mark('dirty',reason='Unexpected boot identity');fail('recovery_required','Guest changed outside lifecycle')
        self.check_profile_identity(profile)
        # The per-VM profile fixes the selected kernel; ABI is then checked again
        # against the actual ioctl records before any candidate is admitted.
        catalog=candidates.load_catalog();entry=candidates.get_input(catalog,scenario['family'],scenario['case_id'],scenario['mode'])
        expected_stage = 'k06' if scenario['family']=='rmw' else 'k07'
        if not self.labdir.name.endswith('-'+scenario['family']):
            fail('sample_family_mismatch','Use the independently registered VM for this scenario family')
        kernel_release = (Path(self.runtime['kernel_build'])/'include/config/kernel.release').read_text().strip()
        if '-kconc-'+expected_stage not in kernel_release:
            fail('sample_family_mismatch','Selected kernel ABI does not match the finite input family')
        run_id=uuid.uuid4().hex;remote='/home/lab/k08/run-'+run_id;build=self.runtime['sample_guest_build']
        request=dict(run_id=run_id,executable=build+'/bin/kcov-sample-k08-'+scenario['order'],
            scenario_library=build+'/bin/'+entry['native_so'],plan_path=None,timeout_seconds=60,fault='none')
        active=dict(run_id=run_id,remote=remote,request=remote+'/request.json',boot_id=state['boot_id'],operation='sample.run')
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K08 serial sample started; cleanup not yet checked')
        persist(self.out/'guest-request.json',request)
        files={'request.json':json.dumps(request),'supervisor.py':(REPO/'adapters/maccconc/k08_guest.py').read_text(),
            'k04_guest.py':(REPO/'adapters/maccconc/k04_guest.py').read_text()}
        active.update(self.guest(f"""import pathlib,json,subprocess
p=pathlib.Path({remote!r});p.mkdir(mode=0o700)
for name,data in {files!r}.items():
 f=p/name;f.write_text(data);f.chmod(0o600)
with (p/'supervisor.stdout').open('xb') as o,(p/'supervisor.stderr').open('xb') as e:
 c=subprocess.Popen(['python3',str(p/'supervisor.py'),'run','--request',str(p/'request.json')],stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
print(json.dumps({{'supervisor_pid':c.pid}}))
"""))
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K08 supervisor active')
        guest=None;collected=False
        try:
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                guest=self.poll_guest(remote)
                if guest is not None: break
                time.sleep(.25)
        except KeyboardInterrupt:
            self.ssh(['sudo','-n','python3',remote+'/supervisor.py','cancel','--request',remote+'/request.json']);raise
        finally:
            try:self.collect(remote);collected=True
            except Exception as error:persist(self.out/'collection-error.json',dict(error=str(error)))
        if guest is None:fail('recovery_required','No guest completion; checkpoint recovery required')
        if not collected:fail('collection_incomplete','Trace collection incomplete; runtime remains dirty')
        command=[request['executable'],request['scenario_library'],'--k08-baseline',scenario['order'],remote+'/trace']
        if (guest.get('run_id')!=run_id or guest.get('boot_id')!=state['boot_id'] or guest.get('command')!=command
                or guest.get('fault')!='none' or read(self.out/'guest/guest-result.json')!=guest):
            fail('guest_result_mismatch','Guest result is not bound to the submitted sample')
        clean=(guest.get('outcome')=='completed' and type(guest.get('exit_code')) is int and guest['exit_code']==0
            and guest.get('remaining_pids')==[] and guest.get('local_cleanup',{}).get('confirmed') is True
            and guest['local_cleanup'].get('errors')==[])
        trace=self.out/'guest/trace/baseline'
        result=dict(passed=False,errors=['Trace absent or incomplete; not a source bug'])
        if clean and (trace/'A.events.jsonl').is_file():
            session=object.__new__(self.k03.Session);session.out,session.commands,session.lab=self.out,[],self.lab
            session.args=SimpleNamespace(source_mapper=Path(self.task['inputs']['source_mapper']),kernel_build=Path(self.runtime['kernel_build']))
            mapping=session.source_map([trace])
            result=self.analyze_sample(trace,mapping,guest,scenario['family'],scenario['order'])
            matches=all(result.get('observations',{}).get(k)==v for k,v in scenario.items())
            result['checks']['submitted_scenario_matches']=matches;result['passed']=result['passed'] and matches
            if not matches:
                result.update(execution_valid=False,control_valid=False,property_evaluated=False,property_violation=False)
                result['observations'].pop('observed_prefix',None)
                result['errors'].append('Submitted scenario differs from observation')
        persist(self.out/'analysis.json',result);persist(self.out/'runtime-identity.json',profile['identity'])
        data=dict(kind='kconc.sample',passed=clean and result['passed'],analysis=result,
            candidate_execution_performed=False,kernel_bug_claim=False)
        if data['passed']:
            provenance=dict(source_map_sha256=digest(self.out/'source-map.jsonl'),
                runtime_identity_sha256=digest(self.out/'runtime-identity.json'),guest_sha256=digest(self.out/'guest/guest-result.json'),
                task_sha256=digest(self.out/'task.json'),run_id=run_id)
            candidate=candidate_from_analysis(result,trace,profile['identity'],self.out/'analysis.json',provenance)
            pool=candidates.export_candidates(self.out/'candidate.json',[candidate],catalog)
            data.update(candidate_path=str(self.out/'candidate.json'),candidate_sha256=digest(self.out/'candidate.json'),summary=pool['summary'])
        data['recovery_required']=not data['passed']
        persist(self.out/'sample-result.json',data);self.last_result=data
        self.mark('ready' if data['passed'] else 'dirty',boot_id=state['boot_id'],result=str(self.out/'sample-result.json'))
        return data


def export_samples(task,out):
    """Revalidate archived samples offline; do not assert that a VM is current."""
    index_path=Path(task['inputs']['samples']);index=candidates._read_json(index_path)
    if not isinstance(index,dict) or set(index)!={'schema_version','samples'} or type(index['schema_version']) is not int or index['schema_version']!=1:
        fail('invalid_sample_index','Expected schema_version=1 and samples array')
    if not isinstance(index['samples'],list) or not index['samples'] or len(index['samples'])>4096:
        fail('invalid_sample_index','Sample index must contain 1..4096 external sample directories')
    analyzer=load('k08_export_analysis',REPO/'adapters/maccconc/k08_analysis.py');rows=[];validations=[]
    for item in index['samples']:
        if not isinstance(item,str) or not item:fail('invalid_sample_index','Sample directory must be a nonempty string')
        path=(index_path.parent/item).resolve();trace=path/'guest/trace/baseline'
        if path.is_relative_to(REPO):fail('invalid_sample_index','Sample evidence must be outside code repository')
        original=read(path/'result.json');scenario=read(path/'task.json')['scenario']
        if original.get('status')!='passed' or original.get('operation')!='sample.run':fail('invalid_sample','Only completed samples can generate candidates')
        pool=candidates._read_json(path/'candidate.json')
        if len(pool.get('candidates',[]))!=1:fail('invalid_sample','Single sample must bind one marker candidate')
        saved_candidate=pool['candidates'][0];source=saved_candidate['sources'][0]
        for field,relative in [('source_map_sha256','source-map.jsonl'),('runtime_identity_sha256','runtime-identity.json'),
                               ('guest_sha256','guest/guest-result.json'),('task_sha256','task.json')]:
            if source.get(field)!=digest(path/relative):fail('sample_binding_mismatch','Archived binding differs: '+relative)
        if original['data'].get('candidate_sha256')!=digest(path/'candidate.json'):
            fail('sample_binding_mismatch','Candidate file differs from completed run')
        # The live mapper passes a dictionary and binds its canonical contents.
        # Reconstruct that representation after checking the archived file bytes.
        # Passing a path instead would change report metadata despite identical data.
        mapping={}
        for line in (path/'source-map.jsonl').read_text().splitlines():
            row=json.loads(line,object_pairs_hook=candidates._pairs)
            candidates.canonical(row)
            if not isinstance(row,dict) or row.get('raw_ip') in mapping:
                fail('sample_binding_mismatch','Invalid or duplicate source-map row')
            mapping[row.get('raw_ip')]=row
        observed=analyzer.analyze(trace,mapping,path/'guest/guest-result.json',scenario['family'],scenario['order'])
        matches=all(observed.get('observations',{}).get(k)==v for k,v in scenario.items())
        observed['checks']['submitted_scenario_matches']=matches;observed['passed']=observed['passed'] and matches
        saved=read(path/'analysis.json')
        if observed!=saved or not observed['passed']:fail('sample_revalidation_failed','Archived trace or analysis has changed: '+str(path))
        provenance={k:v for k,v in source.items() if k not in {'trace_path','trace_sha256','analysis_sha256'}}
        rebuilt=candidate_from_analysis(observed,trace,read(path/'runtime-identity.json'),path/'analysis.json',provenance)
        if rebuilt!=saved_candidate:fail('sample_binding_mismatch','Candidate does not match revalidated evidence')
        rows.append(rebuilt);validations.append(dict(sample=str(path),candidate_id=rebuilt['candidate_id'],passed=True))
    pool=candidates.export_candidates(out/'candidates.json',rows)
    value=dict(passed=True,summary=pool['summary'],validations=validations,index_sha256=digest(index_path),
        pool_path=str(out/'candidates.json'),pool_sha256=digest(out/'candidates.json'),
        scope='Archived samples revalidated offline; current VM state and future candidate execution are not checked')
    persist(out/'export-result.json',value)
    return value


def dispatch(task,out,envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=SampleRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='sample.initialize':data=runtime.initialize()
                    elif op=='sample.status':data=dict(state=read(runtime.statepath),vm=runtime.lab.running())
                    elif op=='sample.recover':data=runtime.recover()
                    else:data=runtime.execute()
                    envelope['data']=data
                    if data.get('passed') is False:fail('sample_validation_failed','Incomplete K08 observation; inspect retained evidence')
        except BaseException:
            if hasattr(runtime,'last_result'):envelope['data']=runtime.last_result
            elif runtime.statepath.exists():envelope['data']['runtime_state']=read(runtime.statepath)
            raise

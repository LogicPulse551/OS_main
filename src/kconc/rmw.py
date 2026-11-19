"""K06 masked-update contrasts. A property failure is distinct from a bad run."""
import json
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
from .lifecycle import Runtime, REPO, read, persist, digest, fail, load, lab_environment
from .manifest import RMW_CASES, RMW_MODES


class RmwRuntime(Runtime):
    lab_prefix = 'os-concurrency-k06'
    state_file = 'run/k06-state.json'
    profile_file = 'k06-runtime.json'

    def identity(self):
        args = SimpleNamespace(output=self.out/('identity-'+uuid.uuid4().hex[:8]),
            guest_build=Path(self.runtime['scenario_guest_build']), build_lab=Path(self.runtime['build_lab']),
            kernel_build=Path(self.runtime['kernel_build']))
        original = self.k03.Session(args).identity()
        build = self.runtime['rmw_guest_build']
        names = ['kcov-autorace-k06', 'regmap-k06-client'] + sorted(
            f'regmap-k06-{case}-{mode}.so' for case in RMW_CASES for mode in RMW_MODES)
        value = self.guest(f"""import pathlib,json,hashlib
p=pathlib.Path({build!r});r=json.loads((p/'result.json').read_text())
print(json.dumps({{'record':r,'device':pathlib.Path('/dev/kconc-regmap').is_char_device(),
'hashes':{{n:hashlib.sha256((p/'bin'/n).read_bytes()).hexdigest() for n in {names!r}}}}}))
""")
        record, hashes = value['record'], value['hashes']
        fields = {'scenario_sha256':'scenarios/regmap-k06.c', 'client_sha256':'scenarios/regmap-k06-client.c',
            'cases_sha256':'scenarios/regmap-k06-cases.h', 'uapi_sha256':'kernel/k06/kconc-regmap.h',
            'executor_patch_sha256':'adapters/maccconc/k05-executor.patch', 'build_script_sha256':'scripts/build-k06-guest.sh'}
        checks = {'native_build':record.get('passed') is True and record.get('scenario')=='regmap-rmw-v1',
            'device':value['device'] is True,
            'binaries':len(record.get('binaries',[]))==len(names) and {x['name']:x['sha256'] for x in record.get('binaries',[])}==hashes,
            'old_executor':record.get('inputs',{}).get('k03_executor_sha256')==original['binaries']['kcov-autorace-k03']}
        checks.update({key:record.get('inputs',{}).get(key)==digest(REPO/path) for key,path in fields.items()})
        identity = dict(kernel_and_k03=original, binaries=hashes, inputs=record['inputs'])
        persist(self.out/'rmw-identity.json',dict(passed=all(checks.values()),checks=checks,identity=identity))
        if not all(checks.values()): fail('identity_mismatch','K06 native scenario or kernel identity differs')
        return identity

    def bound_plan(self, profile):
        binding = Path(self.task['inputs']['binding']); info = read(binding/'binding.json')
        scenario = self.task['scenario']
        checks = [read(binding/'runtime-identity.json')==profile['identity'],
            digest(binding/'plan.txt')==info.get('plan_sha256'), info.get('runtime_identity_bound') is True,
            info.get('runtime_identity_sha256')==digest(binding/'runtime-identity.json'),
            info.get('analysis_sha256')==digest(REPO/'adapters/maccconc/k06_analysis.py'),
            info.get('k03_analysis_sha256')==digest(REPO/'adapters/maccconc/k03_analysis.py'),
            info.get('oracle_sha256')==digest(REPO/'src/kconc/regmap_oracle.py'),
            info.get('scenario')==scenario['id'], info.get('case_id')==scenario['case_id'], info.get('mode')==scenario['mode']]
        if not all(checks): fail('binding_mismatch','Plan must match the exact kernel, native build, input, mode and analyzers')
        load('k06_old_analysis',REPO/'adapters/maccconc/k03_analysis.py').read_plan(binding/'plan.txt')
        plan = (binding/'plan.txt').read_bytes()
        (self.out/'input-plan.txt').write_bytes(plan)
        return plan

    def execute(self):
        op = self.task['operation']; profile = self.profile(); state = read(self.statepath)
        if state.get('state')!='ready': fail('recovery_required','Recover the incomplete K06 runtime first')
        if self.boot_id()!=state.get('boot_id'):
            self.mark('dirty',reason='Unexpected boot identity'); fail('recovery_required','K06 guest changed outside lifecycle')
        self.check_profile_identity(profile)
        client = op=='rmw.matrix'
        analysis = load('k06_analysis',REPO/'adapters/maccconc/k06_analysis.py')
        plan = self.bound_plan(profile) if op=='rmw.replay' else None
        run_id=uuid.uuid4().hex; remote='/home/lab/k06/run-'+run_id; build=self.runtime['rmw_guest_build']
        scenario=self.task.get('scenario',{})
        library = 'regmap-k06-client' if client else f"regmap-k06-{scenario['case_id']}-{scenario['mode']}.so"
        request=dict(run_id=run_id,executable=build+'/bin/'+('regmap-k06-client' if client else 'kcov-autorace-k06'),
            scenario_library=build+'/bin/'+library,plan_path=remote+'/plan.txt' if plan is not None else None,
            timeout_seconds=60,fault='none')
        active=dict(run_id=run_id,remote=remote,request=remote+'/request.json',boot_id=state['boot_id'],operation=op)
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K06 round started; reset and cleanup not yet checked')
        persist(self.out/'guest-request.json',request)
        files={'request.json':json.dumps(request),'supervisor.py':(REPO/'adapters/maccconc/k06_guest.py').read_text(),
            'k04_guest.py':(REPO/'adapters/maccconc/k04_guest.py').read_text()}
        if plan is not None: files['plan.txt']=plan.decode()
        active.update(self.guest(f"""import pathlib,json,subprocess
p=pathlib.Path({remote!r});p.mkdir(mode=0o700)
for name,data in {files!r}.items():
 f=p/name;f.write_text(data);f.chmod(0o600)
with (p/'supervisor.stdout').open('xb') as o,(p/'supervisor.stderr').open('xb') as e:
 c=subprocess.Popen(['python3',str(p/'supervisor.py'),'run','--request',str(p/'request.json')],stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
print(json.dumps({{'supervisor_pid':c.pid}}))
"""))
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K06 supervisor active')
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
            try: self.collect(remote);collected=True
            except Exception as error: persist(self.out/'collection-error.json',dict(error=str(error)))
        if guest is None: fail('recovery_required','No guest completion; checkpoint recovery is required')
        if not collected: fail('collection_incomplete','Guest collection did not complete; runtime remains dirty')
        expected_command = ([request['executable'],'matrix'] if client else [request['executable'],request['scenario_library']]+
            (['--k03-replay',request['plan_path'],remote+'/trace'] if plan is not None else ['--k05-baseline',remote+'/trace']))
        if (guest.get('run_id')!=run_id or guest.get('boot_id')!=state['boot_id'] or guest.get('command')!=expected_command
                or guest.get('fault')!='none' or read(self.out/'guest/guest-result.json')!=guest):
            fail('guest_result_mismatch','Guest record does not bind to the submitted command')
        clean = (guest.get('kind')=='kconc.guest' and type(guest.get('schema_version')) is int and guest['schema_version']==1
            and guest.get('outcome')=='completed' and type(guest.get('exit_code')) is int and guest['exit_code']==0
            and guest.get('remaining_pids')==[] and guest.get('local_cleanup',{}).get('confirmed') is True
            and guest['local_cleanup'].get('errors')==[])
        data=dict(kind='kconc.rmw',operation=op,guest=guest,kernel_bug_claim=False)
        if client:
            from .regmap_oracle import validate_client
            result=read(self.out/'guest/executor.stdout.txt');validation=validate_client(result)
            data.update(client=result,validation=validation,passed=clean and validation['passed'])
        else:
            trace=self.out/'guest/trace'
            if plan is None: trace=trace/'baseline'
            session=object.__new__(self.k03.Session);session.out,session.commands,session.lab=self.out,[],self.lab
            session.args=SimpleNamespace(source_mapper=Path(self.task['inputs']['source_mapper']),kernel_build=Path(self.runtime['kernel_build']))
            if clean and trace.is_dir() and (trace/'A.events.jsonl').exists():
                mapping=session.source_map([trace]);result=analysis.analyze(trace,mapping,guest,replay=plan is not None)
                observation=result.get('observations',{})
                matches=all(observation.get(k)==scenario[k] for k in ('case_id','mode'))
                result.setdefault('checks',{})['submitted_scenario_matches']=matches
                result['passed']=result['passed'] and matches
                if not matches:
                    result.update(execution_valid=False,control_valid=False,property_evaluated=False,property_violation=False)
                    result.setdefault('errors',[]).append('Submitted case/mode differs from observed scenario')
            else: result=dict(passed=False,errors=['Trace absent or incomplete; not a source bug'])
            data.update(analysis=result,passed=clean and result['passed'])
            if data['passed'] and op=='rmw.record':
                binding=analysis.make_plan(trace,self.out/'source-map.jsonl',self.out/'binding')
                persist(self.out/'binding/runtime-identity.json',profile['identity'])
                binding.update(runtime_identity_bound=True,runtime_identity_sha256=digest(self.out/'binding/runtime-identity.json'))
                persist(self.out/'binding/binding.json',binding);data['binding']=binding
            if plan is not None:
                executed = trace/'plan.txt'
                matches = executed.is_file() and executed.read_bytes()==plan
                result.setdefault('checks',{})['executed_plan_matches']=matches
                if not matches:
                    result.update(passed=False,execution_valid=False,control_valid=False,property_evaluated=False,property_violation=False)
                    result.setdefault('errors',[]).append('Executed plan absent or differs from submitted plan')
                    data['passed']=False
        data['recovery_required']=not data['passed']
        persist(self.out/'rmw-result.json',data);self.last_result=data
        self.mark('ready' if data['passed'] else 'dirty',boot_id=state['boot_id'],result=str(self.out/'rmw-result.json'))
        return data


def dispatch(task,out,envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=RmwRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError: fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='rmw.initialize': data=runtime.initialize()
                    elif op=='rmw.status': data=dict(state=read(runtime.statepath),vm=runtime.lab.running())
                    elif op=='rmw.recover': data=runtime.recover()
                    else: data=runtime.execute()
                    envelope['data']=data
                    if data.get('passed') is False: fail('rmw_validation_failed','Incomplete execution evidence; inspect retained K06 records')
        except BaseException:
            if hasattr(runtime,'last_result'): envelope['data']=runtime.last_result
            elif runtime.statepath.exists(): envelope['data']['runtime_state']=read(runtime.statepath)
            raise

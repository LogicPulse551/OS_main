"""K05 real regmap adapter; K04 owns process isolation and checkpoint recovery."""
import json
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
from .lifecycle import Runtime, REPO, read, persist, digest, fail, load, lab_environment


class RegmapRuntime(Runtime):
    lab_prefix = 'os-concurrency-k05'
    state_file = 'run/k05-state.json'
    profile_file = 'k05-runtime.json'

    def identity(self):
        args = SimpleNamespace(output=self.out/('identity-'+uuid.uuid4().hex[:8]),
            guest_build=Path(self.runtime['scenario_guest_build']), build_lab=Path(self.runtime['build_lab']),
            kernel_build=Path(self.runtime['kernel_build']))
        original = self.k03.Session(args).identity()
        build = self.runtime['regmap_guest_build']
        value = self.guest(f"""import pathlib,json,hashlib,os
p=pathlib.Path({build!r});r=json.loads((p/'result.json').read_text())
print(json.dumps({{'record':r,'device':pathlib.Path('/dev/kconc-regmap').is_char_device(),
'hashes':{{n:hashlib.sha256((p/'bin'/n).read_bytes()).hexdigest() for n in ['kcov-autorace-k05','regmap-v1.so','regmap-client']}}}}))
""")
        record, hashes = value['record'], value['hashes']
        fields = {'scenario_sha256':'scenarios/regmap-v1.c','client_sha256':'scenarios/regmap-client.c',
            'uapi_sha256':'kernel/k05/kconc-regmap.h','executor_patch_sha256':'adapters/maccconc/k05-executor.patch',
            'build_script_sha256':'scripts/build-k05-guest.sh'}
        checks = {'native_build':record.get('passed') is True and record.get('scenario')=='regmap-v1',
            'device':value['device'] is True,
            'binaries':{x['name']:x['sha256'] for x in record.get('binaries',[])}==hashes,
            'old_executor':record.get('inputs',{}).get('k03_executor_sha256')==original['binaries']['kcov-autorace-k03']}
        checks.update({key:record.get('inputs',{}).get(key)==digest(REPO/path) for key,path in fields.items()})
        identity = dict(kernel_and_k03=original, binaries=hashes, inputs=record['inputs'])
        persist(self.out/'regmap-identity.json',dict(passed=all(checks.values()),checks=checks,identity=identity))
        if not all(checks.values()): fail('identity_mismatch','K05 native scenario or kernel identity differs')
        return identity

    def execute(self):
        op = self.task['operation']; profile = self.profile(); state = read(self.statepath)
        if state.get('state')!='ready': fail('recovery_required','Recover the incomplete K05 runtime first')
        if self.boot_id()!=state.get('boot_id'):
            self.mark('dirty',reason='Unexpected boot identity')
            fail('recovery_required','K05 guest changed outside lifecycle')
        self.check_profile_identity(profile)
        client = op in ('regmap.baseline','regmap.fault-reset')
        fault = 'setup' if op in ('regmap.fault-reset','regmap.setup-fault') else 'none'
        analysis = load('k05_analysis',REPO/'adapters/maccconc/k05_analysis.py')
        plan = None
        if op=='regmap.replay':
            binding = Path(self.task['inputs']['binding'])
            saved = read(binding/'runtime-identity.json')
            info = read(binding/'binding.json')
            if (saved!=profile['identity'] or digest(binding/'plan.txt')!=info['plan_sha256']
                    or info.get('runtime_identity_bound') is not True
                    or info.get('runtime_identity_sha256')!=digest(binding/'runtime-identity.json')
                    or info.get('analysis_sha256')!=digest(REPO/'adapters/maccconc/k05_analysis.py')):
                fail('binding_mismatch','Plan is not bound to this exact K05 kernel and guest build')
            plan = (binding/'plan.txt').read_bytes()
            load('k05_old_analysis',REPO/'adapters/maccconc/k03_analysis.py').read_plan(binding/'plan.txt')
            (self.out/'input-plan.txt').write_bytes(plan)
        run_id=uuid.uuid4().hex;remote='/home/lab/k05/run-'+run_id
        build=self.runtime['regmap_guest_build']
        request=dict(run_id=run_id,executable=build+'/bin/'+('regmap-client' if client else 'kcov-autorace-k05'),
            scenario_library=build+'/bin/'+('regmap-client' if client else 'regmap-v1.so'),
            plan_path=remote+'/plan.txt' if plan is not None else None,timeout_seconds=60,fault=fault)
        active=dict(run_id=run_id,remote=remote,request=remote+'/request.json',boot_id=state['boot_id'],operation=op)
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K05 round started; reset and cleanup not yet checked')
        persist(self.out/'guest-request.json',request)
        files={'request.json':json.dumps(request),'supervisor.py':(REPO/'adapters/maccconc/k05_guest.py').read_text(),
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
        self.mark('dirty',active=active,boot_id=state['boot_id'],reason='K05 supervisor active')
        guest=None
        collected=False
        try:
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                guest=self.poll_guest(remote)
                if guest is not None: break
                time.sleep(.25)
        except KeyboardInterrupt:
            self.ssh(['sudo','-n','python3',remote+'/supervisor.py','cancel','--request',remote+'/request.json'])
            raise
        finally:
            try:
                self.collect(remote)
                collected=True
            except Exception as error: persist(self.out/'collection-error.json',dict(error=str(error)))
        if guest is None: fail('recovery_required','No guest completion; checkpoint recovery is required')
        if not collected: fail('collection_incomplete','Guest collection did not complete; runtime remains dirty')
        expected_command = ([request['executable'],'fault-reset'] if fault=='setup' else [request['executable'],'baseline','--rounds','20']) if client else [request['executable'],request['scenario_library']]+(['--k03-replay',request['plan_path'],remote+'/trace'] if plan is not None else ['--k05-baseline',remote+'/trace'])
        if guest.get('run_id')!=run_id or guest.get('boot_id')!=state['boot_id'] or guest.get('command')!=expected_command or guest.get('fault')!=fault or read(self.out/'guest/guest-result.json')!=guest:
            fail('guest_result_mismatch','Guest observation/collected record does not bind to the submitted command')
        clean_process = (guest.get('kind')=='kconc.guest' and type(guest.get('schema_version')) is int
            and guest['schema_version']==1 and guest.get('outcome')=='completed'
            and type(guest.get('exit_code')) is int and guest['exit_code']==0
            and guest.get('remaining_pids')==[] and guest.get('local_cleanup',{}).get('confirmed') is True
            and guest['local_cleanup'].get('errors')==[])
        if client:
            from .regmap_client import validate_client
            result=read(self.out/'guest/executor.stdout.txt')
            validation=validate_client(result,fault=fault=='setup')
            passed=clean_process and validation['passed']
            data=dict(kind='kconc.regmap',operation=op,passed=passed,guest=guest,client=result,validation=validation)
        else:
            trace=self.out/'guest/trace'
            if plan is None: trace=trace/'baseline'
            mapper=self.task['inputs']['source_mapper']
            session=object.__new__(self.k03.Session)
            session.out,session.commands,session.lab=self.out,[],self.lab
            session.args=SimpleNamespace(source_mapper=Path(mapper),kernel_build=Path(self.runtime['kernel_build']))
            if clean_process and trace.is_dir() and (trace/'A.events.jsonl').exists():
                mapping=session.source_map([trace])
                result=analysis.analyze(trace,mapping,guest,replay=plan is not None)
            else: result=dict(passed=False,errors=['Trace absent or incomplete; initialization failure is not a source bug'])
            passed=clean_process and result['passed']
            data=dict(kind='kconc.regmap',operation=op,passed=passed,guest=guest,analysis=result)
            if passed and op=='regmap.record':
                binding=analysis.make_plan(trace,self.out/'source-map.jsonl',self.out/'binding')
                persist(self.out/'binding/runtime-identity.json',profile['identity'])
                binding.update(runtime_identity_bound=True,runtime_identity_sha256=digest(self.out/'binding/runtime-identity.json'))
                persist(self.out/'binding/binding.json',binding)
                data['binding']=binding
            if plan is not None and (trace/'plan.txt').read_bytes()!=plan:
                fail('binding_mismatch','Executed plan bytes differ from submitted bound plan')
        # A deliberately failed reset remains quarantined even if the client proved close/open repair.
        data['recovery_required']=not passed or fault!='none'
        data['kernel_bug_claim']=False
        persist(self.out/'regmap-result.json',data)
        self.last_result=data
        if not data['recovery_required']:
            self.mark('ready',boot_id=state['boot_id'],result=str(self.out/'regmap-result.json'))
        else: self.mark('dirty',boot_id=state['boot_id'],active=active,reason='K05 failure or reset-fault test requires explicit recovery')
        return data


def dispatch(task,out,envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=RegmapRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError: fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='regmap.initialize': data=runtime.initialize()
                    elif op=='regmap.status': data=dict(state=read(runtime.statepath),vm=runtime.lab.running())
                    elif op=='regmap.recover': data=runtime.recover()
                    else: data=runtime.execute()
                    envelope['data']=data
                    if data.get('passed') is False: fail('regmap_validation_failed','Inspect retained K05 evidence; recovery may be required')
        except BaseException:
            if hasattr(runtime,'last_result'): envelope['data']=runtime.last_result
            elif runtime.statepath.exists(): envelope['data']['runtime_state']=read(runtime.statepath)
            raise

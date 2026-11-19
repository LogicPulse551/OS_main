"""K11: re-observe a repaired build, then test the original input and property.

Old machine locations are evidence, never a plan for another build. All fresh
attempts are kept; a missed target or incomplete run cannot establish a repair.
"""
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import json
import uuid

from . import candidates
from .legacy_reference import load_reference
from .lifecycle import REPO, read, persist, digest, fail, load, now, lab_environment
from .sampling import SampleRuntime, candidate_from_analysis
from .search import SearchRuntime

PROFILE_ID = 'kconc.k11.regmap-repair-v1'


def logical_contract(bundle):
    identity = bundle['candidate']['identity']
    entry = candidates.validate_input(identity['input'])
    return dict(input=entry, order=identity['baseline_order'],
        property_id='serial-masked-update' if entry['family']=='rmw' else 'mutual-exclusion',
        requirement='Final values must equal a legal serial execution' if entry['family']=='rmw'
            else 'At most one admitted caller in the critical region; busy peer makes progress in a fresh epoch')


def summarize(attempts, requested):
    complete = len(attempts)==requested and all(a['classification']!='running' for a in attempts)
    failures = sum(a.get('property_evaluated') is True and a.get('property_violation') is True for a in attempts)
    good = sum(a.get('classification')=='hit' and a.get('candidate_hit') is True and a.get('property_evaluated') is True
        and a.get('property_violation') is False and a.get('cleanup_verified') is True
        and a.get('recovery_required') is False for a in attempts)
    classification = ('regression-failed' if failures else
        'bounded-pass' if complete and good==requested else 'inconclusive')
    return dict(requested_attempts=requested, attempts=len(attempts), unattempted=requested-len(attempts),
        classification=classification, bounded_pass=classification=='bounded-pass',
        full_candidate_hits=sum(a.get('candidate_hit') is True for a in attempts),
        valid_property_evaluations=sum(a.get('property_evaluated') is True for a in attempts),
        property_violations=failures, valid_repaired_attempts=good, completed=complete,
        outcomes=dict(Counter(a['classification'] for a in attempts)),
        denominator_scope='Every attempt including timeout, path miss, invalid evidence and infrastructure error',
        complete_search=False, source_correctness_proved=False)


class RegressionRuntime(SearchRuntime):
    lab_prefix='os-concurrency-k11'
    state_file='run/k11-state.json'
    profile_file='k11-runtime.json'

    def identity(self):
        # Implemented independently: K11 changes the scenario interpretation in
        # four mutex libraries; the K08/K09 byte-equality bridge must stay strict.
        from .repair_identity import current_identity
        identity, binding = current_identity(self)
        persist(self.out/'repair-binding.json', binding)
        self.repair_binding = binding
        return identity

    def analyzer(self):
        module = load('k11_analysis', REPO/'adapters/maccconc/k11_analysis.py')
        binding = getattr(self, 'repair_binding', None)
        if binding is None:
            self.identity()
            binding = self.repair_binding
        return module, module.verify_profile(binding)

    def analyze_sample(self, trace, mapping, guest, family, order):
        module, profile = self.analyzer()
        return module.analyze_sample(trace, mapping, guest, family, order, profile)

    def analyze_candidate(self, trace, mapping, guest, candidate):
        module, profile = self.analyzer()
        return module.analyze_execution(trace, mapping, guest, candidate, profile)

    def candidate_eligibility(self, candidate, identity):
        candidates.validate_candidate(candidate)
        expected = candidate['identity']['build_identity']
        repair = identity.get('repair_profile', {})
        valid = (expected == identity and repair.get('profile_id') == PROFILE_ID
            and candidate['identity']['input']['family'] == repair.get('family'))
        return dict(supported=valid, reason='exact-new-repair-build' if valid else 'mapping-invalid')

    def validate_fresh_sample(self, directory, identity, scenario):
        trace=directory/'guest/trace/baseline'
        pool=read(directory/'candidate.json')
        if len(pool.get('candidates', []))!=1:fail('invalid_regression_sample','One new candidate required')
        candidate=pool['candidates'][0];candidates.validate_candidate(candidate)
        source=candidate['sources'][0]
        for name in candidates.TRACE_FILES:
            if digest(trace/name)!=source['trace_sha256'][name]:fail('invalid_regression_sample','New raw trace changed')
        for field,name in [('source_map_sha256','source-map.jsonl'),('runtime_identity_sha256','runtime-identity.json'),
            ('guest_sha256','guest/guest-result.json'),('task_sha256','task.json'),('analysis_sha256','analysis.json')]:
            if digest(directory/name)!=source[field]:fail('invalid_regression_sample','New source binding changed: '+name)
        mapping={}
        for line in (directory/'source-map.jsonl').read_text().splitlines():
            row=json.loads(line)
            if row['raw_ip'] in mapping:fail('invalid_regression_sample','Duplicate mapping row')
            mapping[row['raw_ip']]=row
        result=self.analyze_sample(trace,mapping,directory/'guest/guest-result.json',scenario['family'],scenario['order'])
        matches=all(result.get('observations',{}).get(k)==v for k,v in scenario.items())
        result['checks']['submitted_scenario_matches']=matches;result['passed']=result['passed'] and matches
        if not result['passed'] or result!=read(directory/'analysis.json'):
            fail('invalid_regression_sample','Fresh sample does not reproduce under the bound repaired-build analyzer')
        provenance={k:v for k,v in source.items() if k not in {'trace_path','trace_sha256','analysis_sha256'}}
        rebuilt=candidate_from_analysis(result,trace,identity,directory/'analysis.json',provenance)
        if rebuilt!=candidate:fail('invalid_regression_sample','Candidate differs from its recomputed new observation')
        return candidate

    def regress(self):
        bundle=load_reference(self.task['inputs']['bundle'],self.out)
        contract=logical_contract(bundle)
        profile,state=self.ready_profile()
        identity=profile['identity'];entry=contract['input'];family=entry['family']
        if not self.labdir.name.endswith('-'+family):fail('regression_family_mismatch','Reference belongs to another kernel family')
        if identity==bundle['runtime_identity']:fail('repair_build_required','Regression requires a separately bound repaired build')
        scenario={k:entry[k] for k in ('family','case_id','mode')};scenario['order']=contract['order']
        comparison=dict(kind='kconc.cross-build-contract',contract=contract,
            reference_bundle_id=bundle['bundle_id'],reference_candidate_id=bundle['candidate']['candidate_id'],
            reference_build=bundle['runtime_identity'],new_build=identity,
            old_location_status='mapping-invalid',old_schedule_executed=False,
            old_property_violation=bundle['source']['property_violation'],
            mapping_invalid_is_repair_failure=False,
            explanation='Different kernel/native identity: collect a new target and complete prefix; compare original inputs and property, not instruction addresses')
        persist(self.out/'cross-build.json',comparison);persist(self.out/'runtime-identity.json',identity)
        requested=self.task['scenario']['repetitions'];attempts=[]
        data=dict(schema_version=1,kind='kconc.regression',started_utc=now(),passed=False,
            requested_attempts=requested,attempts=attempts,contract=contract,
            cross_build_sha256=digest(self.out/'cross-build.json'),sample=None,interrupted_reason=None,
            scope='Bounded repair regression for the same logical requests; neither old-path replay nor a proof of all source executions')
        def save():
            data['summary']=summarize(attempts,requested)
            persist(self.out/'regression-result.json',data);self.last_result=data
        save()
        # A serial sample is a new observation, not an attempted interleaving.
        directory=self.out/'sample';directory.mkdir()
        sample_task=dict(self.task,operation='regression.sample',scenario=scenario)
        persist(directory/'task.json',sample_task)
        runner=RegressionRuntime(sample_task,directory)
        try:
            sampled=SampleRuntime.execute(runner)
            data['sample']=dict(directory=str(directory),passed=sampled['passed'],result_sha256=digest(directory/'sample-result.json'))
            if not sampled['passed']:fail('regression_sample_failed','New build sample invalid; no old plan may substitute for it')
            candidate=self.validate_fresh_sample(directory,identity,scenario)
            if candidate['identity']['input']!=entry:fail('regression_input_mismatch','New candidate changes original requests')
            comparison.update(new_candidate_id=candidate['candidate_id'],new_candidate_sha256=digest(directory/'candidate.json'),
                new_target_status='freshly-observed',same_high_level_input=True,same_declared_property=True)
            persist(self.out/'cross-build.json',comparison);data['cross_build_sha256']=digest(self.out/'cross-build.json')
            save()
            for ordinal in range(1,requested+1):
                attempt_dir=self.out/f'attempt-{ordinal:03d}';attempt_dir.mkdir()
                row=dict(ordinal=ordinal,attempt_id=uuid.uuid4().hex,directory=str(attempt_dir),
                    classification='running',candidate_hit=False,property_evaluated=False,property_violation=None,
                    cleanup_verified=False,recovery_required=True,started_utc=now())
                attempts.append(row);save()
                persist(attempt_dir/'task.json',dict(self.task,ordinal=ordinal,attempt_id=row['attempt_id'],candidate_id=candidate['candidate_id']))
                execution=None
                try:
                    execution=RegressionRuntime(self.task,attempt_dir)
                    result=execution.run_candidate(candidate);analysis=result['analysis']
                    row.update({k:analysis[k] for k in ('classification','candidate_hit','property_evaluated',
                        'property_violation','cleanup_verified','recovery_required')})
                    row.update(guest_started=True,analysis_path=str(attempt_dir/'analysis.json'),
                        analysis_sha256=digest(attempt_dir/'analysis.json'),result_sha256=digest(attempt_dir/'attempt-result.json'))
                except BaseException as error:
                    row.update(classification='infrastructure-error',guest_started=getattr(execution,'guest_started',False))
                    persist(attempt_dir/'exception.json',dict(type=type(error).__name__,message=str(error)))
                    raise
                finally:
                    row['finished_utc']=now();save()
                if row['recovery_required']:
                    data['interrupted_reason']='Attempt needs explicit recovery; remaining attempts are unattempted'
                    break
        except BaseException as error:
            data['interrupted_reason']=f'{type(error).__name__}: {error}'
            self.mark('dirty',boot_id=state['boot_id'],reason=data['interrupted_reason'])
            save()
            raise
        finally:
            data.update(finished_utc=now(),recovery_required=read(self.statepath).get('state')!='ready')
            data['passed']=(summarize(attempts,requested)['bounded_pass'] and data['interrupted_reason'] is None
                and data['recovery_required'] is False)
            save()
        return data


def dispatch(task,out,envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=RegressionRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:fail('runtime_busy','VM control lock is held')
                    op=task['operation']
                    if op=='regression.initialize':data=runtime.initialize()
                    elif op=='regression.status':
                        runtime.profile();data=dict(state=read(runtime.statepath),vm=runtime.lab.running(),execution_readiness_verified=False)
                    elif op=='regression.recover':data=runtime.recover()
                    else:data=runtime.regress()
                    envelope['data']=data
                    if data.get('passed') is False:
                        fail('regression_not_accepted','Bounded regression did not pass; failed and unattempted executions remain in the result')
        except BaseException:
            if hasattr(runtime,'last_result'):envelope['data']=runtime.last_result
            elif runtime.statepath.exists():envelope['data']['runtime_state']=read(runtime.statepath)
            raise

"""Finite, evidence-preserving reduction of the accepted regmap caller witnesses.

Each edit is tested independently against the original input. A fresh serial
sample binds changed inputs; no original address plan is transferred to them.
This runtime neither rebuilds kernels nor changes the K09/K10 match policy.
"""
from pathlib import Path

from .lifecycle import REPO, read, persist, digest, fail, lab_environment
from .search import SearchRuntime
from .sampling import SampleRuntime, candidate_from_analysis
from .legacy_reference import load_reference
from . import candidates, replay_bundle, search_queue, witness_reduction as policy


def verify_attempt(directory, eligible):
    """Recompute K13 evidence under unchanged K09 analysis and full-plan checks."""
    directory = Path(directory)
    candidate = read(directory/'candidate.json'); candidates.validate_candidate(candidate)
    identity = read(directory/'runtime-identity.json'); task = read(directory/'task.json')
    if not eligible(candidate, identity)['supported']:
        fail('reduction_revalidation_failed', 'Attempt is not bound to its kernel/native identity')
    if task.get('operation') != 'kernel.reduce' or task.get('candidate_id') != candidate['candidate_id']:
        fail('reduction_revalidation_failed', 'Attempt task does not bind the candidate')
    trace = directory/'guest/trace'; guest = read(directory/'guest/guest-result.json')
    request = read(directory/'guest-request.json'); entry = candidate['identity']['input']
    order = candidate['identity']['baseline_order']; build = task['runtime']['search_guest_build']
    remote = '/home/lab/k09/run-' + request['run_id']
    expected = [build+'/bin/kcov-execute-k09-'+order, build+'/bin/'+entry['native_so'],
                '--k09-execute', order, remote+'/plan.txt', remote+'/trace']
    if (guest.get('command') != expected or guest.get('run_id') != request['run_id']
            or request['executable'] != expected[0] or request['scenario_library'] != expected[1]
            or request['plan_path'] != expected[4] or guest.get('fault') != 'none' or request['fault'] != 'none'):
        fail('reduction_revalidation_failed', 'Request/guest execution binding changed')
    mapping = replay_bundle._mapping(directory/'source-map.jsonl')
    report = replay_bundle.k09.analyze(trace, mapping, guest, candidate)
    plan = search_queue.make_plan(candidate)
    matches = (directory/'input-plan.txt').read_bytes() == (trace/'plan.txt').read_bytes() == plan
    if not matches:fail('reduction_revalidation_failed', 'Executed full candidate plan changed')
    report['checks']['executed_plan_matches_submitted'] = True
    report.update(runtime_identity_bound=True, runtime_identity_sha256=digest(directory/'runtime-identity.json'),
        candidate_file_sha256=digest(directory/'candidate.json'), plan_sha256=digest(directory/'input-plan.txt'))
    result = read(directory/'attempt-result.json')
    if (report != read(directory/'analysis.json') or result.get('analysis') != report
            or result.get('guest') != guest or result.get('guest_started') is not True
            or result.get('candidate_id') != candidate['candidate_id']
            or any(result.get(k) != report[k] for k in ('passed','classification','recovery_required'))):
        fail('reduction_revalidation_failed', 'Attempt report no longer matches its raw execution')
    return dict(candidate=candidate, analysis=report, mapping=mapping, trace=trace)


def observation(data, property_id, *, serial=False):
    a = data['analysis']
    prop = a.get('property' if serial else 'observed_property', {})
    valid = a.get('property_evaluated') is True
    return dict(actual_execution=data.get('actual_execution') is True,
        control_valid=a.get('control_valid') is True,
        schedule_validated=(a.get('groups', {}).get('schedule_outcome') is True if serial
                            else a.get('schedule_valid') is True),
        candidate_hit=None if serial else a.get('candidate_hit') is True,
        property_evaluated=valid, property_violation=valid and a.get('property_violation') is True,
        property_id=prop.get('error_type') if a.get('property_violation') else property_id,
        cleanup_verified=data.get('cleanup_verified') is True,
        recovery_required=data.get('recovery_required') is not False)


def valid_execution(obs, *, candidate_required=True):
    return (obs['actual_execution'] and obs['control_valid'] and obs['schedule_validated']
        and (not candidate_required or obs['candidate_hit'] is True) and obs['property_evaluated']
        and obs['cleanup_verified'] and not obs['recovery_required'])


def failing(obs, property_id):
    return valid_execution(obs) and obs['property_violation'] and obs['property_id'] == property_id


def record_launch(directory, runner, completed=False):
    # An SSH response can be lost after the supervisor launches. Preserve that
    # uncertainty; absence of a completion record is not evidence of zero runs.
    started = (True if completed or getattr(runner, 'guest_started', False)
        or (directory/'guest/guest-result.json').exists()
        else None if (directory/'guest-request.json').exists() else False)
    persist(directory/'execution-launch.json', dict(guest_started=started, runner_returned=completed))


class ReductionRuntime(SearchRuntime):
    lab_prefix = 'os-concurrency-k13'
    state_file = 'run/k13-state.json'
    profile_file = 'k13-runtime.json'

    def candidate_eligibility(self, candidate, identity):
        candidates.validate_candidate(candidate)
        if candidate['identity']['build_identity'] == identity:
            return dict(supported=True, reason='exact-new-observed-same-build')
        return super().candidate_eligibility(candidate, identity)

    def reference(self):
        bundle = load_reference(self.task['inputs']['bundle'], self.out)
        profile, _ = self.ready_profile()
        candidate = bundle['candidate']; entry = candidate['identity']['input']
        if (bundle['source']['property_violation'] is not True
                or bundle['runtime_identity'] != profile['identity']
                or not self.candidate_eligibility(candidate, profile['identity'])['supported']
                or not self.labdir.name.endswith('-' + entry['family'])):
            fail('reduction_reference_mismatch', 'Reduction requires this exact original failing build and family')
        persist(self.out/'runtime-identity.json', profile['identity'])
        return bundle, read(Path(bundle['_directory'])/'signature.json')

    def execute_candidate(self, candidate, directory):
        persist(directory/'task.json', dict(self.task, candidate_id=candidate['candidate_id']))
        runner = type(self)(self.task, directory)
        completed = False
        try:
            data = runner.run_candidate(candidate); completed = True
        finally:record_launch(directory, runner, completed)
        # Recompute from the stored raw records, including the full input plan.
        evidence = verify_attempt(directory, self.candidate_eligibility)
        if evidence['analysis'] != data['analysis']:
            fail('reduction_revalidation_failed', 'Candidate evidence changed after execution')
        result = dict(data, actual_execution=data.get('guest_started') is True,
            cleanup_verified=data['analysis']['cleanup_verified'])
        if data['analysis']['execution_valid'] and result['cleanup_verified']:
            result['signature'] = replay_bundle.signature(directory, evidence)
            persist(directory/'signature.json', result['signature'])
        return result

    def execute_sample(self, entry, order, directory):
        task = dict(self.task, operation='reduction.sample', scenario=dict(family=entry['family'],
            case_id=entry['case_id'], mode=entry['mode'], order=order))
        persist(directory/'task.json', task)
        runner = type(self)(task, directory)
        completed = False
        try:
            data = SampleRuntime.execute(runner); completed = True
        finally:record_launch(directory, runner, completed)
        guest = read(directory/'guest/guest-result.json')
        clean = (guest.get('outcome') == 'completed' and type(guest.get('exit_code')) is int
            and guest['exit_code'] == 0 and guest.get('remaining_pids') == []
            and guest.get('local_cleanup', {}).get('confirmed') is True
            and guest['local_cleanup'].get('errors') == [])
        if data['passed']:
            mapping = replay_bundle._mapping(directory/'source-map.jsonl')
            trace = directory/'guest/trace/baseline'
            observed = runner.analyze_sample(trace, mapping, guest, entry['family'], order)
            matches = all(observed.get('observations', {}).get(k) == v for k,v in task['scenario'].items())
            observed['checks']['submitted_scenario_matches'] = matches
            observed['passed'] = observed['passed'] and matches
            if observed != data['analysis']:fail('reduction_revalidation_failed', 'Fresh sample raw analysis changed')
            saved = read(directory/'candidate.json')['candidates'][0]
            source = saved['sources'][0]
            provenance = {k:v for k,v in source.items() if k not in {'trace_path','trace_sha256','analysis_sha256'}}
            rebuilt = candidate_from_analysis(observed, trace, read(directory/'runtime-identity.json'),
                directory/'analysis.json', provenance)
            if rebuilt != saved or saved['identity']['input'] != entry:
                fail('reduction_revalidation_failed', 'Changed input was not observed in the fresh candidate')
            data['candidate'] = saved
        return dict(data, actual_execution=True, cleanup_verified=clean)

    def execute(self):
        bundle, original_signature = self.reference()
        candidate = bundle['candidate']; identity = candidate['identity']; entry = identity['input']
        order = identity['baseline_order']; prop = policy.RMW_PROPERTY if entry['family'] == 'rmw' else policy.MUTEX_PROPERTY
        scenario = self.task['scenario']; budget = scenario['max_trials']; repeats = scenario['replay_repetitions']
        edits = policy.input_edits(entry) + policy.schedule_edits(order)
        ledger = dict(schema_version=1, kind='kconc.reduction-ledger', policy_id=policy.POLICY_ID,
            original_bundle=str(bundle['_directory']), original_candidate_id=candidate['candidate_id'],
            original_input=entry, property_id=prop, budget=scenario, original_confirmations=[],
            trials=[dict(edit=e, status='pending' if i < budget else 'unattempted-budget',
                         runs=[], confirmations=[]) for i,e in enumerate(edits)], executions=[],
            retained_witness=dict(kind='original', bundle=str(bundle['_directory'])),
            global_minimum_proved=False, source_correctness_proved=False,
            independent_edits=True, unsupported=['Deleting required ioctl calls or roles',
                'Deleting initial state or stack identity frames', 'Unregistered bit subsets'])
        self.last_result = dict(kind='kconc.reduction', passed=False, reduction_status='incomplete',
            ledger=str(self.out/'ledger.json'), recovery_required=False)
        error = None

        def save():persist(self.out/'ledger.json', ledger)

        def run(kind, label, *, chosen=None, selected_input=None):
            directory = self.out/label; directory.mkdir()
            persist(directory/'task.json', self.task)
            row = dict(kind=kind, label=label, directory=str(directory), status='started')
            ledger['executions'].append(row); save()
            try:
                data = (self.execute_candidate(chosen, directory) if kind == 'candidate'
                        else self.execute_sample(selected_input, order, directory))
                obs = observation(data, prop, serial=kind == 'serial')
                row.update(status='completed', observation=obs,
                    guest_started=obs['actual_execution'], analysis_sha256=digest(directory/'analysis.json'))
                if 'signature' in data:row['signature_sha256'] = digest(directory/'signature.json')
                persist(directory/'reduction-observation.json', obs); save()
                return data, obs
            except BaseException as exc:
                launch = directory/'execution-launch.json'
                row.update(status='infrastructure-error', guest_started=read(launch)['guest_started'] if launch.exists() else None,
                    exception=dict(type=type(exc).__name__,message=str(exc)))
                persist(directory/'exception.json', row['exception']); save()
                raise

        save()
        try:
            if budget:
                for i in range(repeats):
                    data, obs = run('candidate', 'original-%02d' % (i+1), chosen=candidate)
                    full_match = data.get('signature') == original_signature
                    ledger['original_confirmations'].append(dict(observation=obs, full_match=full_match))
                    save()
                    if not failing(obs, prop) or not full_match:
                        fail('original_witness_unconfirmed', 'Original full-path/property confirmation failed; no edits admitted')
                for index, trial in enumerate(ledger['trials']):
                    if trial['status'] != 'pending':continue
                    trial['status'] = 'running'; edit = trial['edit']; prefix = 'trial-%02d-' % (index+1); save()
                    if edit['kind'] == 'input-mask-subset':
                        data, obs = run('serial', prefix+'sample', selected_input=edit['after_input'])
                        trial['runs'].append(prefix+'sample'); save()
                        if not data['passed']:
                            trial['status'] = 'failed-sample'; save()
                            fail('reduction_sample_invalid', 'Changed-input sample failed; all records retained')
                        changed_candidate = data['candidate']
                        data, obs = run('candidate', prefix+'candidate', chosen=changed_candidate)
                        trial['runs'].append(prefix+'candidate')
                    else:
                        data, obs = run('serial', prefix+'serial', selected_input=entry)
                        trial['runs'].append(prefix+'serial')
                    decision = policy.decide(edit, obs, prop)
                    trial.update(observation=obs, decision=decision, status='rejected'); save()
                    if not valid_execution(obs, candidate_required=edit['kind'] == 'input-mask-subset'):
                        trial['status'] = 'failed-validation'; save()
                        fail('reduction_trial_invalid', 'Invalid execution is retained as failure, not an effective rejection')
                    if decision['accepted']:
                        trial['status'] = 'confirming'; save()
                        # Serial accepted witnesses are outside the current strict sampler
                        # contract (it requires a legal serial state). Do not assert one.
                        if edit['kind'] != 'input-mask-subset':
                            fail('unsupported_serial_failure', 'Serial property failure requires a separate protocol')
                        reference_signature = data.get('signature'); confirmed = True
                        for i in range(repeats):
                            confirmation, seen = run('candidate', prefix+'confirm-%02d' % (i+1), chosen=changed_candidate)
                            full_match = reference_signature is not None and confirmation.get('signature') == reference_signature
                            trial['confirmations'].append(dict(observation=seen, full_match=full_match)); save()
                            if not valid_execution(seen):
                                trial['status'] = 'failed-confirmation'
                                trial['decision'] = dict(decision, accepted=False, reason='confirmation-execution-invalid')
                                save()
                                fail('reduction_confirmation_invalid', 'Invalid confirmation retained as failure; original witness kept')
                            confirmed = confirmed and failing(seen, prop) and full_match
                        if confirmed and len(trial['confirmations']) == repeats:
                            trial['status'] = 'accepted'
                            best = ledger['retained_witness']
                            if best['kind'] == 'original' or edit['cost_after'] < best['cost_after']:
                                ledger['retained_witness'] = dict(kind='reduced', edit_id=edit['edit_id'],
                                    input=edit['after_input'], cost_after=edit['cost_after'],
                                    candidate=prefix+'candidate/candidate.json',
                                    signature=prefix+'candidate/signature.json')
                        else:
                            trial['status'] = 'rejected-confirmation'
                            trial['decision'] = dict(decision, accepted=False, reason='reduced-confirmation-failed')
                    save()
                    if read(self.statepath).get('state') != 'ready':
                        fail('recovery_required', 'Reduction stopped after incomplete execution')
        except BaseException as exc:
            error = exc
            ledger['interruption'] = dict(type=type(exc).__name__, message=str(exc))
        finally:
            for trial in ledger['trials']:
                if trial['status'] == 'pending':trial['status'] = 'unattempted-interruption'
                elif trial['status'] in ('running', 'confirming'):
                    trial['status'] = 'failed-execution'
                    if 'decision' in trial:
                        trial['decision'] = dict(trial['decision'], accepted=False, reason='execution-interrupted')
            counts = dict(actual_candidates=sum(r['kind']=='candidate' and r.get('guest_started') is True for r in ledger['executions']),
                serial_trials=sum(r['kind']=='serial' and r.get('guest_started') is True for r in ledger['executions']),
                launch_unknown=sum(r.get('guest_started') is None for r in ledger['executions']),
                completed_executions=sum(r['status']=='completed' for r in ledger['executions']),
                execution_slots=len(ledger['executions']),
                accepted=sum(t['status']=='accepted' for t in ledger['trials']),
                rejected=sum(t['status'].startswith('rejected') for t in ledger['trials']),
                failed=sum(t['status'].startswith('failed') for t in ledger['trials']),
                unattempted=sum(t['status'].startswith('unattempted') for t in ledger['trials']))
            ledger['summary'] = counts; save()
            self.last_result.update(passed=error is None, ledger_sha256=digest(self.out/'ledger.json'), summary=counts,
                recovery_required=read(self.statepath).get('state') != 'ready',
                reduction_status=('incomplete' if error else 'reduced' if counts['accepted'] else 'not-reduced'),
                scope='Finite registered deletions only; independent edits, complete attempt ledger; no shortest-witness or source correctness claim')
            persist(self.out/'reduction-result.json', self.last_result)
        if error:raise error
        return self.last_result


def dispatch(task, out, envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime = ReductionRuntime(task, out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try:fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:fail('runtime_busy', 'VM lifecycle control lock is held')
                    op = task['operation']
                    if op == 'reduction.initialize':data = runtime.initialize()
                    elif op == 'reduction.status':
                        runtime.profile(); data = dict(state=read(runtime.statepath), vm=runtime.lab.running(), execution_readiness_verified=False)
                    elif op == 'reduction.recover':data = runtime.recover()
                    else:data = runtime.execute()
                    envelope['data'] = data
                    if data.get('passed') is False:fail('reduction_incomplete', 'Inspect the complete retained reduction ledger')
        except BaseException:
            if hasattr(runtime, 'last_result'):envelope['data'] = runtime.last_result
            elif runtime.statepath.exists():envelope['data']['runtime_state'] = read(runtime.statepath)
            raise

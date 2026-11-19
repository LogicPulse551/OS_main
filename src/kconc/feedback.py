"""K12 bounded feedback scheduling over the accepted K11 execution backend."""
import uuid
from pathlib import Path
from . import feedback_evidence as evidence, feedback_queue as queue
from .lifecycle import read, persist, digest, fail, lab_environment
from .regression import RegressionRuntime


class FeedbackRuntime(RegressionRuntime):
    lab_prefix = 'os-concurrency-k12'
    state_file = 'run/k12-state.json'
    profile_file = 'k12-runtime.json'

    def execute(self):
        profile, _ = self.ready_profile()
        config = self.task['scenario']; family = config['family']
        if not self.labdir.name.endswith('-'+family):
            fail('feedback_family_mismatch', 'Select the dedicated family VM')
        inputs = self.task['inputs']
        pool, source_record = evidence.load_samples(read(inputs['samples']))
        history, history_record = evidence.load_history(read(inputs['history']), pool)
        persist(self.out/'imported-pool.json', pool)
        persist(self.out/'source-validation.json', source_record)
        persist(self.out/'history-validation.json', history_record)
        eligible = {c['candidate_id']: self.candidate_eligibility(c, profile['identity'])['supported'] for c in pool['candidates']}
        ledger = queue.make_queue(pool, family, config['total_budget'], pool_limit=config['pool_limit'],
            per_input_budget=config['per_input_budget'], feedback=config['feedback'],
            features=source_record['features'], history=history, eligible=eligible,
            rotation_interval=config['rotation_interval'])
        ledger['source_index_sha256'] = digest(Path(inputs['samples']))
        ledger['history_index_sha256'] = digest(Path(inputs['history']))
        persist(self.out/'runtime-identity.json', profile['identity'])
        persist(self.out/'ledger.json', ledger)
        by_id = {c['candidate_id']:c for c in pool['candidates']}
        interruption = None; error = None
        while (row := queue.next_candidate(ledger)) is not None:
            attempt_id = uuid.uuid4().hex
            queue.begin_attempt(ledger, row['candidate_id'], attempt_id)
            directory = self.out/f'attempt-{len(ledger["attempts"]):03d}'; directory.mkdir()
            persist(directory/'task.json', dict(self.task, attempt_id=attempt_id, candidate_id=row['candidate_id']))
            persist(self.out/'ledger.json', ledger)
            runner = None
            try:
                runner = FeedbackRuntime(self.task, directory)
                data = runner.run_candidate(by_id[row['candidate_id']]); result = data['analysis']
                queue.finish_attempt(ledger, attempt_id, result['classification'], guest_started=True,
                    cleanup_confirmed=result['cleanup_verified'], property_evaluated=result['property_evaluated'],
                    property_violation=result['property_violation'] if result['property_evaluated'] else None,
                    candidate_hit=result['candidate_hit'], recovery_required=result['recovery_required'],
                    observed_feature=evidence.execution_feature(directory,by_id[row['candidate_id']],result) if result['candidate_hit'] else None,
                    evidence=dict(directory=str(directory), analysis_sha256=digest(directory/'analysis.json'),
                                  result_sha256=digest(directory/'attempt-result.json')))
                if result['recovery_required']: interruption = 'Candidate requires checkpoint recovery'
            except BaseException as exc:
                error = exc; interruption = 'Candidate interrupted or infrastructure failed: '+str(exc)
                self.mark('dirty', reason=interruption)
                details = dict(type=type(exc).__name__, message=str(exc), guest_started=getattr(runner,'guest_started',False),
                    runtime_state=read(self.statepath) if self.statepath.exists() else None)
                persist(directory/'exception.json', details)
                queue.finish_attempt(ledger, attempt_id, 'infrastructure-error', guest_started=details['guest_started'],
                    cleanup_confirmed=False, candidate_hit=False, recovery_required=True,
                    evidence=dict(directory=str(directory), exception_sha256=digest(directory/'exception.json')))
            persist(self.out/'ledger.json', ledger)
            if interruption: break
        queue.finalize(ledger, interruption); persist(self.out/'ledger.json', ledger)
        data = dict(kind='kconc.feedback-search', passed=interruption is None,
            ledger=str(self.out/'ledger.json'), ledger_sha256=digest(self.out/'ledger.json'),
            runtime_identity_sha256=digest(self.out/'runtime-identity.json'),
            imported_pool_sha256=digest(self.out/'imported-pool.json'),
            history_validation_sha256=digest(self.out/'history-validation.json'), summary=ledger['summary'],
            recovery_required=read(self.statepath).get('state')!='ready',
            scope='Bounded scheduling/accounting only; no exhaustive coverage, source-correctness or performance claim')
        persist(self.out/'feedback-result.json', data); self.last_result=data
        if error is not None: raise error
        return data


def dispatch(task, out, envelope):
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=FeedbackRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError: fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='feedback.initialize': data=runtime.initialize()
                    elif op=='feedback.status':
                        runtime.profile();data=dict(state=read(runtime.statepath),vm=runtime.lab.running(),execution_readiness_verified=False)
                    elif op=='feedback.recover': data=runtime.recover()
                    else: data=runtime.execute()
                    envelope['data']=data
                    if data.get('passed') is False: fail('feedback_incomplete','Inspect all retained attempted and unexplored candidates')
        except BaseException:
            if hasattr(runtime,'last_result'): envelope['data']=runtime.last_result
            elif runtime.statepath.exists(): envelope['data']['runtime_state']=read(runtime.statepath)
            raise

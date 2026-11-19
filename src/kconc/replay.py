"""K10 original-build replay; the accepted K09 executor remains unchanged."""
from collections import Counter
from pathlib import Path
import uuid
from .search import SearchRuntime
from .lifecycle import read, persist, digest, fail, now, lab_environment


def summarize(attempts, requested):
    outcomes=Counter(a['classification'] for a in attempts)
    matches=sum(a.get('matched') is True for a in attempts)
    finished=all(a['classification']!='running' for a in attempts)
    complete=finished and len(attempts)==requested
    return dict(requested_attempts=requested,attempts=len(attempts),unattempted=requested-len(attempts),
        full_matches=matches,property_reproduced=sum(a.get('property_reproduced') is True for a in attempts),
        classification=dict(outcomes),completed=complete,minimum_attempts=20,minimum_match_ratio=.95,
        stability_accepted=complete and len(attempts)>=20 and matches*20>=len(attempts)*19,
        denominator_scope='All recorded attempts, including divergences, timeouts and infrastructure failures',
        future_probability_claimed=False)


class ReplayRuntime(SearchRuntime):
    lab_prefix='os-concurrency-k10'
    state_file='run/k10-state.json'
    profile_file='k10-runtime.json'

    def replay(self):
        from . import replay_bundle as bundles
        bundle=bundles.load_bundle(self.task['inputs']['bundle'])
        profile,state=self.ready_profile()
        if profile['identity']!=bundle['runtime_identity']:
            fail('replay_build_mismatch','Replay requires the exact original K09 kernel, executor and scenario build')
        candidate=bundle['candidate'];family=candidate['identity']['input']['family']
        if not self.labdir.name.endswith('-'+family):fail('replay_family_mismatch','Use the dedicated VM for this kernel family')
        requested=self.task['scenario']['repetitions'];attempts=[];interruption=None;error=None
        manifest=Path(bundle['_directory'])/'bundle.json'
        data=dict(schema_version=1,kind='kconc.replay',bundle=str(manifest),bundle_sha256=digest(manifest),
            candidate_id=candidate['candidate_id'],requested_attempts=requested,started_utc=now(),
            passed=False,attempts=attempts,interrupted_reason=None,
            scope='New scenario process and initialization each attempt; original-build key-path replay, not whole-machine determinism or K11 regression')
        persist(self.out/'runtime-identity.json',profile['identity'])
        def save():
            data['summary']=summarize(attempts,requested);persist(self.out/'replay-result.json',data);self.last_result=data
        save()
        for ordinal in range(1,requested+1):
            row=dict(ordinal=ordinal,attempt_id=uuid.uuid4().hex,classification='running',matched=False,
                property_reproduced=False,guest_started=None,recovery_required=None,started_utc=now())
            directory=self.out/f'attempt-{ordinal:03d}';directory.mkdir()
            row['directory']=str(directory);attempts.append(row);save()
            runner=None
            try:
                persist(directory/'task.json',dict(self.task,attempt_id=row['attempt_id'],ordinal=ordinal,candidate_id=candidate['candidate_id']))
                runner=ReplayRuntime(self.task,directory)
                result=runner.run_candidate(candidate)
                row.update(guest_started=True,recovery_required=result['recovery_required'],
                    candidate_classification=result['classification'],attempt_result_sha256=digest(directory/'attempt-result.json'))
                comparison=bundles.compare(bundle,directory)
                persist(directory/'comparison.json',comparison)
                row.update(comparison_sha256=digest(directory/'comparison.json'),matched=comparison['full_match'] and result['classification']=='hit' and not result['recovery_required'],
                    property_reproduced=comparison['property_reproduced'],comparison_classification=comparison['classification'])
                row['classification']=('matched' if row['matched'] else result['classification']
                    if result['classification'] not in ('hit','miss') else 'path-diverged')
                if comparison['classification']=='invalid' or comparison.get('errors'):
                    row.update(classification='invalid',matched=False,recovery_required=True)
                    interruption='Replay evidence comparison invalid; explicit checkpoint recovery required'
                    self.mark('dirty',boot_id=state['boot_id'],reason=interruption,result=str(directory/'comparison.json'))
                elif result['recovery_required']:interruption='Attempt requires explicit checkpoint recovery'
            except BaseException as exc:
                error=exc;interruption=f'{type(exc).__name__}: {exc}'
                row.update(classification='infrastructure-error',matched=False,guest_started=getattr(runner,'guest_started',False),recovery_required=True)
                persist(directory/'exception.json',dict(type=type(exc).__name__,message=str(exc)))
                # If comparison or collection is uncertain, do not leave a ready
                # state that would permit a new process without explicit recovery.
                self.mark('dirty',boot_id=state['boot_id'],reason=interruption,result=str(directory/'exception.json'))
            row['finished_utc']=now();data['interrupted_reason']=interruption;save()
            if interruption:break
        data.update(passed=interruption is None,finished_utc=now(),recovery_required=read(self.statepath).get('state')!='ready')
        save()
        if error is not None:raise error
        return data


def dispatch(task,out,envelope):
    if task['operation']=='replay.bind':
        from .replay_bundle import create_bundle
        bundle=create_bundle(task['inputs']['attempt'],out/'bundle')
        path=Path(bundle['_directory'])/'bundle.json'
        envelope['data']=dict(kind='kconc.replay-binding',passed=True,bundle=str(path),bundle_sha256=digest(path),
            candidate_id=bundle['candidate']['candidate_id'],actual_replay_performed=False)
        return
    from .cli import runtime_lock
    import fcntl
    with lab_environment(task['runtime']):
        runtime=ReplayRuntime(task,out)
        try:
            with runtime_lock(task['runtime']):
                with (runtime.labdir/'run/control.lock').open('a') as lock:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:fail('runtime_busy','VM lifecycle control lock is held')
                    op=task['operation']
                    if op=='replay.initialize':data=runtime.initialize()
                    elif op=='replay.status':
                        runtime.profile();data=dict(state=read(runtime.statepath),vm=runtime.lab.running(),execution_readiness_verified=False)
                    elif op=='replay.recover':data=runtime.recover()
                    else:data=runtime.replay()
                    envelope['data']=data
                    if data.get('passed') is False:fail('replay_incomplete','Replay interrupted; all attempts and unattempted count retained')
        except BaseException:
            if hasattr(runtime,'last_result'):envelope['data']=runtime.last_result
            elif runtime.statepath.exists():envelope['data']['runtime_state']=read(runtime.statepath)
            raise

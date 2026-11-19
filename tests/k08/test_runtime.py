"""K08 host and guest evidence gates; no VM, SSH or kernel execution."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import lifecycle, sampling
from kconc.cli import OperationError
from kconc.manifest import ManifestError, normalize_manifest


def save(path, value):
    Path(path).write_text(json.dumps(value), encoding='utf-8')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='k08-offline-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.labdir = self.base / 'os-concurrency-k08-rmw'
        self.out = self.base / 'output'
        self.kernel = self.base / 'kernel'
        for path in [self.out, self.kernel/'include/config', *[self.labdir/x for x in ('run', 'images', 'evidence', 'keys', 'seed')]]:
            path.mkdir(parents=True)
        (self.kernel/'include/config/kernel.release').write_text('7.2.0-rc3-kconc-k06+')
        self.fields = dict(lab_dir=str(self.labdir), ssh_port=2230, build_lab=str(self.base/'build'),
            kernel_build=str(self.kernel), scenario_guest_build='/home/lab/k03/build-old',
            sample_guest_build='/home/lab/k08/build-new')
        self.scenario = dict(family='rmw', case_id='disjoint-bits', mode='split', order='ab')
        self.task = dict(schema_version=1, operation='sample.run', runtime=self.fields,
            scenario=self.scenario, inputs={'source_mapper': str(self.base/'mapper')})
        save(self.out/'task.json', self.task)
        rt = self.rt = object.__new__(sampling.SampleRuntime)
        rt.task, rt.out, rt.runtime, rt.labdir = self.task, self.out, self.fields, self.labdir
        rt.statepath, rt.profilepath = self.labdir/rt.state_file, self.labdir/rt.profile_file
        self.identity = {'kernel_and_k03': 'offline identity'}
        rt.identity = Mock(return_value=self.identity)
        rt.boot_id = Mock(return_value='boot-a')
        rt.guest, rt.poll_guest, rt.collect = Mock(side_effect=self.launch), Mock(side_effect=self.poll), Mock(side_effect=self.collect)
        rt.ssh, rt.call = Mock(), Mock()
        rt.lab = SimpleNamespace(stop=Mock(), start=Mock(), process_alive=Mock(return_value=False), qmp=Mock())
        self.map = Mock(side_effect=self.map_source)
        rt.k03 = SimpleNamespace(Session=type('OfflineSession', (), {'source_map': self.map}))
        self.profile = dict(schema_version=1, lab_dir=str(self.labdir), runtime=self.fields, identity=self.identity,
            checkpoint=str(self.labdir/'images/baseline-frozen.qcow2'))
        save(rt.profilepath, self.profile)
        self.ready()
        self.marks = []
        self.guest = dict(outcome='completed', exit_code=0, remaining_pids=[], local_cleanup=dict(confirmed=True, errors=[]))
        self.guest_changes, self.collected_changes = {}, {}
        self.collection_error, self.trace_present = False, True
        self.analysis_value = dict(passed=True, execution_valid=True, property_evaluated=True,
            property_violation=False, checks={}, errors=[], observations=dict(self.scenario))
        self.analysis = SimpleNamespace(analyze=Mock(side_effect=lambda *a, **kw: copy.deepcopy(self.analysis_value)))
        self.candidate = dict(candidate_id='offline-candidate')
        self.export = Mock(side_effect=self.export_candidate)
        for module in (lifecycle, sampling):
            p=patch.object(module, 'persist', side_effect=self.persist);p.start();self.addCleanup(p.stop)
        for target, value in [('load', self.analysis), ('candidate_from_analysis', self.candidate)]:
            p=patch.object(sampling, target, return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(sampling.candidates, 'export_candidates', self.export);p.start();self.addCleanup(p.stop)

    def ready(self):
        save(self.rt.statepath, dict(state='ready', boot_id='boot-a'))

    def state(self):
        return json.loads(self.rt.statepath.read_text())

    def persist(self, path, value):
        save(path, value)
        if Path(path)==self.rt.statepath:self.marks.append(copy.deepcopy(value))

    def launch(self, code):
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertTrue((self.out/'guest-request.json').is_file())
        return dict(supervisor_pid=123)

    def poll(self, remote):
        request=json.loads((self.out/'guest-request.json').read_text())
        command=[request['executable'], request['scenario_library'], '--k08-baseline', self.scenario['order'], remote+'/trace']
        value=dict(self.guest, run_id=request['run_id'], boot_id='boot-a', fault='none', command=command)
        value.update(self.guest_changes)
        return value

    def collect(self, remote):
        directory=self.out/'guest';directory.mkdir(exist_ok=True)
        value=self.poll(remote);value.update(self.collected_changes)
        save(directory/'guest-result.json', value)
        if self.trace_present:
            trace=directory/'trace/baseline';trace.mkdir(parents=True, exist_ok=True)
            (trace/'A.events.jsonl').write_text('offline fixture')
        if self.collection_error:raise OSError('Interrupted archive collection')

    def map_source(self, traces):
        path=self.out/'source-map.jsonl';path.write_text('offline mapping')
        return path

    def export_candidate(self, path, rows, *args):
        self.assertEqual(self.state()['state'], 'dirty')
        value=dict(candidates=rows, summary=dict(executed_candidates=0))
        save(path, value)
        return value

    def rejects(self, code):
        with self.assertRaises(OperationError) as caught:self.rt.execute()
        self.assertEqual(caught.exception.code, code)

    def test_complete_sample_binds_order_then_exports_before_ready(self):
        result=self.rt.execute()
        self.assertTrue(result['passed']);self.assertFalse(result['recovery_required'])
        self.assertFalse(result['candidate_execution_performed']);self.assertFalse(result['kernel_bug_claim'])
        self.assertEqual(self.marks[0]['state'], 'dirty');self.assertEqual(self.state()['state'], 'ready')
        request=json.loads((self.out/'guest-request.json').read_text())
        self.assertTrue(request['executable'].endswith('kcov-sample-k08-ab'))
        self.assertIsNone(request['plan_path']);self.assertEqual(request['fault'], 'none')

    def test_ba_changes_executor_order_without_changing_input_so(self):
        self.scenario['order']='ba';self.analysis_value['observations']['order']='ba'
        result=self.rt.execute();self.assertTrue(result['passed'])
        request=json.loads((self.out/'guest-request.json').read_text())
        self.assertTrue(request['executable'].endswith('kcov-sample-k08-ba'))
        self.assertTrue(request['scenario_library'].endswith('regmap-k06-disjoint-bits-split.so'))

    def test_dirty_runtime_blocks_identity_and_launch(self):
        save(self.rt.statepath, dict(state='dirty', boot_id='boot-a'))
        self.rejects('recovery_required');self.rt.identity.assert_not_called();self.rt.guest.assert_not_called()

    def test_unexpected_boot_persists_dirty(self):
        self.rt.boot_id.return_value='other'
        self.rejects('recovery_required');self.assertEqual(self.state()['state'], 'dirty');self.rt.guest.assert_not_called()

    def test_changed_identity_rejects_before_guest_mutation(self):
        self.rt.identity.return_value={'changed':'identity'}
        self.rejects('identity_mismatch');self.rt.guest.assert_not_called()

    def test_profile_cannot_redirect_sample_build(self):
        self.profile['runtime']=dict(self.fields, sample_guest_build='/home/lab/k08/build-other')
        save(self.rt.profilepath,self.profile)
        self.rejects('runtime_profile_mismatch');self.rt.guest.assert_not_called()

    def test_wrong_family_vm_or_kernel_blocks_launch(self):
        self.scenario.update(family='mutex', case_id='shared-register', mode='shared')
        self.rejects('sample_family_mismatch');self.rt.guest.assert_not_called()
        self.scenario.update(family='rmw', case_id='disjoint-bits', mode='split')
        (self.kernel/'include/config/kernel.release').write_text('7.2.0-rc3-kconc-k07+')
        self.rejects('sample_family_mismatch');self.rt.guest.assert_not_called()

    def test_launcher_failure_cannot_clear_dirty_or_export(self):
        self.rt.guest.side_effect=OSError('lost SSH after launch')
        with self.assertRaises(OSError):self.rt.execute()
        self.assertEqual(self.state()['state'], 'dirty');self.export.assert_not_called()

    def test_poll_failure_collects_evidence_and_keeps_dirty(self):
        self.rt.poll_guest.side_effect=OSError('lost SSH')
        with self.assertRaises(OSError):self.rt.execute()
        self.rt.collect.assert_called_once();self.assertEqual(self.state()['state'], 'dirty');self.export.assert_not_called()

    def test_keyboard_interrupt_requests_cancel_and_never_marks_ready(self):
        self.rt.poll_guest.side_effect=KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):self.rt.execute()
        self.rt.ssh.assert_called_once();self.rt.collect.assert_called_once()
        self.assertEqual(self.state()['state'], 'dirty');self.export.assert_not_called()

    def test_timeout_without_supervisor_result_retains_dirty(self):
        self.rt.poll_guest.return_value=None;self.rt.poll_guest.side_effect=None
        with patch.object(sampling.time,'monotonic',side_effect=[0,100]):self.rejects('recovery_required')
        self.assertEqual(self.state()['state'], 'dirty');self.export.assert_not_called()

    def test_partial_collection_cannot_export_or_clear_dirty(self):
        self.collection_error=True
        self.rejects('collection_incomplete');self.assertEqual(self.state()['state'], 'dirty');self.export.assert_not_called()

    def test_collected_result_must_match_polled_result(self):
        self.collected_changes['boot_id']='different'
        self.rejects('guest_result_mismatch');self.assertEqual(self.state()['state'], 'dirty')

    def test_consistently_collected_guest_record_must_bind_run_boot_and_fault(self):
        for field,value in [('run_id','different'),('boot_id','other-boot'),('fault','setup')]:
            with self.subTest(field=field):
                self.ready();self.guest_changes={field:value}
                self.rejects('guest_result_mismatch');self.assertEqual(self.state()['state'],'dirty')
                self.export.assert_not_called()

    def test_polled_command_cannot_use_wrong_order_or_automatic_search(self):
        original=self.poll
        def wrong(remote):
            value=original(remote);value['command'][2:4]=['--k03-record','unused'];return value
        self.rt.poll_guest.side_effect=wrong
        self.rejects('guest_result_mismatch');self.export.assert_not_called()

    def test_incomplete_cleanup_and_boolean_exit_reject_without_analysis(self):
        for changes in [dict(exit_code=False),dict(remaining_pids=[999]),dict(local_cleanup={'confirmed':True}),
                        dict(outcome='execution_failed',exit_code=73)]:
            with self.subTest(changes=changes):
                self.ready();self.guest.update(changes)
                result=self.rt.execute()
                self.assertFalse(result['passed']);self.assertTrue(result['recovery_required'])
                self.assertEqual(self.state()['state'],'dirty')
                self.analysis.analyze.assert_not_called();self.export.assert_not_called()
                self.guest=dict(outcome='completed',exit_code=0,remaining_pids=[],local_cleanup=dict(confirmed=True,errors=[]))

    def test_missing_trace_cannot_export(self):
        self.trace_present=False
        result=self.rt.execute();self.assertFalse(result['passed']);self.assertEqual(self.state()['state'],'dirty')
        self.export.assert_not_called();self.analysis.analyze.assert_not_called()

    def test_analyzer_exception_retains_dirty(self):
        self.analysis.analyze.side_effect=ValueError('truncated trace')
        with self.assertRaises(ValueError):self.rt.execute()
        self.assertEqual(self.state()['state'],'dirty');self.export.assert_not_called()

    def test_source_map_failure_retains_dirty(self):
        self.map.side_effect=ValueError('unmapped position')
        with self.assertRaises(ValueError):self.rt.execute()
        self.assertEqual(self.state()['state'],'dirty');self.export.assert_not_called()

    def test_candidate_export_failure_retains_dirty(self):
        self.export.side_effect=OSError('storage failure')
        with self.assertRaises(OSError):self.rt.execute()
        self.assertEqual(self.state()['state'],'dirty')
        self.assertFalse((self.out/'sample-result.json').exists())

    def test_wrong_submitted_scenario_revokes_execution_and_property_claims(self):
        self.analysis_value['observations']['case_id']='overlap-bits'
        result=self.rt.execute()
        self.assertFalse(result['passed']);self.assertEqual(self.state()['state'],'dirty');self.export.assert_not_called()
        self.assertIs(result['analysis']['execution_valid'],False)
        self.assertIs(result['analysis']['property_evaluated'],False)

    def test_bad_checkpoint_hash_stops_recovery_before_vm_or_overlay_changes(self):
        checkpoint=self.labdir/'images/baseline-frozen.qcow2';checkpoint.write_bytes(b'fixture');checkpoint.chmod(0o444)
        self.addCleanup(lambda:checkpoint.chmod(0o666))
        overlay=self.labdir/'images/experiment.qcow2';overlay.write_bytes(b'retain me')
        self.profile['disks']=[dict(path=str(checkpoint),sha256='0'*64)];save(self.rt.profilepath,self.profile)
        with self.assertRaises(OperationError) as caught:self.rt.recover()
        self.assertEqual(caught.exception.code,'checkpoint_mismatch');self.assertEqual(self.state()['state'],'dirty')
        self.assertEqual(overlay.read_bytes(),b'retain me');self.rt.lab.stop.assert_not_called();self.rt.call.assert_not_called()

    def recovery_fixture(self):
        checkpoint=self.labdir/'images/baseline-frozen.qcow2';checkpoint.write_bytes(b'fixture');checkpoint.chmod(0o444)
        self.addCleanup(lambda:checkpoint.chmod(0o666))
        overlay=self.labdir/'images/experiment.qcow2';overlay.write_bytes(b'old writable layer')
        self.profile.update(disks=[dict(path=str(checkpoint),sha256=lifecycle.digest(checkpoint))],launch_env={})
        save(self.rt.profilepath,self.profile)
        self.rt.boot_id.return_value='boot-b'
        self.rt.call.side_effect=lambda argv:overlay.write_bytes(b'fresh writable layer')
        return overlay

    def test_recovery_retries_read_only_exit_check_before_replacing_overlay(self):
        overlay=self.recovery_fixture();attempts=[]
        def stopped(path):
            self.assertEqual(path,self.labdir)
            self.assertEqual(overlay.read_bytes(),b'old writable layer')
            self.assertEqual(list((self.labdir/'images').glob('retired-*')),[])
            self.rt.call.assert_not_called()
            attempts.append(len(attempts))
            if len(attempts)<3:raise RuntimeError('An active QEMU command references the baseline.')
        prepare=SimpleNamespace(require_stopped=Mock(side_effect=stopped))
        with patch.object(lifecycle,'load',return_value=prepare),patch.object(lifecycle.time,'sleep'),\
                patch.object(lifecycle.time,'monotonic',side_effect=iter(range(100))):
            result=self.rt.recover()
        self.assertTrue(result['passed']);self.assertEqual(len(attempts),3)
        self.assertEqual(self.state()['state'],'ready');self.assertEqual(self.state()['boot_id'],'boot-b')
        self.assertEqual(overlay.read_bytes(),b'fresh writable layer')
        archives=list((self.labdir/'images').glob('retired-*'))
        self.assertEqual(len(archives),1);self.assertEqual(archives[0].read_bytes(),b'old writable layer')

    def test_exit_check_timeout_never_renames_overlay_or_creates_new_disk(self):
        overlay=self.recovery_fixture()
        prepare=SimpleNamespace(require_stopped=Mock(side_effect=RuntimeError('An active QEMU command references the baseline.')))
        with patch.object(lifecycle,'load',return_value=prepare),patch.object(lifecycle.time,'sleep'),\
                patch.object(lifecycle.time,'monotonic',side_effect=iter(range(100))):
            with self.assertRaises((OperationError,RuntimeError)):self.rt.recover()
        self.assertGreater(prepare.require_stopped.call_count,1)
        self.assertEqual(self.state()['state'],'dirty')
        self.assertEqual(overlay.read_bytes(),b'old writable layer')
        self.assertEqual(list((self.labdir/'images').glob('retired-*')),[])
        self.rt.call.assert_not_called();self.rt.lab.start.assert_not_called()
        self.assertFalse(json.loads((self.out/'recovery.json').read_text())['passed'])

    def test_nontransient_exit_errors_fail_immediately_without_disk_changes(self):
        overlay=self.recovery_fixture()
        for error in [RuntimeError('Invalid baseline PID file; inspect it before copying.'),OSError('permission denied')]:
            with self.subTest(error=str(error)):
                prepare=SimpleNamespace(require_stopped=Mock(side_effect=error))
                with patch.object(lifecycle,'load',return_value=prepare),patch.object(lifecycle.time,'sleep') as sleep:
                    with self.assertRaises(type(error)):self.rt.recover()
                prepare.require_stopped.assert_called_once();sleep.assert_not_called()
                self.assertEqual(self.state()['state'],'dirty');self.assertEqual(overlay.read_bytes(),b'old writable layer')
                self.assertEqual(list((self.labdir/'images').glob('retired-*')),[])
                self.rt.call.assert_not_called();self.rt.lab.start.assert_not_called()

    def test_legacy_cannot_bypass_missing_or_dirty_state(self):
        self.rt.statepath.unlink()
        with self.assertRaises(OperationError):lifecycle.guard_legacy(self.fields,'k03.replay')
        save(self.rt.statepath,dict(state='dirty'))
        with self.assertRaises(OperationError):lifecycle.guard_legacy(self.fields,'env.check')
        lifecycle.guard_legacy(self.fields,'env.status')

    def test_manifest_requires_finite_input_order_and_exact_guest_build_root(self):
        self.assertEqual(normalize_manifest(self.task,self.base)['scenario'],self.scenario)
        for changes in [dict(family='other'),dict(case_id='unknown'),dict(mode='shared'),dict(order='aba'),dict(order=True),dict(extra=1)]:
            with self.subTest(changes=changes):
                task=copy.deepcopy(self.task);task['scenario'].update(changes)
                with self.assertRaises(ManifestError):normalize_manifest(task,self.base)
        for path in ['/home/lab/k07/build-old','/home/lab/k08/build-new/nested','/home/lab/k08/build-../..']:
            with self.subTest(path=path):
                task=copy.deepcopy(self.task);task['runtime']['sample_guest_build']=path
                with self.assertRaises(ManifestError):normalize_manifest(task,self.base)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='k08-identity-');self.addCleanup(tmp.cleanup)
        self.out=Path(tmp.name)
        self.rt=object.__new__(sampling.SampleRuntime)
        self.rt.out=self.out
        self.rt.runtime=dict(scenario_guest_build='/home/lab/k03/build-old',build_lab='/offline/build',
            kernel_build='/offline/kernel',sample_guest_build='/home/lab/k08/build-new')
        original=dict(binaries={'kcov-autorace-k03':'0'*64})
        self.rt.k03=SimpleNamespace(Session=Mock(return_value=SimpleNamespace(identity=Mock(return_value=original))))
        names=['kcov-sample-k08-ab','kcov-sample-k08-ba']+sorted(x['native_so'] for x in sampling.candidates.load_catalog()['inputs'])
        hashes={name:'1'*64 for name in names}
        inputs=dict(k03_executor_sha256='0'*64,
            executor_patch_sha256=lifecycle.digest(REPO/'adapters/maccconc/k08-executor.patch'),
            build_script_sha256=lifecycle.digest(REPO/'scripts/build-k08-guest.sh'),accepted_builds={},
            copied_scenarios=[dict(name=name,sha256=hashes[name]) for name in names if name.endswith('.so')])
        for stage in ['k06','k07']:
            fields={'scenario_sha256':f'scenarios/regmap-{stage}.c','client_sha256':f'scenarios/regmap-{stage}-client.c',
                'cases_sha256':f'scenarios/regmap-{stage}-cases.h','uapi_sha256':f'kernel/{stage}/kconc-regmap.h',
                'executor_patch_sha256':'adapters/maccconc/k05-executor.patch','build_script_sha256':f'scripts/build-{stage}-guest.sh'}
            inputs['accepted_builds'][stage]=dict(inputs={key:lifecycle.digest(REPO/path) for key,path in fields.items()},
                binaries=[dict(name=name,sha256=hashes[name]) for name in names if name.startswith('regmap-'+stage+'-')])
        self.value=dict(record=dict(passed=True,kind='kconc.sampler.build',inputs=inputs,
            binaries=[dict(name=name,sha256=value) for name,value in hashes.items()]),hashes=hashes,device=True)
        self.rt.guest=Mock(return_value=self.value)

    def test_complete_identity_records_all_checks(self):
        identity=sampling.SampleRuntime.identity(self.rt)
        self.assertEqual(identity['binaries'],self.value['hashes'])
        self.assertTrue(json.loads((self.out/'sample-identity.json').read_text())['passed'])

    def test_changed_build_adapter_source_or_copied_bytes_are_rejected(self):
        original=copy.deepcopy(self.value)
        mutations=[lambda v:v['record']['inputs'].update(executor_patch_sha256='f'*64),
            lambda v:v['record']['inputs'].update(build_script_sha256='f'*64),
            lambda v:v['record']['inputs'].update(k03_executor_sha256='f'*64),
            lambda v:v['record']['inputs']['accepted_builds']['k06']['inputs'].update(scenario_sha256='f'*64),
            lambda v:v['record']['inputs']['accepted_builds']['k07']['inputs'].update(uapi_sha256='f'*64),
            lambda v:v['record']['inputs']['accepted_builds']['k07']['binaries'][0].update(sha256='f'*64),
            lambda v:v['record']['inputs']['copied_scenarios'][0].update(sha256='f'*64),
            lambda v:v['hashes'].update({'kcov-sample-k08-ba':'f'*64}),
            lambda v:v.update(device=False)]
        for i,mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                value=copy.deepcopy(original);mutate(value);self.rt.guest.return_value=value
                with self.assertRaises(OperationError) as caught:sampling.SampleRuntime.identity(self.rt)
                self.assertEqual(caught.exception.code,'identity_mismatch')
                self.assertFalse(json.loads((self.out/'sample-identity.json').read_text())['passed'])


class ExportTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='k08-export-');self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name);self.sample=self.base/'sample';self.sample.mkdir()
        self.out=self.base/'export';self.out.mkdir()
        (self.sample/'guest').mkdir()
        self.index=self.base/'index.json';save(self.index,dict(schema_version=1,samples=['sample']))
        self.task=dict(inputs={'samples':str(self.index)})
        self.scenario=dict(family='rmw',case_id='disjoint-bits',mode='split',order='ab')
        self.analysis=dict(passed=True,checks={'submitted_scenario_matches':True},errors=[],observations=dict(self.scenario))
        for name,value in [('task.json',dict(scenario=self.scenario)),('analysis.json',self.analysis),
            ('runtime-identity.json',dict(offline='identity')),('guest/guest-result.json',dict(offline='guest'))]:save(self.sample/name,value)
        (self.sample/'source-map.jsonl').write_text(json.dumps(dict(raw_ip='0xffffffff81858010',found=True))+'\n')
        source={field:lifecycle.digest(self.sample/relative) for field,relative in [
            ('source_map_sha256','source-map.jsonl'),('runtime_identity_sha256','runtime-identity.json'),
            ('guest_sha256','guest/guest-result.json'),('task_sha256','task.json')]}
        self.candidate=dict(candidate_id='offline-id',sources=[source])
        save(self.sample/'candidate.json',dict(candidates=[self.candidate]))
        save(self.sample/'result.json',dict(status='passed',operation='sample.run',data=dict(candidate_sha256=lifecycle.digest(self.sample/'candidate.json'))))
        self.analyzer=Mock(side_effect=lambda *a,**k:copy.deepcopy(self.analysis))
        for name,value in [('load',SimpleNamespace(analyze=self.analyzer)),('candidate_from_analysis',self.candidate)]:
            p=patch.object(sampling,name,return_value=value);p.start();self.addCleanup(p.stop)
        self.export=Mock(side_effect=self.export_pool)
        p=patch.object(sampling.candidates,'export_candidates',self.export);p.start();self.addCleanup(p.stop)
        p=patch.object(sampling,'persist',side_effect=save);p.start();self.addCleanup(p.stop)

    def export_pool(self,path,rows):
        value=dict(summary={'source_records':len(rows)},candidates=rows);save(path,value);return value

    def rejects(self,code):
        with self.assertRaises(OperationError) as caught:sampling.export_samples(self.task,self.out)
        self.assertEqual(caught.exception.code,code);self.export.assert_not_called()
        self.assertFalse((self.out/'export-result.json').exists())

    def test_revalidation_finishes_before_export_and_never_creates_runtime(self):
        with patch.object(sampling,'SampleRuntime',side_effect=AssertionError('No VM from offline export')):
            result=sampling.export_samples(self.task,self.out)
        self.assertTrue(result['passed']);self.analyzer.assert_called_once();self.export.assert_called_once()

    def test_rejected_index_shapes_never_load_sample_or_export(self):
        for value in [dict(schema_version=True,samples=['sample']),dict(schema_version=1,samples=[]),
                      dict(schema_version=1,samples=[5]),dict(schema_version=1,samples=['sample'],extra=True)]:
            with self.subTest(value=value):save(self.index,value);self.rejects('invalid_sample_index')

    def test_failed_outer_sample_cannot_be_exported(self):
        value=json.loads((self.sample/'result.json').read_text());value['status']='failed';save(self.sample/'result.json',value)
        self.rejects('invalid_sample');self.analyzer.assert_not_called()

    def test_changed_recomputed_analysis_cannot_export(self):
        self.analyzer.side_effect=None;self.analyzer.return_value=dict(self.analysis,passed=False)
        self.rejects('sample_revalidation_failed')

    def test_source_binding_changes_cannot_export(self):
        (self.sample/'source-map.jsonl').write_text(json.dumps(dict(raw_ip='0xffffffff81858010',found=False))+'\n')
        self.rejects('sample_binding_mismatch')
        self.analyzer.assert_not_called()

    def test_candidate_file_must_match_completed_run_digest(self):
        value=json.loads((self.sample/'candidate.json').read_text());value['unbound']='changed';save(self.sample/'candidate.json',value)
        self.rejects('sample_binding_mismatch')

    def test_regenerated_candidate_must_match_saved_candidate(self):
        with patch.object(sampling,'candidate_from_analysis',return_value={'candidate_id':'different'}):self.rejects('sample_binding_mismatch')

    def test_export_storage_failure_cannot_create_success_record(self):
        self.export.side_effect=OSError('storage full')
        with self.assertRaises(OSError):sampling.export_samples(self.task,self.out)
        self.assertFalse((self.out/'export-result.json').exists())


class ExportIntegrationTests(unittest.TestCase):
    """Synthetic trace fixtures through real analyzers, candidate and export code.

    These check archive/runtime representation consistency, not a new kernel run
    or independent decoding of the fixture's placeholder KCOV words.
    """
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='k08-export-integration-');self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        spec=importlib.util.spec_from_file_location('k08_export_analysis_fixtures',Path(__file__).with_name('test_analysis.py'))
        self.fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.fixtures)
        self.helper=self.fixtures.AnalysisTests();self.addCleanup(self.helper.doCleanups)

    def archived_sample(self,entry,order):
        f=self.helper.fixture(entry['family'],order,entry['case_id'],entry['mode'])
        sample=self.base/(entry['input_id'].replace(':','-')+'-'+order)
        trace=sample/'guest/trace/baseline';shutil.copytree(f.trace,trace)
        mapping=sample/'source-map.jsonl'
        mapping.write_text(''.join(json.dumps(row)+'\n' for row in f.mapping.values()))
        save(sample/'guest/guest-result.json',f.guest)
        scenario=dict(family=entry['family'],case_id=entry['case_id'],mode=entry['mode'],order=order)
        save(sample/'task.json',dict(schema_version=1,operation='sample.run',scenario=scenario))
        identity=dict(synthetic_build='f'*64);save(sample/'runtime-identity.json',identity)
        report=self.fixtures.analysis.analyze(trace,f.mapping,f.guest,entry['family'],order)
        self.assertTrue(report['passed'],report)
        report['checks']['submitted_scenario_matches']=True
        self.assertEqual(set(report['artifacts']['source_map']),{'canonical_sha256'})
        save(sample/'analysis.json',report)
        provenance={field:lifecycle.digest(sample/relative) for field,relative in [
            ('source_map_sha256','source-map.jsonl'),('runtime_identity_sha256','runtime-identity.json'),
            ('guest_sha256','guest/guest-result.json'),('task_sha256','task.json')]}
        provenance['run_id']='a'*32
        candidate=sampling.candidate_from_analysis(report,trace,identity,sample/'analysis.json',provenance)
        sampling.candidates.export_candidates(sample/'candidate.json',[candidate])
        save(sample/'result.json',dict(status='passed',operation='sample.run',
            data=dict(candidate_sha256=lifecycle.digest(sample/'candidate.json'))))
        return sample,candidate

    def export(self,samples,name='export'):
        index=self.base/(name+'-index.json');save(index,dict(schema_version=1,samples=[p.name for p in samples]))
        out=self.base/name;out.mkdir()
        return sampling.export_samples(dict(inputs={'samples':str(index)}),out),out

    def test_all_28_dict_analyzed_archives_revalidate_via_jsonl_without_report_drift(self):
        samples=[];expected=[]
        for entry in sampling.candidates.load_catalog()['inputs']:
            for order in ('ab','ba'):
                sample,candidate=self.archived_sample(entry,order)
                samples.append(sample);expected.append(candidate['candidate_id'])
        before={str(path):lifecycle.digest(path) for sample in samples for path in sample.rglob('*') if path.is_file()}
        result,out=self.export(samples)
        self.assertTrue(result['passed']);self.assertEqual(result['summary']['observed_baselines'],28)
        self.assertEqual(result['summary']['unique_candidates'],28)
        self.assertEqual(result['summary']['executed_candidates'],0)
        pool=json.loads((out/'candidates.json').read_text())
        self.assertEqual({row['candidate_id'] for row in pool['candidates']},set(expected))
        self.assertEqual(before,{str(path):lifecycle.digest(path) for sample in samples for path in sample.rglob('*') if path.is_file()})

    def test_changed_raw_trace_is_rejected_by_real_reanalysis(self):
        entry=sampling.candidates.get_input(sampling.candidates.load_catalog(),'rmw','disjoint-bits','split')
        sample,_=self.archived_sample(entry,'ba')
        path=sample/'guest/trace/baseline/A.events.jsonl'
        rows=[json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['timestamp']='0x0000000000000002'
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        with self.assertRaises(OperationError) as caught:self.export([sample])
        self.assertEqual(caught.exception.code,'sample_revalidation_failed')
        self.assertFalse((self.base/'export/candidates.json').exists())
        self.assertFalse((self.base/'export/export-result.json').exists())


class GuestTests(unittest.TestCase):
    def setUp(self):
        def load(name,file):
            spec=importlib.util.spec_from_file_location(name,REPO/'adapters/maccconc'/file)
            mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
        self.supervisor=load('offline_k08_base','k04_guest.py')
        with patch.dict(sys.modules,{'k04_guest':self.supervisor}):self.guest=load('offline_k08_guest','k08_guest.py')
        self.directory=Path('/home/lab/k08/run-'+'a'*32)
        self.request=dict(executable='/home/lab/k08/build-one/bin/kcov-sample-k08-ab',
            scenario_library='/home/lab/k08/build-one/bin/regmap-k06-disjoint-bits-split.so',plan_path=None,fault='none')

    def test_ab_and_ba_select_only_the_explicit_baseline_flag(self):
        for order in ['ab','ba']:
            req=dict(self.request,executable='/home/lab/k08/build-one/bin/kcov-sample-k08-'+order)
            command=self.guest.command_for_request(req,self.directory)
            self.assertEqual(command,[req['executable'],req['scenario_library'],'--k08-baseline',order,str(self.directory/'trace')])

    def test_replay_fault_unknown_case_or_mixed_build_are_rejected(self):
        for changes in [dict(plan_path=str(self.directory/'plan.txt')),dict(fault='setup'),dict(executable='/bin/sh'),
                        dict(scenario_library='/home/lab/k08/build-other/bin/regmap-k06-disjoint-bits-split.so'),
                        dict(scenario_library='/home/lab/k08/build-one/bin/regmap-k06-unknown-split.so')]:
            with self.subTest(changes=changes),self.assertRaises(self.supervisor.GuestError):
                self.guest.command_for_request(dict(self.request,**changes),self.directory)

    def test_all_fourteen_reused_sos_are_allowed_and_no_others(self):
        catalog=sampling.candidates.load_catalog()
        self.assertEqual(self.guest.NAMES,{row['native_so'] for row in catalog['inputs']})
        for row in catalog['inputs']:
            req=dict(self.request,scenario_library='/home/lab/k08/build-one/bin/'+row['native_so'])
            self.assertEqual(self.guest.command_for_request(req,self.directory)[2],'--k08-baseline')

    def test_path_validation_rejects_aliases_and_symlinks(self):
        for path in ['/home/lab/k08/../k07/build-a/bin/x','/home/lab//k08/build-a/bin/x','relative']:
            with self.subTest(path=path),self.assertRaises(self.supervisor.GuestError):self.supervisor._path(path)
        with tempfile.TemporaryDirectory(prefix='k08-path-') as directory:
            base=Path(directory);target=base/'file';target.write_text('fixture')
            link=base/'alias';link.symlink_to(target)
            with self.assertRaises(self.supervisor.GuestError):self.supervisor._regular(link)


if __name__=='__main__':
    unittest.main()

"""K05 host gates and command boundaries; no SSH, QEMU or guest is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import lifecycle, regmap
from kconc.cli import OperationError
from kconc.manifest import ManifestError, normalize_manifest
from test_client import baseline, fault_report


def save(path, value):
    Path(path).write_text(json.dumps(value), encoding='utf-8')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='k05-offline-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.labdir = self.base / 'os-concurrency-k05-fixture'
        self.out = self.base / 'output'
        for path in [self.out, *[self.labdir / d for d in ('run', 'images', 'evidence', 'keys', 'seed')]]:
            path.mkdir(parents=True)
        self.fields = dict(lab_dir=str(self.labdir), ssh_port=2226, build_lab=str(self.base / 'build'),
            kernel_build=str(self.base / 'kernel'), scenario_guest_build='/home/lab/k03/build-old',
            regmap_guest_build='/home/lab/k05/build-new')
        self.task = dict(schema_version=1, operation='regmap.baseline', runtime=self.fields, inputs={})
        runtime = self.runtime = object.__new__(regmap.RegmapRuntime)
        runtime.task, runtime.out, runtime.runtime, runtime.labdir = self.task, self.out, self.fields, self.labdir
        runtime.statepath = self.labdir / runtime.state_file
        runtime.profilepath = self.labdir / runtime.profile_file
        runtime.commands = []
        self.identity = {'kernel_and_k03': 'offline build identity', 'binaries': 'offline pinned binaries'}
        runtime.identity = Mock(return_value=self.identity)
        runtime.boot_id = Mock(return_value='boot-a')
        runtime.guest = Mock(side_effect=self.launch)
        runtime.poll_guest = Mock(side_effect=self.poll)
        runtime.collect = Mock(side_effect=self.collect)
        runtime.ssh = Mock()
        runtime.lab = SimpleNamespace(stop=Mock(), start=Mock(), process_alive=Mock(return_value=False), qmp=Mock())
        runtime.call = Mock()
        self.profile = dict(schema_version=1, lab_dir=str(self.labdir), runtime=self.fields,
                            identity=self.identity, checkpoint=str(self.labdir/'images/baseline-frozen.qcow2'))
        self.guest = dict(schema_version=1, kind='kconc.guest', outcome='completed', exit_code=0,
                         remaining_pids=[], local_cleanup=dict(confirmed=True, errors=[]))
        self.client = baseline()
        self.guest_changes = {}
        self.collected_changes = {}
        self.collection_error = False
        self.marks = []
        def persist(path, value):
            save(path, value)
            if Path(path) == runtime.statepath: self.marks.append(copy.deepcopy(value))
        for module in (lifecycle, regmap):
            p = patch.object(module, 'persist', side_effect=persist); p.start(); self.addCleanup(p.stop)
        p = patch.object(regmap, 'load', return_value=SimpleNamespace(read_plan=Mock())); p.start(); self.addCleanup(p.stop)
        save(runtime.profilepath, self.profile)
        save(runtime.statepath, dict(state='ready', boot_id='boot-a'))

    def state(self):
        return json.loads(self.runtime.statepath.read_text())

    def launch(self, code):
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertTrue((self.out/'guest-request.json').is_file())
        return dict(supervisor_pid=123)

    def poll(self, remote):
        request = json.loads((self.out/'guest-request.json').read_text())
        if Path(request['executable']).name == 'regmap-client':
            command = [request['executable'], 'fault-reset'] if request['fault'] == 'setup' else [request['executable'], 'baseline', '--rounds', '20']
        else:
            command = [request['executable'], request['scenario_library'], '--k05-baseline', remote+'/trace']
        value = dict(self.guest, run_id=request['run_id'], boot_id='boot-a', fault=request['fault'], command=command)
        value.update(self.guest_changes)
        return value

    def collect(self, remote):
        path = self.out/'guest'; path.mkdir(exist_ok=True)
        value = self.poll(remote); value.update(self.collected_changes)
        save(path/'guest-result.json', value)
        save(path/'executor.stdout.txt', self.client)
        if self.collection_error:
            raise OSError('archive collection interrupted after partial extraction')

    def rejects(self, code):
        with self.assertRaises(OperationError) as caught:
            self.runtime.execute()
        self.assertEqual(caught.exception.code, code)

    def test_complete_baseline_marks_dirty_before_launch_then_ready(self):
        result = self.runtime.execute()
        self.assertTrue(result['passed'])
        self.assertTrue(result['validation']['passed'])
        self.assertFalse(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'ready')
        self.assertEqual(self.marks[0]['state'], 'dirty')
        self.assertFalse(result['kernel_bug_claim'])

    def test_dirty_runtime_is_rejected_before_identity_or_guest(self):
        save(self.runtime.statepath, dict(state='dirty', boot_id='boot-a'))
        self.rejects('recovery_required')
        self.runtime.identity.assert_not_called(); self.runtime.guest.assert_not_called()

    def test_unexpected_guest_boot_persists_dirty_and_rejects(self):
        self.runtime.boot_id.return_value = 'boot-b'
        self.rejects('recovery_required')
        self.assertEqual(self.state()['state'], 'dirty')
        self.runtime.guest.assert_not_called()

    def test_changed_build_identity_cannot_start_a_round(self):
        self.runtime.identity.return_value = {'other': 'build'}
        self.rejects('identity_mismatch')
        self.runtime.guest.assert_not_called()

    def test_runtime_profile_cannot_redirect_registered_guest(self):
        self.profile['runtime'] = dict(self.fields, regmap_guest_build='/home/lab/k05/build-other')
        save(self.runtime.profilepath, self.profile)
        self.rejects('runtime_profile_mismatch')
        self.runtime.guest.assert_not_called()

    def test_partial_collection_failure_cannot_become_ready(self):
        self.collection_error = True
        self.rejects('collection_incomplete')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertTrue((self.out/'collection-error.json').exists())

    def test_wrong_command_result_is_not_accepted(self):
        self.guest_changes['command'] = ['/bin/true']
        self.rejects('guest_result_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_collected_result_must_equal_observed_result(self):
        self.collected_changes['boot_id'] = 'different-collected-boot'
        self.rejects('guest_result_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_boolean_exit_code_does_not_establish_process_completion(self):
        self.guest['exit_code'] = False
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertTrue(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'dirty')

    def test_missing_cleanup_errors_or_residual_processes_prevent_reuse(self):
        self.guest['remaining_pids'] = [999]
        self.guest['local_cleanup'] = {'confirmed': True}
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertEqual(self.state()['state'], 'dirty')

    def test_forged_client_pass_without_rounds_does_not_allow_reuse(self):
        self.client = {'passed': True}
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertEqual(self.state()['state'], 'dirty')

    def test_successful_fault_exercise_still_requires_checkpoint_recovery(self):
        self.task['operation'] = 'regmap.fault-reset'; self.client = fault_report()
        result = self.runtime.execute()
        self.assertTrue(result['passed']); self.assertTrue(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'dirty')

    def test_early_setup_failure_with_empty_trace_keeps_a_result_and_dirty_gate(self):
        self.task.update(operation='regmap.setup-fault', inputs={'source_mapper': str(self.base/'mapper')})
        self.guest.update(outcome='execution_failed', exit_code=1)
        source_map = Mock(side_effect=AssertionError('An early failed execution must not invoke the mapper'))
        session = type('OfflineSession', (), {'source_map': source_map})
        self.runtime.k03 = SimpleNamespace(Session=session)
        original_collect = self.collect
        def failed_trace(remote):
            original_collect(remote)
            trace = self.out/'guest/trace/baseline'; trace.mkdir(parents=True)
            (trace/'A.events.jsonl').write_text('')
            (trace/'B.events.jsonl').write_text('')
        self.runtime.collect.side_effect = failed_trace
        result = self.runtime.execute()
        source_map.assert_not_called()
        self.assertFalse(result['passed']); self.assertTrue(result['recovery_required'])
        self.assertFalse(result['kernel_bug_claim'])
        self.assertTrue(result['analysis']['errors'])
        self.assertEqual(result['guest']['exit_code'], 1)
        self.assertEqual(json.loads((self.out/'regmap-result.json').read_text()), result)
        self.assertEqual(self.state()['state'], 'dirty')

    def make_binding(self):
        binding = self.base/'binding'; binding.mkdir()
        (binding/'plan.txt').write_text('offline fixed plan')
        save(binding/'runtime-identity.json', self.identity)
        info = dict(plan_sha256=lifecycle.digest(binding/'plan.txt'), runtime_identity_bound=True,
                    runtime_identity_sha256=lifecycle.digest(binding/'runtime-identity.json'),
                    analysis_sha256=lifecycle.digest(REPO/'adapters/maccconc/k05_analysis.py'))
        save(binding/'binding.json', info)
        self.task.update(operation='regmap.replay', inputs=dict(binding=str(binding), source_mapper=str(self.base/'mapper')))
        return binding, info

    def test_stale_bound_runtime_cannot_launch(self):
        binding, info = self.make_binding()
        save(binding/'runtime-identity.json', {'other': 'build'})
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_changed_plan_bytes_cannot_launch(self):
        binding, info = self.make_binding()
        (binding/'plan.txt').write_text('changed plan')
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_changed_analyzer_cannot_reuse_bound_plan(self):
        binding, info = self.make_binding()
        info['analysis_sha256'] = '0'*64; save(binding/'binding.json', info)
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_unbound_plan_cannot_launch(self):
        binding, info = self.make_binding()
        info['runtime_identity_bound'] = False; save(binding/'binding.json', info)
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_k05_recovery_hash_failure_keeps_old_overlay_and_blocks_stop(self):
        checkpoint = self.labdir/'images/baseline-frozen.qcow2'; checkpoint.write_bytes(b'offline fixture')
        checkpoint.chmod(0o444); self.addCleanup(lambda: checkpoint.chmod(0o666))
        overlay = self.labdir/'images/experiment.qcow2'; overlay.write_bytes(b'old layer')
        self.profile['disks'] = [dict(path=str(checkpoint), sha256='0'*64)]
        save(self.runtime.profilepath, self.profile)
        with self.assertRaises(OperationError) as caught: self.runtime.recover()
        self.assertEqual(caught.exception.code, 'checkpoint_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertEqual(overlay.read_bytes(), b'old layer')
        self.runtime.lab.stop.assert_not_called(); self.runtime.call.assert_not_called()

    def test_legacy_k03_cannot_bypass_missing_or_dirty_k05_state(self):
        self.runtime.statepath.unlink()
        with self.assertRaises(OperationError): lifecycle.guard_legacy(self.fields, 'k03.replay')
        save(self.runtime.statepath, {'state': 'dirty'})
        with self.assertRaises(OperationError): lifecycle.guard_legacy(self.fields, 'env.check')
        lifecycle.guard_legacy(self.fields, 'env.status')

    def test_manifest_requires_k05_paths_and_rejects_arbitrary_guest_build(self):
        value = normalize_manifest(self.task, self.base)
        self.assertEqual(value['runtime']['regmap_guest_build'], '/home/lab/k05/build-new')
        del self.task['runtime']['regmap_guest_build']
        with self.assertRaises(ManifestError): normalize_manifest(self.task, self.base)
        self.task['runtime']['regmap_guest_build'] = '/home/lab/k04/build-new'
        with self.assertRaises(ManifestError): normalize_manifest(self.task, self.base)


class GuestCommandTests(unittest.TestCase):
    def setUp(self):
        def load(name, file):
            spec = importlib.util.spec_from_file_location(name, REPO/'adapters/maccconc'/file)
            value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
            return value
        self.old = load('offline_k04_supervisor', 'k04_guest.py')
        self.old_command = self.old.command_for_request
        with patch.dict(sys.modules, {'k04_guest': self.old}):
            self.new = load('offline_k05_supervisor', 'k05_guest.py')
        self.directory = Path('/home/lab/k05/run-'+'a'*32)
        self.request = dict(executable='/home/lab/k05/build-01/bin/kcov-autorace-k05',
            scenario_library='/home/lab/k05/build-01/bin/regmap-v1.so', plan_path=None, fault='none')

    def test_k04_default_record_and_replay_commands_are_preserved(self):
        req = dict(executable='/old/exe', scenario_library='/old/test.so', plan_path=None)
        self.assertEqual(self.old_command(req, self.directory), ['/old/exe', '/old/test.so', '--k03-record', str(self.directory/'trace')])
        req['plan_path'] = '/old/plan'
        self.assertEqual(self.old_command(req, self.directory)[2:], ['--k03-replay', '/old/plan', str(self.directory/'trace')])

    def test_k05_record_uses_baseline_only_and_fixed_client_rounds(self):
        self.assertEqual(self.new.command_for_request(self.request, self.directory)[2:], ['--k05-baseline', str(self.directory/'trace')])
        req = dict(self.request, executable='/home/lab/k05/build-01/bin/regmap-client', scenario_library='/home/lab/k05/build-01/bin/regmap-client')
        self.assertEqual(self.new.command_for_request(req, self.directory)[1:], ['baseline', '--rounds', '20'])

    def test_arbitrary_executable_mixed_build_and_client_plan_are_rejected(self):
        for values in [dict(executable='/bin/sh'), dict(scenario_library='/home/lab/k05/build-other/bin/regmap-v1.so'),
                       dict(executable='/home/lab/k05/build-01/bin/regmap-client', scenario_library='/home/lab/k05/build-01/bin/regmap-client', plan_path=str(self.directory/'plan.txt'))]:
            with self.subTest(values=values), self.assertRaises(self.old.GuestError):
                self.new.command_for_request(dict(self.request, **values), self.directory)


if __name__ == '__main__':
    unittest.main()

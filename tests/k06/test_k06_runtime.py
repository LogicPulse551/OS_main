"""K06 host evidence gates; SSH, QEMU and the guest are never executed here."""
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
from kconc import lifecycle, rmw
from kconc.cli import OperationError
from kconc.manifest import ManifestError, normalize_manifest


def save(path, value):
    Path(path).write_text(json.dumps(value), encoding='utf-8')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='k06-offline-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.labdir = self.base / 'os-concurrency-k06-fixture'
        self.out = self.base / 'output'
        for path in [self.out, *[self.labdir / d for d in ('run', 'images', 'evidence', 'keys', 'seed')]]:
            path.mkdir(parents=True)
        self.fields = dict(lab_dir=str(self.labdir), ssh_port=2227, build_lab=str(self.base / 'build'),
            kernel_build=str(self.base / 'kernel'), scenario_guest_build='/home/lab/k03/build-old',
            rmw_guest_build='/home/lab/k06/build-new')
        self.scenario = dict(id='regmap-rmw-v1', case_id='disjoint-bits', mode='split')
        self.task = dict(schema_version=1, operation='rmw.record', runtime=self.fields,
                         scenario=self.scenario, inputs={'source_mapper': str(self.base / 'mapper')})
        runtime = self.runtime = object.__new__(rmw.RmwRuntime)
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
        self.source_map = Mock(return_value={'offline': 'source map'})
        runtime.k03 = SimpleNamespace(Session=type('OfflineSession', (), {'source_map': self.source_map}))
        self.profile = dict(schema_version=1, lab_dir=str(self.labdir), runtime=self.fields,
                            identity=self.identity, checkpoint=str(self.labdir / 'images/baseline-frozen.qcow2'))
        self.guest = dict(schema_version=1, kind='kconc.guest', outcome='completed', exit_code=0,
                         remaining_pids=[], local_cleanup=dict(confirmed=True, errors=[]))
        self.guest_changes = {}
        self.collected_changes = {}
        self.collection_error = False
        self.trace_present = True
        self.collected_plan = None
        self.marks = []
        self.analysis_value = dict(passed=True, execution_valid=True, property_evaluated=True,
            property_violation=False, property={'allowed': True}, checks={}, errors=[],
            observations={'case_id': 'disjoint-bits', 'mode': 'split'})
        self.analysis = SimpleNamespace(analyze=Mock(side_effect=lambda *a, **k: copy.deepcopy(self.analysis_value)),
            make_plan=Mock(side_effect=self.make_output_binding), read_plan=Mock())
        def persist(path, value):
            save(path, value)
            if Path(path) == runtime.statepath:
                self.marks.append(copy.deepcopy(value))
        for module in (lifecycle, rmw):
            p = patch.object(module, 'persist', side_effect=persist)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(rmw, 'load', return_value=self.analysis)
        p.start(); self.addCleanup(p.stop)
        save(runtime.profilepath, self.profile)
        save(runtime.statepath, dict(state='ready', boot_id='boot-a'))

    def state(self):
        return json.loads(self.runtime.statepath.read_text())

    def launch(self, code):
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertTrue((self.out / 'guest-request.json').is_file())
        return dict(supervisor_pid=123)

    def poll(self, remote):
        request = json.loads((self.out / 'guest-request.json').read_text())
        if Path(request['executable']).name == 'regmap-k06-client':
            command = [request['executable'], 'matrix']
        else:
            tail = ['--k03-replay', request['plan_path'], remote + '/trace'] if request['plan_path'] else ['--k05-baseline', remote + '/trace']
            command = [request['executable'], request['scenario_library']] + tail
        value = dict(self.guest, run_id=request['run_id'], boot_id='boot-a', fault=request['fault'], command=command)
        value.update(self.guest_changes)
        return value

    def collect(self, remote):
        path = self.out / 'guest'; path.mkdir(exist_ok=True)
        value = self.poll(remote); value.update(self.collected_changes)
        save(path / 'guest-result.json', value)
        if self.trace_present:
            trace = path / 'trace'
            if self.task['operation'] == 'rmw.record':
                trace = trace / 'baseline'
            trace.mkdir(parents=True)
            (trace / 'A.events.jsonl').write_text('offline fixture')
            if self.task['operation'] == 'rmw.replay':
                (trace / 'plan.txt').write_bytes(self.collected_plan or (self.out / 'input-plan.txt').read_bytes())
        if self.collection_error:
            raise OSError('Archive was interrupted after partial extraction')

    def make_output_binding(self, trace, mapping, out):
        Path(out).mkdir()
        (Path(out) / 'plan.txt').write_text('offline generated plan')
        return {'runtime_identity_bound': False}

    def make_binding(self):
        binding = self.base / 'input-binding'; binding.mkdir()
        (binding / 'plan.txt').write_text('offline fixed plan')
        save(binding / 'runtime-identity.json', self.identity)
        info = dict(plan_sha256=lifecycle.digest(binding / 'plan.txt'), runtime_identity_bound=True,
            runtime_identity_sha256=lifecycle.digest(binding / 'runtime-identity.json'),
            analysis_sha256=lifecycle.digest(REPO / 'adapters/maccconc/k06_analysis.py'),
            k03_analysis_sha256=lifecycle.digest(REPO / 'adapters/maccconc/k03_analysis.py'),
            oracle_sha256=lifecycle.digest(REPO / 'src/kconc/regmap_oracle.py'),
            scenario=self.scenario['id'], case_id=self.scenario['case_id'], mode=self.scenario['mode'])
        save(binding / 'binding.json', info)
        self.task.update(operation='rmw.replay', inputs=dict(binding=str(binding), source_mapper=str(self.base / 'mapper')))
        return binding, info

    def rejects(self, code):
        with self.assertRaises(OperationError) as caught:
            self.runtime.execute()
        self.assertEqual(caught.exception.code, code)

    def test_complete_record_marks_dirty_then_ready_and_binds_runtime(self):
        result = self.runtime.execute()
        self.assertTrue(result['passed'])
        self.assertFalse(result['recovery_required'])
        self.assertEqual(self.marks[0]['state'], 'dirty')
        self.assertEqual(self.state()['state'], 'ready')
        self.assertFalse(result['kernel_bug_claim'])
        binding = json.loads((self.out / 'binding/binding.json').read_text())
        self.assertIs(binding['runtime_identity_bound'], True)
        self.assertEqual(binding['runtime_identity_sha256'], lifecycle.digest(self.out / 'binding/runtime-identity.json'))

    def test_valid_observed_violation_is_not_execution_failure(self):
        self.make_binding()
        self.analysis_value.update(property_violation=True, property={'allowed': False})
        result = self.runtime.execute()
        self.assertTrue(result['passed'])
        self.assertTrue(result['analysis']['property_violation'])
        self.assertFalse(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'ready')

    def test_dirty_runtime_rejects_before_identity_and_guest(self):
        save(self.runtime.statepath, {'state': 'dirty', 'boot_id': 'boot-a'})
        self.rejects('recovery_required')
        self.runtime.identity.assert_not_called(); self.runtime.guest.assert_not_called()

    def test_unexpected_boot_persists_dirty(self):
        self.runtime.boot_id.return_value = 'boot-b'
        self.rejects('recovery_required')
        self.assertEqual(self.state()['state'], 'dirty')
        self.runtime.guest.assert_not_called()

    def test_changed_live_identity_rejects_before_guest(self):
        self.runtime.identity.return_value = {'other': 'build'}
        self.rejects('identity_mismatch'); self.runtime.guest.assert_not_called()

    def test_profile_cannot_redirect_guest_build(self):
        self.profile['runtime'] = dict(self.fields, rmw_guest_build='/home/lab/k06/build-other')
        save(self.runtime.profilepath, self.profile)
        self.rejects('runtime_profile_mismatch'); self.runtime.guest.assert_not_called()

    def test_binding_checks_exact_case_mode_scenario_and_analyzers(self):
        binding, info = self.make_binding()
        changes = {'case_id': 'overlap-bits', 'mode': 'update-bits', 'scenario': 'other',
            'analysis_sha256': '0' * 64, 'k03_analysis_sha256': '0' * 64,
            'oracle_sha256': '0' * 64, 'runtime_identity_sha256': '0' * 64,
            'runtime_identity_bound': False, 'plan_sha256': '0' * 64}
        for key, value in changes.items():
            with self.subTest(field=key):
                save(binding / 'binding.json', dict(info, **{key: value}))
                self.rejects('binding_mismatch')
                self.runtime.guest.assert_not_called()

    def test_binding_cannot_reuse_another_runtime_identity(self):
        binding, info = self.make_binding()
        save(binding / 'runtime-identity.json', {'other': 'build'})
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_changed_bound_plan_bytes_rejected_before_guest(self):
        binding, info = self.make_binding()
        (binding / 'plan.txt').write_text('changed plan')
        self.rejects('binding_mismatch'); self.runtime.guest.assert_not_called()

    def test_partial_collection_leaves_dirty(self):
        self.collection_error = True
        self.rejects('collection_incomplete')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_collected_result_must_equal_polled_result(self):
        self.collected_changes['boot_id'] = 'other-boot'
        self.rejects('guest_result_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_wrong_command_record_is_rejected(self):
        self.guest_changes['command'] = ['/bin/true']
        self.rejects('guest_result_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_guest_record_must_match_run_boot_and_fault(self):
        for key, value in [('run_id', 'other'), ('boot_id', 'other'), ('fault', 'setup')]:
            with self.subTest(field=key):
                # Each rejected execution conservatively dirties the fixture.
                save(self.runtime.statepath, {'state': 'ready', 'boot_id': 'boot-a'})
                self.guest_changes = {key: value}
                self.trace_present = False
                self.rejects('guest_result_mismatch')

    def test_boolean_exit_code_cannot_establish_completion(self):
        self.guest['exit_code'] = False
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertTrue(result['recovery_required'])
        self.source_map.assert_not_called()

    def test_residual_processes_prevent_reuse(self):
        self.guest['remaining_pids'] = [999]
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertEqual(self.state()['state'], 'dirty')

    def test_unconfirmed_cleanup_prevents_reuse(self):
        self.guest['local_cleanup'] = {'confirmed': True}
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertEqual(self.state()['state'], 'dirty')

    def test_failed_replay_without_plan_keeps_structured_result(self):
        self.make_binding()
        self.guest.update(outcome='execution_failed', exit_code=1)
        self.trace_present = False
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertTrue(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'dirty')
        self.source_map.assert_not_called()
        self.assertEqual(json.loads((self.out / 'rmw-result.json').read_text()), result)

    def test_observed_case_mismatch_revokes_execution_and_property_claim(self):
        self.analysis_value.update(property_violation=True, property={'allowed': False},
                                   observations={'case_id': 'overlap-bits', 'mode': 'split'})
        result = self.runtime.execute()
        self.assertFalse(result['passed'])
        for name in ('execution_valid', 'property_evaluated', 'property_violation'):
            self.assertIs(result['analysis'][name], False, name)
        self.analysis.make_plan.assert_not_called()
        self.assertEqual(self.state()['state'], 'dirty')

    def test_executed_plan_must_match_submitted_bytes(self):
        self.make_binding(); self.collected_plan = b'other executed plan'
        result = self.runtime.execute()
        self.assertFalse(result['passed']); self.assertTrue(result['recovery_required'])
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertEqual(json.loads((self.out / 'rmw-result.json').read_text()), result)

    def test_checkpoint_hash_failure_preserves_overlay_and_does_not_stop(self):
        checkpoint = self.labdir / 'images/baseline-frozen.qcow2'
        checkpoint.write_bytes(b'offline fixture'); checkpoint.chmod(0o444)
        self.addCleanup(lambda: checkpoint.chmod(0o666))
        overlay = self.labdir / 'images/experiment.qcow2'; overlay.write_bytes(b'old layer')
        self.profile['disks'] = [dict(path=str(checkpoint), sha256='0' * 64)]
        save(self.runtime.profilepath, self.profile)
        with self.assertRaises(OperationError) as caught:
            self.runtime.recover()
        self.assertEqual(caught.exception.code, 'checkpoint_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertEqual(overlay.read_bytes(), b'old layer')
        self.runtime.lab.stop.assert_not_called(); self.runtime.call.assert_not_called()

    def test_legacy_cannot_bypass_missing_or_dirty_k06_state(self):
        self.runtime.statepath.unlink()
        with self.assertRaises(OperationError): lifecycle.guard_legacy(self.fields, 'k03.replay')
        save(self.runtime.statepath, {'state': 'dirty'})
        with self.assertRaises(OperationError): lifecycle.guard_legacy(self.fields, 'env.check')
        lifecycle.guard_legacy(self.fields, 'env.status')

    def test_manifest_requires_fixed_case_mode_and_guest_path(self):
        self.assertEqual(normalize_manifest(self.task, self.base)['scenario'], self.scenario)
        for changes in [{'case_id': 'unknown'}, {'mode': 'atomic'}, {'mode': False}, {'extra': 1}]:
            with self.subTest(changes=changes):
                task = copy.deepcopy(self.task); task['scenario'].update(changes)
                with self.assertRaises(ManifestError): normalize_manifest(task, self.base)
        for build in ['/home/lab/k05/build-01', '/home/lab/k06/build-01/nested', '/home/lab/k06/build-../..']:
            with self.subTest(build=build):
                task = copy.deepcopy(self.task); task['runtime']['rmw_guest_build'] = build
                with self.assertRaises(ManifestError): normalize_manifest(task, self.base)


class GuestCommandTests(unittest.TestCase):
    def setUp(self):
        def load(name, file):
            spec = importlib.util.spec_from_file_location(name, REPO / 'adapters/maccconc' / file)
            value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
            return value
        self.supervisor = load('offline_k06_base_supervisor', 'k04_guest.py')
        with patch.dict(sys.modules, {'k04_guest': self.supervisor}):
            self.adapter = load('offline_k06_supervisor', 'k06_guest.py')
        self.directory = Path('/home/lab/k06/run-' + 'a' * 32)
        self.request = dict(executable='/home/lab/k06/build-01/bin/kcov-autorace-k06',
            scenario_library='/home/lab/k06/build-01/bin/regmap-k06-disjoint-bits-split.so', plan_path=None, fault='none')

    def test_record_uses_baseline_only_not_automatic_conflict_search(self):
        self.assertEqual(self.adapter.command_for_request(self.request, self.directory)[2:],
                         ['--k05-baseline', str(self.directory / 'trace')])

    def test_replay_uses_exact_plan_and_fixed_library(self):
        req = dict(self.request, plan_path=str(self.directory / 'plan.txt'))
        self.assertEqual(self.adapter.command_for_request(req, self.directory),
            [req['executable'], req['scenario_library'], '--k03-replay', req['plan_path'], str(self.directory / 'trace')])

    def test_matrix_uses_fixed_command(self):
        req = dict(self.request, executable='/home/lab/k06/build-01/bin/regmap-k06-client',
                   scenario_library='/home/lab/k06/build-01/bin/regmap-k06-client')
        self.assertEqual(self.adapter.command_for_request(req, self.directory), [req['executable'], 'matrix'])

    def test_arbitrary_binary_mixed_build_undeclared_case_and_fault_are_rejected(self):
        for changes in [{'executable': '/bin/sh'},
            {'scenario_library': '/home/lab/k06/build-other/bin/regmap-k06-disjoint-bits-split.so'},
            {'scenario_library': '/home/lab/k06/build-01/bin/regmap-k06-unknown-split.so'}, {'fault': 'setup'}]:
            with self.subTest(changes=changes), self.assertRaises(self.supervisor.GuestError):
                self.adapter.command_for_request(dict(self.request, **changes), self.directory)

    def test_matrix_rejects_control_plan(self):
        req = dict(self.request, executable='/home/lab/k06/build-01/bin/regmap-k06-client',
            scenario_library='/home/lab/k06/build-01/bin/regmap-k06-client', plan_path=str(self.directory / 'plan.txt'))
        with self.assertRaises(self.supervisor.GuestError):
            self.adapter.command_for_request(req, self.directory)


if __name__ == '__main__':
    unittest.main()

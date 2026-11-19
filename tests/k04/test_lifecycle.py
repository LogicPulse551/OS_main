"""Offline K04 quarantine/recovery tests; subprocesses and VM hooks are mocked."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from kconc import lifecycle
from kconc.cli import OperationError


def complete_evidence(property_ok=True):
    guest = {'schema_version': 1, 'kind': 'kconc.guest', 'outcome': 'completed', 'exit_code': 0,
             'remaining_pids': [], 'local_cleanup': {'confirmed': True, 'errors': []},
             'phase_errors': [], 'phases': [
                 {'phase': 'setup', 'passed': True}, {'phase': 'initial_state', 'passed': True},
                 {'phase': 'operations', 'passed': True, 'a_calls': 1, 'b_calls': 1},
                 {'phase': 'property', 'passed': property_ok, 'oracle': 'legal-dup-close-result'},
                 {'phase': 'teardown', 'passed': True}]}
    run = {'control_valid': True, 'overflow': False, 'raw_words_well_formed': True,
           'child_ok': True, 'a_done': True, 'b_done': True, 'safe_to_continue': True,
           'reset': {'called': True, 'rc': 0, 'errno': 0}, 'A': {'timeouts': 0}, 'B': {'timeouts': 0}}
    return guest, run


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kconc-lifecycle-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.labdir = self.base / 'os-concurrency-k04-test'
        self.out = self.base / 'evidence'
        for path in (*[self.labdir / name for name in ('run', 'images', 'evidence', 'keys', 'seed')], self.out):
            path.mkdir(parents=True)
        self.plan = self.base / 'plan.txt'
        self.plan.write_text('offline plan checked by the mocked pinned analyzer\n')
        self.checkpoint = self.labdir / 'images/baseline-frozen.qcow2'
        self.checkpoint.write_bytes(b'offline checkpoint fixture, not a disk image')
        self.checkpoint.chmod(0o444)
        self.addCleanup(lambda: self.checkpoint.chmod(0o666))
        self.disk = self.labdir / 'images/experiment.qcow2'
        self.disk.write_bytes(b'offline previous overlay fixture')
        self.runtime_fields = {
            'lab_dir': str(self.labdir), 'ssh_port': 2225, 'build_lab': str(self.base / 'build'),
            'kernel_build': str(self.base / 'kernel'), 'scenario_guest_build': '/home/lab/k03/build-old',
            'lifecycle_guest_build': '/home/lab/k04/build-new',
        }
        self.task = {'operation': 'scenario.run', 'runtime': self.runtime_fields,
                     'scenario': {'id': 'dup-close-v1', 'timeout_seconds': 5, 'fault': 'none'},
                     'inputs': {'plan': str(self.plan)}}
        self.runtime = object.__new__(lifecycle.Runtime)
        self.runtime.task, self.runtime.out = self.task, self.out
        self.runtime.runtime, self.runtime.labdir = self.runtime_fields, self.labdir
        self.runtime.statepath = self.labdir / lifecycle.STATE
        self.runtime.profilepath = self.labdir / lifecycle.PROFILE
        self.runtime.commands = []
        self.runtime.lab = SimpleNamespace(stop=Mock(), start=Mock(), process_alive=Mock(return_value=False), qmp=Mock())
        self.runtime.boot_id = Mock(return_value='boot-one')
        self.runtime.identity = Mock(return_value={'fixed': 'identity'})
        self.runtime.guest = Mock(return_value={'supervisor_pid': 700})
        self.runtime.ssh = Mock()
        self.guest, self.run = complete_evidence()
        self.runtime.poll_guest = Mock(side_effect=self.poll)
        self.runtime.collect = Mock(side_effect=self.collect)
        self.runtime.call = Mock(side_effect=self.call)
        self.analyzer = SimpleNamespace(read_plan=Mock(return_value={'stack': []}),
            read_events=Mock(return_value=[]), _raw_consistency=Mock(return_value={'valid': True}),
            _control_checks=Mock(return_value={'fixed_target_hit': True}))
        self.prepare = SimpleNamespace(require_stopped=Mock())
        self.profile = {'schema_version': 1, 'lab_dir': str(self.labdir), 'runtime': self.runtime_fields,
                        'checkpoint': str(self.checkpoint),
                        'disks': [{'path': str(self.checkpoint), 'sha256': lifecycle.digest(self.checkpoint)}],
                        'identity': {'fixed': 'identity'}, 'launch_env': {'LAB_KERNEL': 'offline-fixture'}}
        self.persisted = []
        save_patch = patch.object(lifecycle, 'persist', side_effect=self.save)
        save_patch.start()
        self.addCleanup(save_patch.stop)
        load_patch = patch.object(lifecycle, 'load', side_effect=lambda name, path:
                                 self.prepare if name == 'k04_prepare' else self.analyzer)
        load_patch.start()
        self.addCleanup(load_patch.stop)
        self.save(self.runtime.profilepath, self.profile)
        self.save(self.runtime.statepath, {'state': 'ready', 'boot_id': 'boot-one'})

    def save(self, path, value):
        # This test isolates state ordering; production persist performs fsync.
        path = Path(path)
        path.write_text(json.dumps(value), encoding='utf-8')
        self.persisted.append((str(path), json.loads(json.dumps(value))))

    def state(self):
        return lifecycle.read(self.runtime.statepath)

    def bind_guest(self, remote):
        request = lifecycle.read(self.out / 'guest-request.json')
        for key, value in {
            'run_id': request['run_id'], 'boot_id': 'boot-one', 'fault': request['fault'],
            'command': [request['executable'], request['scenario_library'], '--k03-replay',
                        request['plan_path'], remote + '/trace'],
        }.items():
            self.guest.setdefault(key, value)

    def poll(self, remote):
        self.bind_guest(remote)
        return copy.deepcopy(self.guest)

    def collect(self, remote):
        self.bind_guest(remote)
        trace = self.out / 'guest/trace'
        trace.mkdir(parents=True)
        self.save(self.out / 'guest/guest-result.json', self.guest)
        self.save(trace / 'run.json', self.run)
        (trace / 'plan.txt').write_bytes((self.out / 'input-plan.txt').read_bytes())

    def call(self, args, **kwargs):
        self.assertEqual(args[:2], ['qemu-img', 'create'])
        Path(args[-1]).write_bytes(b'offline fresh overlay fixture')
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    def test_dirty_runtime_refuses_before_any_guest_access(self):
        self.save(self.runtime.statepath, {'state': 'dirty', 'boot_id': 'boot-one'})
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'recovery_required')
        self.runtime.boot_id.assert_not_called()
        self.runtime.identity.assert_not_called()
        self.runtime.guest.assert_not_called()

    def test_guest_reboot_marks_dirty_before_scenario_identity_or_launch(self):
        self.runtime.boot_id.return_value = 'boot-other'
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'recovery_required')
        self.assertEqual(self.state()['state'], 'dirty')
        self.runtime.identity.assert_not_called()
        self.runtime.guest.assert_not_called()

    def test_mismatched_binary_identity_cannot_start_a_scenario(self):
        self.runtime.identity.return_value = {'fixed': 'different'}
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'identity_mismatch')
        self.runtime.guest.assert_not_called()
        self.assertEqual(self.state()['state'], 'ready')

    def test_malformed_plan_rejected_before_mark_or_upload(self):
        self.analyzer.read_plan.side_effect = ValueError('offline bad plan')
        with self.assertRaises(ValueError):
            self.runtime.run_scenario()
        self.assertEqual(self.state()['state'], 'ready')
        self.runtime.guest.assert_not_called()

    def test_dirty_is_persisted_before_guest_launch_and_cleared_only_after_evidence(self):
        def launch(code):
            state = self.state()
            self.assertEqual(state['state'], 'dirty')
            self.assertEqual(state['active']['request'], state['active']['remote'] + '/request.json')
            self.assertTrue((self.out / 'guest-request.json').is_file())
            return {'supervisor_pid': 700}
        self.runtime.guest.side_effect = launch
        result = self.runtime.run_scenario()
        self.assertTrue(result['passed'])
        self.assertEqual(self.state()['state'], 'ready')
        self.assertTrue((self.out / 'scenario-result.json').is_file())
        self.assertTrue(result['classification']['phases_complete'])

    def test_failed_supervisor_launch_keeps_dirty_across_new_invocation(self):
        self.runtime.guest.side_effect = RuntimeError('offline SSH failure')
        with self.assertRaises(RuntimeError):
            self.runtime.run_scenario()
        self.assertEqual(self.state()['state'], 'dirty')
        self.runtime.guest.reset_mock()
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'recovery_required')
        self.runtime.guest.assert_not_called()

    def test_property_violation_keeps_clean_runtime_ready_and_reports_failure(self):
        self.guest['phases'][3].update(passed=False, injected=True, oracle_test_only=True)
        self.task['scenario']['fault'] = 'property'
        result = self.runtime.run_scenario()
        self.assertFalse(result['passed'])
        self.assertEqual(result['classification']['property'], 'violated')
        self.assertEqual(result['classification']['cleanup'], 'clean')
        self.assertEqual(self.state()['state'], 'ready')

    def test_timeout_result_with_missing_teardown_requires_recovery(self):
        self.guest.update(outcome='timeout', exit_code=-15, phases=self.guest['phases'][:2])
        result = self.runtime.run_scenario()
        self.assertFalse(result['passed'])
        self.assertTrue(result['classification']['recovery_required'])
        self.assertEqual(self.state()['state'], 'dirty')

    def test_runtime_profile_port_mismatch_refuses_without_vm_access(self):
        self.runtime.runtime = {**self.runtime_fields, 'ssh_port': 2222}
        with self.assertRaises(OperationError) as error:
            self.runtime.profile()
        self.assertEqual(error.exception.code, 'runtime_profile_mismatch')
        self.runtime.boot_id.assert_not_called()
        self.runtime.guest.assert_not_called()

    def test_checkpoint_mismatch_prevents_stop_or_disk_replacement_and_keeps_dirty(self):
        self.profile['disks'][0]['sha256'] = '0' * 64
        self.save(self.runtime.profilepath, self.profile)
        initial = self.disk.read_bytes()
        with self.assertRaises(OperationError) as error:
            self.runtime.recover()
        self.assertEqual(error.exception.code, 'checkpoint_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertEqual(self.disk.read_bytes(), initial)
        self.runtime.lab.stop.assert_not_called()
        self.runtime.call.assert_not_called()

    def test_recovery_identity_failure_leaves_new_vm_quarantined_and_old_disk_retained(self):
        self.runtime.boot_id.return_value = 'boot-two'
        self.runtime.identity.return_value = {'fixed': 'wrong-after-recovery'}
        with self.assertRaises(OperationError) as error:
            self.runtime.recover()
        self.assertEqual(error.exception.code, 'identity_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')
        old = list((self.labdir / 'images').glob('retired-*.qcow2'))
        self.assertEqual(len(old), 1)
        self.assertEqual(old[0].read_bytes(), b'offline previous overlay fixture')
        self.assertFalse(lifecycle.read(self.out / 'recovery.json')['passed'])

    def test_confirmed_recovery_requires_new_boot_and_returns_ready(self):
        self.runtime.boot_id.return_value = 'boot-two'
        result = self.runtime.recover()
        self.assertTrue(result['passed'])
        self.assertEqual(self.state()['state'], 'ready')
        self.assertEqual(self.state()['boot_id'], 'boot-two')
        self.prepare.require_stopped.assert_called_once_with(self.labdir)
        self.runtime.lab.start.assert_called_once()

    def test_recovery_final_evidence_write_failure_cannot_leave_ready(self):
        self.runtime.boot_id.return_value = 'boot-two'
        def disk_error(path, value):
            if Path(path).name == 'recovery.json':
                raise OSError('injected final evidence failure')
            self.save(path, value)
        with patch.object(lifecycle, 'persist', side_effect=disk_error):
            with self.assertRaises(OSError):
                self.runtime.recover()
        self.assertNotEqual(self.state()['state'], 'ready')

    def test_cancel_rejects_request_path_not_bound_to_active_run(self):
        run_id = 'a' * 32
        active = {'run_id': run_id, 'remote': '/home/lab/k04/run-' + run_id,
                  'request': '/home/lab/k04/run-' + 'b' * 32 + '/request.json', 'boot_id': 'boot-one'}
        with self.assertRaises(OperationError) as error:
            self.runtime.cancel_guest(active)
        self.assertEqual(error.exception.code, 'invalid_active_run')
        self.runtime.ssh.assert_not_called()

    def test_cancel_rejects_stale_boot_without_sending_request(self):
        run_id = 'a' * 32
        remote = '/home/lab/k04/run-' + run_id
        active = {'run_id': run_id, 'remote': remote, 'request': remote + '/request.json', 'boot_id': 'old-boot'}
        with self.assertRaises(OperationError) as error:
            self.runtime.cancel_guest(active)
        self.assertEqual(error.exception.code, 'recovery_required')
        self.runtime.ssh.assert_not_called()

    def test_cancel_after_guest_completion_preserves_consistent_cleanup_axes(self):
        interrupted = False
        def interrupt_once(remote):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            return self.poll(remote)
        self.runtime.poll_guest.side_effect = interrupt_once
        self.runtime.cancel_guest = Mock()
        with self.assertRaises(KeyboardInterrupt):
            self.runtime.run_scenario()
        classification = lifecycle.read(self.out / 'scenario-result.json')['classification']
        self.assertEqual(classification['recovery_required'], classification['cleanup'] != 'clean')

    def reject_wrong_guest_binding(self, field, value):
        self.guest[field] = value
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'guest_result_mismatch')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertFalse((self.out / 'scenario-result.json').exists())
        self.assertEqual(lifecycle.read(self.out / 'guest-observed.json')[field], value)

    def test_result_for_another_run_is_rejected(self):
        self.reject_wrong_guest_binding('run_id', 'b' * 32)

    def test_result_for_another_boot_is_rejected(self):
        self.reject_wrong_guest_binding('boot_id', 'boot-unrelated')

    def test_fault_label_from_another_request_is_rejected(self):
        self.reject_wrong_guest_binding('fault', 'cleanup')

    def test_result_from_another_command_is_rejected(self):
        self.reject_wrong_guest_binding('command', ['/different/executor'])

    def test_different_collected_plan_cannot_pass_control_validation(self):
        def collect_wrong_plan(remote):
            self.collect(remote)
            (self.out / 'guest/trace/plan.txt').write_bytes(b'different saved plan\n')
        self.runtime.collect.side_effect = collect_wrong_plan
        result = self.runtime.run_scenario()
        self.assertFalse(result['passed'])
        self.assertFalse(result['analysis']['checks']['submitted_plan_bytes_identical'])
        self.assertEqual(result['classification']['control'], 'not_hit')
        self.assertEqual(result['classification']['property'], 'not_evaluated')

    def test_original_input_changes_do_not_replace_submitted_plan_snapshot(self):
        submitted = self.plan.read_bytes()
        def launch(code):
            self.plan.write_bytes(b'original user path changed after submission\n')
            return {'supervisor_pid': 700}
        self.runtime.guest.side_effect = launch
        result = self.runtime.run_scenario()
        self.assertTrue(result['passed'])
        self.assertEqual((self.out / 'input-plan.txt').read_bytes(), submitted)
        self.assertTrue(result['analysis']['checks']['submitted_plan_bytes_identical'])

    def test_collected_result_must_match_poll_observation(self):
        def collect_changed(remote):
            self.collect(remote)
            changed = copy.deepcopy(self.guest)
            changed['exit_code'] = 9
            self.save(self.out / 'guest/guest-result.json', changed)
        self.runtime.collect.side_effect = collect_changed
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'collection_incomplete')
        self.assertEqual(self.state()['state'], 'dirty')

    def test_collection_failure_cannot_clear_quarantine(self):
        self.runtime.collect.side_effect = RuntimeError('offline failed artifact transfer')
        with self.assertRaises(OperationError) as error:
            self.runtime.run_scenario()
        self.assertEqual(error.exception.code, 'collection_incomplete')
        self.assertEqual(self.state()['state'], 'dirty')
        self.assertTrue((self.out / 'collection-error.json').exists())

    def test_legacy_execution_cannot_bypass_dirty_marker_but_status_can_read_it(self):
        self.save(self.runtime.statepath, {'state': 'dirty', 'boot_id': 'boot-one'})
        lifecycle.guard_legacy(self.runtime_fields, 'env.status')
        for operation in ('k03.replay', 'env.check', 'build.identity'):
            with self.subTest(operation=operation):
                with self.assertRaises(OperationError) as error:
                    lifecycle.guard_legacy(self.runtime_fields, operation)
                self.assertEqual(error.exception.code, 'recovery_required')

    def test_registered_runtime_with_missing_state_cannot_bypass_legacy_guard(self):
        self.runtime.statepath.unlink()
        self.assertTrue(self.runtime.profilepath.is_file())
        lifecycle.guard_legacy(self.runtime_fields, 'env.status')
        with self.assertRaises(OperationError) as error:
            lifecycle.guard_legacy(self.runtime_fields, 'k03.replay')
        self.assertEqual(error.exception.code, 'recovery_required')

    def test_cancel_dispatch_preserves_late_guest_acknowledgement_without_clearing_state(self):
        run_id = 'c' * 32
        remote = '/home/lab/k04/run-' + run_id
        active = {'run_id': run_id, 'remote': remote, 'request': remote + '/request.json', 'boot_id': 'boot-one'}
        self.save(self.runtime.statepath, {'state': 'dirty', 'boot_id': 'boot-one', 'active': active})
        task = {**self.task, 'operation': 'scenario.cancel', 'scenario': {'run_id': run_id}}
        reply = {'run_id': run_id, 'cancel_requested': False, 'already_finished': True}
        self.runtime.cancel_guest = Mock(return_value=SimpleNamespace(stdout=json.dumps(reply).encode()))
        envelope = {'data': {}, 'result_scope': 'offline cancellation protocol fixture'}
        with patch.object(lifecycle, 'Runtime', return_value=self.runtime):
            lifecycle.dispatch(task, self.out, envelope)
        self.assertEqual(envelope['data'], {**reply, 'cleanup_verified': False})
        self.assertEqual(self.state()['state'], 'dirty')
        self.runtime.cancel_guest.assert_called_once_with(active)
        saved = lifecycle.read(self.out / 'runtime-result.json')
        self.assertFalse(saved['data']['cancel_requested'])
        self.assertTrue(saved['data']['already_finished'])


if __name__ == '__main__':
    unittest.main()

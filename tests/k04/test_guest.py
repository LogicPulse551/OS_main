"""Guest supervisor tests: offline fixtures only, never a VM/kernel scenario."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('k04_guest_tested', REPO / 'adapters/maccconc/k04_guest.py')
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.run_id = 'a' * 32
        self.directory = Path('/home/lab/k04/run-' + self.run_id)
        self.request = self.directory / 'request.json'
        self.value = {'run_id': self.run_id, 'executable': '/home/lab/k04/build-unit/bin/executor',
                      'scenario_library': '/home/lab/k04/build-unit/bin/scenario.so',
                      'plan_path': str(self.directory / 'plan.txt'), 'timeout_seconds': 5, 'fault': 'none'}

    def load(self, value=None, path=None):
        with patch.object(guest.sys, 'platform', 'linux'), \
                patch.object(guest.os, 'geteuid', return_value=0, create=True), \
                patch.object(guest, '_no_symlinks'), \
                patch.object(guest.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)), \
                patch.object(guest, '_regular'), \
                patch.object(guest.os, 'access', return_value=True), \
                patch.object(guest, '_read_regular', return_value=json.dumps(value or self.value).encode()):
            return guest.load_request(path or self.request)

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX path contract')
    def test_exact_request_contract_and_replay(self):
        path, value = self.load()
        self.assertEqual(path, self.request)
        self.assertEqual(value, self.value)

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX path contract')
    def test_unknown_field_and_run_identity_rejected(self):
        for updates in ({'command': 'sh'}, {'run_id': 'b' * 32}):
            with self.subTest(updates=updates), self.assertRaises(guest.GuestError):
                self.load(dict(self.value, **updates))

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX path contract')
    def test_executable_and_plan_cannot_escape_designated_roots(self):
        for updates in ({'executable': '/usr/bin/sh'}, {'scenario_library': '/home/lab/k03/build-a/bin/x.so'},
                        {'plan_path': '/tmp/plan.txt'}, {'executable': '/home/lab/k04/build-a/bin/../bad'}):
            with self.subTest(updates=updates), self.assertRaises(guest.GuestError):
                self.load(dict(self.value, **updates))

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX path contract')
    def test_timeout_bool_and_unknown_fault_are_rejected(self):
        for updates in ({'timeout_seconds': True}, {'timeout_seconds': 0}, {'timeout_seconds': 301},
                        {'timeout_seconds': 1.5}, {'fault': 'arbitrary'}):
            with self.subTest(updates=updates), self.assertRaises(guest.GuestError):
                self.load(dict(self.value, **updates))

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in ('{"run_id":"a","run_id":"b"}', '{"value":NaN}', '{"value":1e999}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                guest.parse_json(data)

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX ownership and symlinks')
    def test_symlink_and_fifo_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / 'file'
            file.write_text('{}')
            link = root / 'link'
            link.symlink_to(file)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            for path in (link, fifo):
                with self.subTest(path=path), self.assertRaises(guest.GuestError):
                    guest._read_regular(path, 100)

    def test_phase_parser_retains_values_and_rejects_duplicates(self):
        data = ('ordinary stdout\n'
                'KCONC_PHASE {"phase":"setup","passed":true}\n'
                'KCONC_PHASE {"phase":"property","passed":false,"oracle":"legal-dup-close-result","outcome":5}\n'
                'KCONC_PHASE {"phase":"setup","passed":true}\n'
                'KCONC_PHASE {"phase":"bad","passed":true}\n'
                'KCONC_PHASE {"phase":"teardown","passed":1}\n').encode()
        with patch.object(guest, '_read_regular', return_value=data):
            phases, errors = guest.parse_phases(Path('/fixture'), True)
        self.assertEqual(len(phases), 2)
        self.assertFalse(phases[1]['passed'])
        self.assertEqual(len(errors), 3)

    def test_phase_parser_does_not_invent_missing_stages(self):
        with patch.object(guest, '_read_regular', return_value=b'KCONC_PHASE {"phase":"setup","passed":false}\n'):
            phases, errors = guest.parse_phases(Path('/fixture'), False)
        self.assertEqual(phases, [{'phase': 'setup', 'passed': False}])
        self.assertEqual(errors, [])


@unittest.skipUnless(sys.platform == 'linux', 'Actual local Linux process-group fixtures; no VM')
class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kconc-k04-guest-test-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.request_path = self.directory / 'request.json'
        self.request_path.write_text('{}')
        self.helper = self.directory / 'fixture.py'
        self.plan = self.directory / 'plan.txt'
        self.plan.write_text('offline fixture')
        self.request = {'run_id': 'a' * 32, 'executable': sys.executable,
                        'scenario_library': str(self.helper), 'plan_path': str(self.plan),
                        'timeout_seconds': 1, 'fault': 'none'}
        # Only the privileged deployment-path validator is bypassed. Real child
        # sessions, timeout/cancellation, PID checks and signal/reaping run below.
        validated = patch.object(guest, 'load_request', return_value=(self.request_path, self.request))
        validated.start()
        self.addCleanup(validated.stop)
        original = guest._read_regular
        def local_read(path, limit, *, private=False):
            return original(path, limit, private=False)
        readable = patch.object(guest, '_read_regular', side_effect=local_read)
        readable.start()
        self.addCleanup(readable.stop)

    def helper_code(self, extra=''):
        self.helper.write_text('''import json,os,pathlib,subprocess,sys,time
trace=pathlib.Path(sys.argv[-1]); trace.mkdir()
with (trace/'testcase.stdout.txt').open('w') as log:
 for phase in ['setup','initial_state','operations','property','teardown']:
  log.write('KCONC_PHASE '+json.dumps({'phase':phase,'passed':True})+'\\n')
''' + extra)

    def test_completion_captures_real_process_identity_without_implying_reset(self):
        self.helper_code()
        result = guest.supervise(self.request_path)
        self.assertEqual(result['outcome'], 'completed')
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['remaining_pids'], [])
        self.assertEqual(result['process']['pgid'], result['process']['pid'])
        self.assertGreater(result['process']['starttime'], 0)
        self.assertEqual(len(result['phases']), 5)
        self.assertEqual(json.loads((self.directory / 'guest-result.json').read_text()), result)
        self.assertIn('not kernel state reset', result['scope'])
        with self.assertRaises(guest.GuestError):
            guest.supervise(self.request_path)

    def test_timeout_stops_and_reaps_real_parent_and_descendant(self):
        self.helper_code("child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\ntime.sleep(30)\n")
        result = guest.supervise(self.request_path)
        self.assertEqual(result['outcome'], 'timeout')
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['remaining_pids'], [])
        self.assertTrue(result['local_cleanup']['confirmed'])
        self.assertIn(15, result['local_cleanup']['signals'])

    def test_cancel_marker_stops_real_running_group(self):
        self.helper_code('time.sleep(30)\n')
        failures = []
        def request_cancel():
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    path = self.directory / 'guest-state.json'
                    if path.exists() and json.loads(path.read_text()).get('state') == 'running':
                        guest.cancel(self.request_path)
                        return
                    time.sleep(.01)
                failures.append('Supervisor never entered running state')
            except Exception as error:
                failures.append(str(error))
        thread = threading.Thread(target=request_cancel)
        thread.start()
        try:
            result = guest.supervise(self.request_path)
        finally:
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(result['outcome'], 'cancelled')
        self.assertTrue(result['cancel_requested'])
        self.assertEqual(result['remaining_pids'], [])
        self.assertTrue(result['local_cleanup']['confirmed'])

    def test_cancel_before_start_never_spawns(self):
        guest.cancel(self.request_path)
        with patch.object(guest.subprocess, 'Popen') as launch:
            result = guest.supervise(self.request_path)
            launch.assert_not_called()
        self.assertEqual(result['outcome'], 'cancelled')
        self.assertIsNone(result['process'])

    def test_exit_zero_with_remaining_descendant_is_execution_failure(self):
        self.helper_code("subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n")
        result = guest.supervise(self.request_path)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['outcome'], 'execution_failed')
        self.assertEqual(result['error']['type'], 'ResidualProcesses')
        self.assertEqual(result['remaining_pids'], [])
        self.assertTrue(result['local_cleanup']['confirmed'])

    def test_changed_leader_identity_refuses_signal(self):
        process = SimpleNamespace(pid=123, returncode=None, poll=lambda: None)
        identity = {'pid': 123, 'pgid': 123, 'session_id': 123, 'starttime': 10}
        changed = dict(identity, starttime=11)
        with patch.object(guest, 'reap_adopted', return_value=[]), \
                patch.object(guest, 'group_members', return_value=[changed]), \
                patch.object(guest.os, 'killpg') as signal_group:
            result = guest.terminate_group(process, identity, grace=.01)
            signal_group.assert_not_called()
        self.assertFalse(result['confirmed'])
        self.assertIn('Leader starttime changed', result['errors'][0])

    def test_descendant_that_changes_session_is_reported_not_falsely_clean(self):
        self.helper_code("child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)\n"
                         "pathlib.Path('escaped.pid').write_text(str(child.pid))\n")
        try:
            result = guest.supervise(self.request_path)
            pid = int((self.directory / 'escaped.pid').read_text())
            self.assertEqual(result['outcome'], 'execution_failed')
            self.assertIn(pid, result['remaining_pids'])
            self.assertFalse(result['local_cleanup']['confirmed'])
            self.assertEqual(result['local_cleanup']['signals'], [])
        finally:
            # This is the known local fixture PID, not production supervisor cleanup.
            path = self.directory / 'escaped.pid'
            if path.exists():
                pid = int(path.read_text())
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass


if __name__ == '__main__':
    unittest.main()

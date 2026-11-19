"""Offline QEMU/probe fixtures; no running process or VM is contacted."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('k04_runtime_probe_tests', REPO / 'scripts/verify-maccconc-runtime.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class RuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='k04-offline-vsock-')
        self.addCleanup(self.temporary.cleanup)
        self.lab_dir = Path(self.temporary.name).resolve()
        (self.lab_dir / 'run').mkdir()
        (self.lab_dir / 'evidence').mkdir()
        self.pidfile = self.lab_dir / 'run/qemu.pid'
        self.pidfile.write_text('4242\n')
        self.command = ['qemu-system-x86_64', '-pidfile', str(self.pidfile),
                        '-netdev', 'user,id=n0,hostfwd=tcp:127.0.0.1:2225-:22',
                        '-device', 'virtio-rng-pci', '-device', 'vhost-vsock-pci,guest-cid=6']
        self.launch = {'command': self.command}

    def live(self, command=None, raw=None):
        data = raw if raw is not None else ('\0'.join(command or self.command) + '\0').encode()
        original = Path.read_bytes

        def read(path):
            if path.as_posix() == '/proc/4242/cmdline':
                return data
            return original(path)
        return patch.object(Path, 'read_bytes', read)

    def test_live_cid_comes_from_current_launch_not_lock_default(self):
        before = copy.deepcopy(self.launch)
        with self.live():
            identity = PROBE.live_launch_identity(self.lab_dir, self.launch)
        self.assertTrue(identity['passed'])
        self.assertEqual(identity['guest_vsock_cid'], 6)
        self.assertEqual(identity['qemu_pid'], 4242)
        self.assertEqual(self.launch, before)

    def test_guest_cid_range_boundaries(self):
        for cid in (3, 6, 4294967294):
            with self.subTest(cid=cid):
                self.assertEqual(PROBE.guest_vsock_cid(['-device', f'vhost-vsock-pci,guest-cid={cid}']), cid)

    def test_guest_cid_reserved_out_of_range_and_non_decimal_rejected(self):
        for value in ('0', '1', '2', '4294967295', '4294967296', '-1', '+6', '6.0', 'True', '0x6', '６', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PROBE.guest_vsock_cid(['-device', f'vhost-vsock-pci,guest-cid={value}'])

    def test_missing_or_duplicate_vsock_devices_rejected(self):
        commands = [[], ['-device', 'virtio-rng-pci'], ['-device'],
                    ['-device', '-name', 'bad'],
                    ['-device', 'vhost-vsock-pci,guest-cid=6'] * 2,
                    ['-device', 'vhost-vsock-pci,guest-cid=6', '-device', 'vhost-vsock-pci,guest-cid=7']]
        for command in commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                PROBE.guest_vsock_cid(command)

    def test_missing_duplicate_or_malformed_guest_cid_fields_rejected(self):
        for device in ('vhost-vsock-pci', 'vhost-vsock-pci,guest-cid',
                       'vhost-vsock-pci,guest-cid=6,guest-cid=6',
                       'vhost-vsock-pci,guest-cid=6,guest-cid=7'):
            with self.subTest(device=device), self.assertRaises(ValueError):
                PROBE.guest_vsock_cid(['-device', device])

    def test_live_cid_and_other_argument_mismatches_rejected(self):
        for index, value in ((-1, 'vhost-vsock-pci,guest-cid=5'),
                             (4, 'user,id=n0,hostfwd=tcp:127.0.0.1:2224-:22'),
                             (0, 'unrelated-process')):
            command = list(self.command)
            command[index] = value
            with self.subTest(index=index), self.live(command), self.assertRaisesRegex(ValueError, 'differs'):
                PROBE.live_launch_identity(self.lab_dir, self.launch)

    def test_launch_argv_schema_and_executable_rejected(self):
        for command in (None, '', [], ['qemu-system-x86_64', True], [''], ['unrelated-process']):
            with self.subTest(command=command), self.assertRaises(ValueError):
                PROBE.live_launch_identity(self.lab_dir, {'command': command})

    def test_pid_must_belong_to_same_lab_and_be_decimal(self):
        different = copy.deepcopy(self.launch)
        different['command'][2] = str(self.lab_dir / 'other/qemu.pid')
        with self.assertRaisesRegex(ValueError, 'PID file does not match'):
            PROBE.live_launch_identity(self.lab_dir, different)
        for pid in ('0', '-42', '1.0', 'True', ''):
            self.pidfile.write_text(pid)
            with self.subTest(pid=pid), self.assertRaisesRegex(ValueError, 'positive decimal PID'):
                PROBE.live_launch_identity(self.lab_dir, self.launch)

    def test_missing_or_malformed_live_command_rejected(self):
        for raw in (b'', b'qemu-system-x86_64', b'\0'):
            with self.subTest(raw=raw), self.live(raw=raw), self.assertRaises(ValueError):
                PROBE.live_launch_identity(self.lab_dir, self.launch)

    def transport(self, observed_guest=6, bind_guest=6):
        evidence = self.lab_dir / 'evidence'
        runtime = PROBE.LOCK['runtime']
        nonce_fields = {'guest_nonce': 'a' * 64, 'host_nonce': 'b' * 64}
        server = dict(nonce_fields, passed=True, observed_peer_cid=observed_guest, port=runtime['vsock_port'])
        client = dict(nonce_fields, passed=True, host_cid=runtime['host_vsock_cid'],
                      observed_peer_cid=runtime['host_vsock_cid'], port=runtime['vsock_port'], socket_bind_cid=bind_guest)
        process = Mock(returncode=0)
        process.poll.side_effect = [None, None, 0]

        def launch(command, stdout, stderr):
            Path(command[command.index('--ready-file') + 1]).write_text('{}')
            stdout.write(json.dumps(server) + '\n')
            return process
        with patch.object(PROBE.subprocess, 'Popen', side_effect=launch) as popen, \
                patch.object(PROBE, 'ssh', return_value={'exit_code': 0, 'stdout': json.dumps(client)}) as ssh:
            result = PROBE.check_transport(object(), PurePosixPath('/guest/build'), evidence, 6)
        return result, popen.call_args.args[0], ssh.call_args.args[1]

    def test_transport_uses_verified_cid_and_locked_host_and_port(self):
        lock = copy.deepcopy(PROBE.LOCK)
        result, command, client = self.transport()
        self.assertTrue(result['passed'])
        self.assertEqual(command[command.index('--expected-peer-cid') + 1], '6')
        self.assertEqual(command[command.index('--port') + 1], str(lock['runtime']['vsock_port']))
        self.assertEqual(client[1:3], [str(lock['runtime']['host_vsock_cid']), str(lock['runtime']['vsock_port'])])
        self.assertEqual(PROBE.LOCK, lock)

    def test_transport_rejects_peer_or_bind_cid_from_old_guest(self):
        for peer, bind in ((5, 6), (6, 5)):
            with self.subTest(peer=peer, bind=bind):
                result, _, _ = self.transport(observed_guest=peer, bind_guest=bind)
                self.assertFalse(result['passed'])

    def test_transport_rejects_invalid_or_boolean_cid_before_start(self):
        for cid in (True, False, '6', 6.0, 2, 4294967295):
            with self.subTest(cid=cid), patch.object(PROBE.subprocess, 'Popen') as popen, self.assertRaises(ValueError):
                PROBE.check_transport(object(), PurePosixPath('/guest/build'), self.lab_dir / 'evidence', cid)
            popen.assert_not_called()

    def run_main(self, mode, command=None):
        (self.lab_dir / 'evidence/baseline-fork.json').write_text(json.dumps({
            'target_lab': str(self.lab_dir), 'source_lab': str(self.lab_dir / 'original')}))
        (self.lab_dir / 'evidence/last-launch.json').write_text(json.dumps(self.launch))
        fake_lab = SimpleNamespace(qmp=Mock(return_value={'running': True}))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
        output = io.StringIO()
        argv = ['verify-maccconc-runtime.py', '--guest-build', '/guest/build'] + mode
        with self.live(command), patch.object(PROBE.sys, 'argv', argv), \
                patch.dict(PROBE.os.environ, {'LAB_DIR': str(self.lab_dir), 'LAB_SSH_PORT': '2225'}), \
                patch.object(PROBE, 'file_sha256', return_value='offline-fixture'), \
                patch.object(PROBE.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(PROBE.importlib.util, 'module_from_spec', return_value=fake_lab), \
                patch.object(PROBE, 'check_transport', return_value={'passed': True}) as transport, \
                patch.object(PROBE, 'ssh') as ssh, contextlib.redirect_stdout(output):
            code = PROBE.main()
        return code, json.loads(output.getvalue()), transport, ssh

    def test_transport_only_checks_live_identity_and_passes_cid(self):
        code, result, transport, ssh = self.run_main(['--transport-only'])
        self.assertEqual(code, 0)
        self.assertEqual(result['live_launch_identity']['guest_vsock_cid'], 6)
        self.assertTrue(result['checks']['live_launch_identity'])
        self.assertEqual(transport.call_args.args[-1], 6)
        ssh.assert_not_called()

    def test_both_modes_reject_stale_launch_before_guest_operations(self):
        command = list(self.command)
        command[-1] = 'vhost-vsock-pci,guest-cid=5'
        for mode in ([], ['--transport-only']):
            with self.subTest(mode=mode):
                code, result, transport, ssh = self.run_main(mode, command)
                self.assertEqual(code, 1)
                self.assertFalse(result['passed'])
                self.assertEqual(result['errors'][0]['phase'], 'live-launch-identity')
                transport.assert_not_called()
                ssh.assert_not_called()


if __name__ == '__main__':
    unittest.main()

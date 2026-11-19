"""Recovery confinement tests; all QEMU/SSH calls are mocks, no VM is touched."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import lifecycle
from kconc.cli import OperationError


@unittest.skipUnless(sys.platform == 'linux', 'POSIX recovery path contract')
class RecoveryPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kconc-k04-recovery-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.labdir = self.base / 'os-concurrency-k04-unit'
        self.out = self.base / 'evidence-output'
        self.out.mkdir()
        self.labdir.mkdir()
        for name in ('images', 'run', 'evidence', 'keys', 'seed'):
            (self.labdir / name).mkdir()
        self.checkpoint = self.labdir / 'images/baseline-frozen.qcow2'
        self.checkpoint.write_bytes(b'offline frozen checkpoint')
        self.checkpoint.chmod(0o444)
        self.disk = self.labdir / 'images/experiment.qcow2'
        self.disk.write_bytes(b'offline writable overlay: must remain unchanged')
        self.runtime = {'lab_dir': str(self.labdir), 'ssh_port': 2225,
                        'build_lab': str(self.base / 'build'), 'kernel_build': str(self.base / 'kernel'),
                        'scenario_guest_build': '/home/lab/k03/build-01',
                        'lifecycle_guest_build': '/home/lab/k04/build-01'}
        self.profile = {'schema_version': 1, 'lab_dir': str(self.labdir), 'runtime': self.runtime,
                        'checkpoint': str(self.checkpoint),
                        'disks': [{'path': str(self.checkpoint), 'sha256': hashlib.sha256(self.checkpoint.read_bytes()).hexdigest()}],
                        'identity': {}, 'launch_env': {}}
        self.write_profile()
        (self.labdir / lifecycle.STATE).write_text(json.dumps({'state': 'dirty', 'boot_id': 'old-boot'}))
        self.lab = SimpleNamespace(stop=Mock(), start=Mock(), process_alive=Mock(return_value=False), qmp=Mock())
        loaded = patch.object(lifecycle, 'load', side_effect=lambda name, path: self.lab if name == 'k04_lab' else SimpleNamespace())
        loaded.start()
        self.addCleanup(loaded.stop)

    def write_profile(self):
        (self.labdir / lifecycle.PROFILE).write_text(json.dumps(self.profile))

    def instance(self):
        return lifecycle.Runtime({'operation': 'runtime.recover', 'runtime': self.runtime}, self.out)

    def assert_early_rejection(self, expected):
        before = self.disk.read_bytes()
        runtime = self.instance()
        with patch.object(runtime, 'call') as command:
            with self.assertRaises(OperationError) as error:
                runtime.recover()
            self.assertEqual(error.exception.code, expected)
            command.assert_not_called()
        self.lab.stop.assert_not_called()
        self.lab.start.assert_not_called()
        self.lab.qmp.assert_not_called()
        self.assertEqual(self.disk.read_bytes(), before)
        self.assertEqual(json.loads((self.labdir / lifecycle.STATE).read_text())['state'], 'dirty')

    def test_checkpoint_path_cannot_differ_from_verified_disk(self):
        other = self.base / 'unverified.qcow2'
        other.write_bytes(b'not the registered checkpoint')
        self.profile['checkpoint'] = str(other)
        self.write_profile()
        self.assert_early_rejection('invalid_checkpoint')

    def test_first_verified_disk_must_be_actual_checkpoint(self):
        self.profile['disks'][0]['path'] = str(self.base / 'other-frozen.qcow2')
        self.write_profile()
        self.assert_early_rejection('invalid_checkpoint')

    def test_checkpoint_hash_change_blocks_before_shutdown_or_rename(self):
        self.profile['disks'][0]['sha256'] = '0' * 64
        self.write_profile()
        self.assert_early_rejection('checkpoint_mismatch')

    def test_symlink_images_cannot_redirect_overlay_replacement(self):
        images = self.labdir / 'images'
        protected = self.base / 'protected-other-vm-images'
        images.rename(protected)
        images.symlink_to(protected, target_is_directory=True)
        old_disk = protected / 'experiment.qcow2'
        before = old_disk.read_bytes()
        with self.assertRaises(OperationError):
            runtime = self.instance()
            with patch.object(runtime, 'call') as command:
                runtime.recover()
                command.assert_not_called()
        self.lab.stop.assert_not_called()
        self.lab.start.assert_not_called()
        self.assertEqual(old_disk.read_bytes(), before)
        self.assertEqual(list(protected.glob('retired-*')), [])

    def test_symlink_control_and_evidence_directories_are_rejected(self):
        for component in ('run', 'evidence'):
            with self.subTest(component=component):
                source = self.labdir / component
                protected = self.base / ('protected-' + component)
                source.rename(protected)
                source.symlink_to(protected, target_is_directory=True)
                try:
                    with self.assertRaises(OperationError):
                        self.instance()
                    self.lab.stop.assert_not_called()
                finally:
                    source.unlink()
                    protected.rename(source)


if __name__ == '__main__':
    unittest.main()

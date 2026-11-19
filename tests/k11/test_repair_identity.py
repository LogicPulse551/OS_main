"""K11 identity orchestration rejects missing live observations before binding.

These fixtures mock SSH and the separately tested native/profile verifiers;
they do not claim a kernel build or guest execution.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from kconc import lifecycle, repair_identity
from kconc.cli import OperationError


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RepairIdentityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='k11-repair-identity-')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.driver = self.root/'driver.c'
        self.driver.write_bytes(b'fixture driver; real patch checks belong to verify_profile\n')
        self.kernel_path = self.root/'build-result.json'
        self.kernel = dict(task='K11', family='rmw', repaired_driver={'path': str(self.driver)})
        self.kernel_path.write_text(json.dumps(self.kernel))
        self.record_text = '{"effective_manifest_sha256":"manifest-sha","inputs":{"fixture":true}}\n'
        self.facts = dict(record=json.loads(self.record_text), record_text=self.record_text,
            record_sha256=sha(self.record_text.encode()), manifest_sha256='manifest-sha',
            manifest=[], hashes={'fixture.so': 'compiled-fixture-sha'}, parents={}, source_hashes={},
            device=True, executors_executable=True)
        self.analyzer = SimpleNamespace(PROFILE_ID='kconc.k11.regmap-repair-v1',
            verify_native=Mock(return_value={'passed': True}),
            verify_profile=Mock(side_effect=self.profile))
        self.session_args = []
        owner = self

        class Session:
            def __init__(self, args):
                owner.session_args.append(args)
                self.args = args

            def identity(self):
                self.args.output.mkdir()
                (self.args.output/'identity.json').write_text(json.dumps({
                    'passed': True, 'kernel': {'build_result': str(owner.kernel_path)}}))
                return {'kernel_image': 'live-kernel-sha', 'vmlinux': 'live-vmlinux-sha'}

        self.runtime = SimpleNamespace(runtime=dict(sample_guest_build='/home/lab/k11/build-01',
            search_guest_build='/home/lab/k11/build-01', scenario_guest_build='/home/lab/k03/build-01',
            build_lab='/unused-build-lab', kernel_build='/unused-new-kernel'),
            out=self.root/'evidence', k03=SimpleNamespace(Session=Session),
            guest=Mock(side_effect=lambda code: copy.deepcopy(self.facts)))
        self.runtime.out.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(repair_identity, 'load', return_value=self.analyzer).start()
        patch.object(repair_identity.candidates, 'load_catalog', return_value={'inputs': [{'native_so': 'fixture.so'}]}).start()

    def profile(self, binding):
        return SimpleNamespace(identity=dict(profile_id=binding['profile_id'], family=binding['family'],
            kernel_record_sha256=binding['kernel_record']['sha256'],
            native_record_sha256=binding['native_record']['sha256'],
            driver_sha256=binding['repaired_driver']['sha256']))

    def run_identity(self):
        return repair_identity.current_identity(self.runtime)

    def assert_error(self, code):
        with self.assertRaises(OperationError) as caught:
            self.run_identity()
        self.assertEqual(caught.exception.code, code)

    def test_live_identity_calls_native_and_profile_verifiers(self):
        original = self.kernel_path.read_bytes()
        identity, binding = self.run_identity()
        self.assertEqual(identity['kernel_and_k03']['kernel_image'], 'live-kernel-sha')
        self.assertEqual(identity['repair_profile']['profile_id'], 'kconc.k11.regmap-repair-v1')
        self.analyzer.verify_native.assert_called_once()
        self.analyzer.verify_profile.assert_called_once_with(binding)
        self.assertEqual(self.kernel_path.read_bytes(), original)
        self.assertEqual(Path(binding['kernel_record']['path']).read_bytes(), original)
        self.assertEqual(Path(binding['repaired_driver']['path']).read_bytes(), self.driver.read_bytes())

    def test_evidence_directory_does_not_change_artifact_identity(self):
        first, binding_a = self.run_identity()
        self.runtime.out = self.root/'second-evidence'
        self.runtime.out.mkdir()
        second, binding_b = self.run_identity()
        self.assertEqual(first, second)
        self.assertNotEqual(binding_a['kernel_record']['path'], binding_b['kernel_record']['path'])

    def test_sampler_executor_split_is_rejected_before_live_collection(self):
        self.runtime.runtime['search_guest_build'] = '/home/lab/k11/build-02'
        self.assert_error('repair_build_required')
        self.assertEqual(self.session_args, [])
        self.runtime.guest.assert_not_called()

    def test_old_native_build_cannot_select_repaired_contract(self):
        self.runtime.runtime.update(sample_guest_build='/home/lab/k10-control/build-01',
            search_guest_build='/home/lab/k10-control/build-01')
        self.assert_error('repair_build_required')
        self.assertEqual(self.session_args, [])

    def test_failed_live_kernel_check_cannot_use_saved_native_evidence(self):
        session = Mock()
        session.identity.side_effect = ValueError('live kernel chain failed')
        self.runtime.k03.Session = Mock(return_value=session)
        with self.assertRaisesRegex(ValueError, 'live kernel chain failed'):
            self.run_identity()
        self.runtime.guest.assert_not_called()
        self.analyzer.verify_profile.assert_not_called()

    def test_old_kernel_record_rejected_before_native_collection(self):
        self.kernel['task'] = 'K10'
        self.kernel_path.write_text(json.dumps(self.kernel))
        self.assert_error('repair_build_required')
        self.runtime.guest.assert_not_called()

    def test_unknown_kernel_family_rejected_before_native_collection(self):
        self.kernel['family'] = 'other'
        self.kernel_path.write_text(json.dumps(self.kernel))
        self.assert_error('repair_build_required')
        self.runtime.guest.assert_not_called()

    def test_real_device_is_required(self):
        self.facts['device'] = False
        self.assert_error('repair_native_mismatch')
        self.analyzer.verify_profile.assert_not_called()

    def test_executable_permission_is_required(self):
        self.facts['executors_executable'] = False
        self.assert_error('repair_native_mismatch')
        self.analyzer.verify_profile.assert_not_called()

    def test_observed_manifest_hash_must_match_native_record(self):
        self.facts['manifest_sha256'] = 'different-manifest'
        self.assert_error('repair_native_mismatch')
        self.analyzer.verify_profile.assert_not_called()

    def test_exported_record_bytes_must_match_live_record_hash(self):
        self.facts['record_text'] += ' '
        self.assert_error('repair_native_mismatch')
        self.analyzer.verify_profile.assert_not_called()

    def test_native_verifier_rejection_cannot_be_overridden_by_device_flags(self):
        self.analyzer.verify_native.side_effect = ValueError('parent source differs')
        with self.assertRaisesRegex(ValueError, 'parent source differs'):
            self.run_identity()
        self.analyzer.verify_profile.assert_not_called()

    def test_profile_verifier_rejection_cannot_be_overridden_by_successful_native_check(self):
        self.analyzer.verify_profile.side_effect = ValueError('wrong repaired driver')
        with self.assertRaisesRegex(ValueError, 'wrong repaired driver'):
            self.run_identity()
        self.assertFalse((self.runtime.out/'repair-identity.json').exists())


class RepairRecoveryGuardTests(unittest.TestCase):
    def test_dirty_k11_blocks_legacy_execution_but_status_remains_read_only(self):
        with tempfile.TemporaryDirectory(prefix='k11-recovery-guard-') as folder:
            lab = Path(folder)
            (lab/'run').mkdir()
            (lab/'k11-runtime.json').write_text('{}')
            state = lab/'run/k11-state.json'
            for value in ('dirty', 'recovering', 'unknown'):
                with self.subTest(state=value):
                    state.write_text(json.dumps({'state': value}))
                    with self.assertRaises(OperationError) as caught:
                        lifecycle.guard_legacy({'lab_dir': str(lab)}, 'env.probe')
                    self.assertEqual(caught.exception.code, 'recovery_required')
                    lifecycle.guard_legacy({'lab_dir': str(lab)}, 'env.status')
            state.write_text(json.dumps({'state': 'ready'}))
            lifecycle.guard_legacy({'lab_dir': str(lab)}, 'env.probe')


if __name__ == '__main__':
    unittest.main()

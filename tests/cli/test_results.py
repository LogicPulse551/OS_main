"""Result-reader boundaries; these fixtures do not stand in for kernel runs."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from kconc.results import MAX_RESULT_BYTES, ResultError, read_result


def runtime():
    return {'task': 'K02', 'mode': 'full', 'passed': True,
            'checks': {'kernel_identity': True, 'kcov': True}, 'errors': [], 'exit_code': 0}


def record():
    return {'action': 'record', 'passed': True, 'summary': {
        'candidate_count': 11, 'upstream_injection_failed': 0, 'upstream_wait_timeout': 7,
        'upstream_reordered': 4, 'evidence_control_valid': 4}}


def replay():
    return {'action': 'replay', 'passed': True, 'comparison': {
        'passed': True, 'checks': {'plan_identical': True, 'target_hit': True},
        'errors': [], 'differences': [], 'counts': {'actual': {'A': {'fs_file_memory_records': 27}}},
        'projection': {'actual': ['large raw event content'] * 2000},
        'scope': 'fixed sample key path, not full VM determinism'}}


def envelope(status='passed', code=0):
    return {'schema_version': 1, 'kind': 'kconc.run', 'operation': 'env.status',
            'status': status, 'exit_code': code, 'result_scope': 'Runtime status observation only',
            'error': None, 'data': {'backend': 'existing tool'}}


class ResultReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kconc-result-test-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'result.json'

    def write(self, value):
        self.path.write_text(json.dumps(value), encoding='utf-8')
        return self.path

    def invalid(self, value, code=None, **kwargs):
        with self.assertRaises(ResultError) as caught:
            read_result(self.write(value), **kwargs)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertTrue(caught.exception.message)

    def test_k02_runtime_summary_is_historical_and_bound_to_bytes(self):
        source = self.write(runtime())
        result = read_result(source)
        self.assertEqual(result['kind'], 'maccconc.k02.runtime')
        self.assertIs(result['reported_passed'], True)
        self.assertIs(result['revalidated'], False)
        self.assertEqual(result['summary']['check_count'], 2)
        self.assertEqual(result['source']['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(result['source']['bytes'], source.stat().st_size)
        self.assertEqual(result['source']['path'], str(source.resolve()))

    def test_k02_transport_and_false_checks_are_not_full_success(self):
        data = runtime()
        data.update(mode='transport-only', passed=False, exit_code=1)
        data['checks']['kcov'] = False
        result = read_result(self.write(data), backend_exit_code=1)
        self.assertIs(result['reported_passed'], False)
        self.assertEqual(result['summary']['mode'], 'transport-only')
        self.assertEqual(result['summary']['failed_checks'], ['kcov'])
        data['passed'] = True
        self.invalid(data, 'inconsistent_result')

    def test_record_keeps_failed_candidate_denominator(self):
        result = read_result(self.write(record()), backend_exit_code=0)
        self.assertEqual(result['summary']['candidate_count'], 11)
        self.assertEqual(result['summary']['upstream_wait_timeout'], 7)
        self.assertEqual(result['summary']['evidence_control_valid'], 4)
        self.assertIn('not kernel bug', result['scope'])

    def test_record_rejects_inconsistent_counts(self):
        for key, value in [('candidate_count', 4), ('upstream_wait_timeout', -1),
                           ('evidence_control_valid', 5), ('candidate_count', True)]:
            with self.subTest(key=key, value=value):
                data = record(); data['summary'][key] = value
                self.invalid(data)

    def test_replay_omits_large_projection_but_keeps_match_counts(self):
        result = read_result(self.write(replay()))
        self.assertIs(result['reported_passed'], True)
        self.assertIs(result['revalidated'], False)
        self.assertEqual(result['summary']['counts']['actual']['A']['fs_file_memory_records'], 27)
        self.assertNotIn('projection', json.dumps(result))
        self.assertLess(len(json.dumps(result)), 2500)

    def test_replay_rejects_claimed_success_with_differences_or_failed_checks(self):
        data = replay(); data['comparison']['differences'] = [{'thread': 'A'}]
        self.invalid(data, 'inconsistent_result')
        data = replay(); data['comparison']['checks']['target_hit'] = False
        self.invalid(data, 'inconsistent_result')
        data = replay(); data['comparison']['passed'] = False
        self.invalid(data, 'inconsistent_result')

    def test_early_backend_failure_needs_no_success_payload(self):
        result = read_result(self.write({'action': 'bind', 'passed': False,
                            'error': {'type': 'ValueError', 'message': 'Missing source mapping'}}), backend_exit_code=1)
        self.assertIs(result['reported_passed'], False)
        self.assertEqual(result['summary']['error']['message'], 'Missing source mapping')
        self.invalid({'action': 'bind', 'passed': True, 'error': {'message': 'failure'}}, 'inconsistent_result')

    def test_nonzero_backend_never_promotes_passed_payload(self):
        self.invalid(replay(), 'inconsistent_result', backend_exit_code=2)
        data = replay(); data['passed'] = False
        result = read_result(self.write(data), backend_exit_code=0)
        self.assertIs(result['reported_passed'], False)
        self.invalid(runtime(), 'invalid_result', backend_exit_code=True)

    def test_child_exit_pass_means_negative_fixture_rejected(self):
        data = {'action': 'child-exit', 'passed': True,
                'run': {'child_ok': False, 'child_status': 1792, 'control_valid': False}}
        result = read_result(self.write(data), backend_exit_code=0)
        self.assertTrue(result['summary']['negative_fixture_rejected'])
        self.assertIn('negative test', result['scope'])
        data['run']['child_status'] = 0
        self.invalid(data, 'inconsistent_result')

    def test_view_is_only_archived_transport(self):
        data = {'action': 'view', 'passed': True, 'mode': 'archived-trace-view-only',
                'frame_bytes': 3988, 'frame_sha256': '1' * 64, 'trace': '/saved/reference', 'ui_verified': False}
        result = read_result(self.write(data))
        self.assertFalse(result['summary']['ui_verified'])
        self.assertIn('no testcase execution', result['scope'])
        data['ui_verified'] = True
        self.invalid(data, 'inconsistent_result')

    def test_build_and_binding_have_distinct_scopes(self):
        result = read_result(self.write({'action': 'build', 'passed': True, 'guest_build': '/guest/build', 'exit_code': 0}))
        self.assertIn('compilation does not establish controlled execution', result['scope'])
        self.invalid({'action': 'build', 'passed': True, 'guest_build': '/guest/build', 'exit_code': 1}, 'inconsistent_result')
        data = {'action': 'bind', 'passed': True, 'candidate': 'candidate-000003',
                'binding': {'candidate': 'candidate-000003', 'plan_sha256': 'a' * 64, 'identity': {'kernel_image': 'b' * 64}}}
        result = read_result(self.write(data))
        self.assertEqual(result['summary']['plan_sha256'], 'a' * 64)
        data['binding']['candidate'] = 'candidate-000004'
        self.invalid(data, 'inconsistent_result')

    def test_boolean_and_required_fields_are_strict(self):
        for value in [1, 0, 'true', None]:
            with self.subTest(value=value):
                data = runtime(); data['passed'] = value
                self.invalid(data, 'invalid_result')
        data = runtime(); del data['passed']
        self.invalid(data, 'invalid_result')
        data = runtime(); data['checks']['kcov'] = 1
        self.invalid(data, 'invalid_result')
        self.invalid({'action': 'replay', 'passed': True}, 'invalid_result')

    def test_unknown_build_identity_and_trace_files_do_not_become_success(self):
        for data in [{'passed': True}, {'stage': 'kernel', 'artifacts': []},
                     {'identity': {}, 'candidate': 'candidate-000003'}, {'control_valid': True},
                     {'task': 'K02', 'passed': True, 'runtime_checks': {}}]:
            with self.subTest(data=data):
                self.invalid(data, 'unsupported_result')
        self.invalid({'action': [], 'passed': True}, 'unsupported_result')

    def test_json_errors_duplicate_keys_and_nonfinite_numbers(self):
        for text in ['[]', '{', '{"action":"record","passed":true,"passed":false}',
                     '{"action":"record","passed":true,"summary":{"x":0,"x":1}}',
                     '{"action":"record","passed":true,"x":NaN}',
                     '{"action":"record","passed":true,"x":1e999}']:
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(ResultError) as caught:
                    read_result(self.path)
                self.assertEqual(caught.exception.code, 'invalid_result')

    def test_missing_directory_and_oversized_files_are_rejected(self):
        for path in [self.path, self.path.parent]:
            with self.subTest(path=path):
                with self.assertRaises(ResultError) as caught:
                    read_result(path)
                self.assertEqual(caught.exception.code, 'result_io_error')
        with self.path.open('wb') as stream:
            stream.truncate(MAX_RESULT_BYTES + 1)
        with self.assertRaises(ResultError) as caught:
            read_result(self.path)
        self.assertEqual(caught.exception.code, 'result_too_large')

    def test_unified_read_is_not_promoted_to_passed(self):
        data = envelope('read')
        data.update(operation='result.read', result_scope='Historical result read only')
        data['data'] = {'reported_passed': True, 'projection': ['large event'] * 2000}
        result = read_result(self.write(data))
        self.assertIsNone(result['reported_passed'])
        self.assertIs(result['revalidated'], False)
        self.assertEqual(result['summary']['status'], 'read')
        self.assertTrue(result['summary']['data']['reported_passed'])
        self.assertNotIn('projection', json.dumps(result))
        self.invalid(data, 'inconsistent_result', backend_exit_code=1)

    def test_unified_failure_statuses_remain_failures(self):
        for status in ['failed', 'invalid', 'unsupported', 'interrupted']:
            with self.subTest(status=status):
                data = envelope(status, 2)
                data['error'] = {'code': status, 'message': 'Operation did not complete'}
                result = read_result(self.write(data), backend_exit_code=2)
                self.assertIs(result['reported_passed'], False)
                self.assertEqual(result['summary']['status'], status)
                data['exit_code'] = 0
                self.invalid(data, 'inconsistent_result')

    def test_unified_contract_rejects_inconsistent_or_invalid_envelopes(self):
        result = read_result(self.write(envelope()), backend_exit_code=0)
        self.assertIs(result['reported_passed'], True)
        for key, value in [('schema_version', True), ('schema_version', 2), ('status', []),
                           ('exit_code', True), ('data', []), ('error', 'failed'), ('result_scope', '')]:
            with self.subTest(key=key, value=value):
                data = envelope(); data[key] = value
                self.invalid(data)
        data = envelope(); data['error'] = {'message': 'Failed'}
        self.invalid(data, 'inconsistent_result')

    def test_unified_early_failures_allow_unknown_operation(self):
        for status, code in [('invalid', 2), ('failed', 1), ('unsupported', 2), ('interrupted', 130)]:
            with self.subTest(status=status):
                data = envelope(status, code)
                data.update(operation=None, error={'code': 'invalid_manifest', 'message': 'Operation not yet decoded'})
                result = read_result(self.write(data), backend_exit_code=code)
                self.assertIs(result['reported_passed'], False)
                self.assertIsNone(result['summary']['operation'])
        for status in ['passed', 'read']:
            with self.subTest(status=status):
                data = envelope(status); data['operation'] = None
                self.invalid(data, 'invalid_result')
        data = envelope('invalid', 2); del data['operation']
        self.invalid(data, 'invalid_result')


if __name__ == '__main__':
    unittest.main()

"""K04 manifest, dispatch and historical-result boundaries; no VM execution."""
from contextlib import nullcontext
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import cli
from kconc.manifest import CATALOG, LIFECYCLE_OPERATIONS, ManifestError, normalize_manifest
from kconc.results import ResultError, read_result


class K04EntryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kconc-k04-entry-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.runtime = {'lab_dir': str(self.base / 'runtime'), 'ssh_port': 2225,
                        'build_lab': str(self.base / 'build'), 'kernel_build': str(self.base / 'kernel'),
                        'scenario_guest_build': '/home/lab/k03/build-01',
                        'lifecycle_guest_build': '/home/lab/k04/build-01'}

    def task(self, operation='scenario.run'):
        task = {'schema_version': 1, 'operation': operation, 'runtime': self.runtime.copy()}
        if operation == 'scenario.run':
            task['inputs'] = {'plan': 'saved plan.txt'}
        if operation == 'scenario.cancel':
            task['scenario'] = {'run_id': 'a' * 32}
        return task

    def reject(self, task):
        with self.assertRaises(ManifestError) as caught:
            normalize_manifest(task, self.base)
        self.assertEqual(caught.exception.code, 'invalid_manifest')

    def write_result(self, value):
        path = self.base / 'record.json'
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    @staticmethod
    def classification():
        return {'execution': 'controlled_completed', 'control': 'hit', 'property': 'holds',
                'trace': 'valid', 'cleanup': 'clean', 'passed': True, 'recovery_required': False}

    def test_runtime_profiles_and_plan_are_required(self):
        full = {'lab_dir', 'ssh_port', 'build_lab', 'kernel_build', 'scenario_guest_build', 'lifecycle_guest_build'}
        for operation in LIFECYCLE_OPERATIONS:
            task = self.task(operation)
            normalize_manifest(task, self.base)
            required = full if operation in {'runtime.initialize', 'runtime.recover', 'scenario.run'} else {'lab_dir', 'ssh_port'}
            for name in required:
                value = copy.deepcopy(task)
                del value['runtime'][name]
                with self.subTest(operation=operation, missing=name):
                    self.reject(value)
        value = self.task(); value['inputs'] = {}
        self.reject(value)

    def test_run_defaults_and_plan_relative_path(self):
        task = normalize_manifest(self.task(), self.base)
        self.assertEqual(task['scenario'], {'id': 'dup-close-v1', 'fault': 'none', 'timeout_seconds': 30})
        self.assertEqual(task['inputs']['plan'], str((self.base / 'saved plan.txt').resolve()))
        for fault in ['none', 'setup', 'hang', 'cleanup', 'property']:
            value = self.task(); value['scenario'] = {'fault': fault, 'timeout_seconds': 1}
            self.assertEqual(normalize_manifest(value, self.base)['scenario']['fault'], fault)

    def test_bad_scenario_fields_and_types_are_rejected(self):
        invalid = [None, [], False, {'id': 'regmap'}, {'id': False}, {'fault': 'shell'}, {'fault': []},
                   {'timeout_seconds': True}, {'timeout_seconds': '30'}, {'timeout_seconds': 0},
                   {'timeout_seconds': 121}, {'timeout_seconds': 1.5}, {'command': 'true'}, {'run_id': 'a' * 32}]
        for scenario in invalid:
            task = self.task(); task['scenario'] = scenario
            with self.subTest(scenario=scenario):
                self.reject(task)
        for operation in CATALOG:
            if operation.startswith('scenario.'):
                continue
            task = self.task(operation); task['scenario'] = {}
            with self.subTest(operation=operation):
                self.reject(task)

    def test_lifecycle_guest_path_is_confined(self):
        for path in ['/home/lab/k04', '/home/lab/k04/build-', '/home/lab/k04/other',
                     '/home/lab/k040/build-one', '/home/lab/k04/build-one/../x',
                     '/home/lab/k03/build-one', 'relative', '', True]:
            task = self.task(); task['runtime']['lifecycle_guest_build'] = path
            with self.subTest(path=path):
                self.reject(task)
        for path in ['/home/lab/k04/build-one', '/home/lab/k04/build-one/nested']:
            task = self.task(); task['runtime']['lifecycle_guest_build'] = path
            self.assertEqual(normalize_manifest(task, self.base)['runtime']['lifecycle_guest_build'], path)

    def test_cancel_has_explicit_run_identity(self):
        task = self.task('scenario.cancel')
        task['runtime'] = {key: self.runtime[key] for key in ['lab_dir', 'ssh_port']}
        self.assertEqual(normalize_manifest(task, self.base)['scenario']['run_id'], 'a' * 32)
        for value in [None, {}, {'run_id': ''}, {'run_id': '../run'}, {'run_id': 'a' * 31},
                      {'run_id': 'g' * 32}, {'run_id': 'A' * 32}, {'run_id': True},
                      {'run_id': 'a' * 32, 'timeout_seconds': 3}]:
            task['scenario'] = value
            with self.subTest(value=value):
                self.reject(task)

    def fake_lifecycle(self):
        module = types.ModuleType('kconc.lifecycle')
        module.dispatch = Mock()
        module.guard_legacy = Mock()
        return module

    def test_new_operations_dispatch_before_legacy_lock_or_process(self):
        module = self.fake_lifecycle()
        def dispatch(task, out, envelope):
            envelope['data'] = {'dispatched': task['operation']}
            envelope['backend'] = {'kind': 'in-process-lifecycle'}
        module.dispatch.side_effect = dispatch
        for operation in LIFECYCLE_OPERATIONS:
            task = normalize_manifest(self.task(operation), self.base)
            envelope = {'data': {}}
            with patch.dict(sys.modules, {'kconc.lifecycle': module}), \
                    patch.object(cli, 'runtime_lock', side_effect=AssertionError('lifecycle owns locking')), \
                    patch.object(cli, 'execute_process', side_effect=AssertionError('no additional backend')):
                cli.run_live(task, self.base / operation, envelope)
            self.assertEqual(envelope['data']['dispatched'], operation)
        self.assertEqual(module.dispatch.call_count, len(LIFECYCLE_OPERATIONS))
        module.guard_legacy.assert_not_called()

    def test_legacy_guard_runs_under_lock_before_any_execution(self):
        module = self.fake_lifecycle()
        module.guard_legacy.side_effect = cli.OperationError('recovery_required', 'offline fixture')
        task = normalize_manifest({'schema_version': 1, 'operation': 'k03.view', 'runtime': self.runtime,
                                   'inputs': {'trace': 'historical trace'}}, self.base)
        with patch.dict(sys.modules, {'kconc.lifecycle': module}), \
                patch.object(cli, 'runtime_lock', return_value=nullcontext()) as lock, \
                patch.object(cli, 'execute_process') as execute, \
                self.assertRaises(cli.OperationError) as caught:
            cli.run_live(task, self.base, {'data': {}})
        self.assertEqual(caught.exception.code, 'recovery_required')
        lock.assert_called_once_with(task['runtime'])
        module.guard_legacy.assert_called_once_with(task['runtime'], 'k03.view')
        execute.assert_not_called()

    def test_runtime_records_are_historical_only(self):
        value = {'schema_version': 1, 'kind': 'kconc.runtime', 'passed': True,
                 'operation': 'runtime.recover', 'scope': 'Recorded recovery', 'state': 'ready'}
        result = read_result(self.write_result(value))
        self.assertIs(result['reported_passed'], True)
        self.assertIs(result['revalidated'], False)
        self.assertIn('not revalidated', result['scope'])
        value['passed'] = False
        value['error'] = {'code': 'recovery_failed'}
        self.assertIs(read_result(self.write_result(value))['reported_passed'], False)

    def test_scenario_result_keeps_all_axes(self):
        value = {'schema_version': 1, 'kind': 'kconc.scenario', 'passed': True,
                 'scope': 'Fixed sample only', 'classification': self.classification(),
                 'guest': {'raw_report': 'retained in source record'}}
        result = read_result(self.write_result(value))
        self.assertEqual(result['summary']['classification'], value['classification'])
        self.assertIs(result['revalidated'], False)
        value['passed'] = False
        value['classification'].update(passed=False, cleanup='unconfirmed', recovery_required=True, execution='timeout', property='not_evaluated')
        result = read_result(self.write_result(value))
        self.assertIs(result['reported_passed'], False)
        self.assertEqual(result['summary']['classification']['execution'], 'timeout')

    def test_result_contradictions_and_malformed_records_rejected(self):
        record = {'schema_version': 1, 'kind': 'kconc.scenario', 'passed': True,
                  'scope': 'Fixed sample', 'classification': self.classification()}
        cases = []
        for axis, value in [('cleanup', 'failed'), ('property', 'violated'), ('trace', 'overflow'),
                            ('recovery_required', True), ('passed', False), ('execution', []),
                            ('control', 'made-up')]:
            item = copy.deepcopy(record); item['classification'][axis] = value; cases.append(item)
        for key, value in [('schema_version', True), ('passed', 1), ('scope', ''),
                           ('error', {'code': 'contradiction'}), ('classification', [])]:
            item = copy.deepcopy(record); item[key] = value; cases.append(item)
        for item in cases:
            with self.subTest(item=item), self.assertRaises(ResultError):
                read_result(self.write_result(item))
        with self.assertRaises(ResultError):
            read_result(self.write_result(record), backend_exit_code=1)
        value = {'schema_version': 1, 'kind': 'kconc.runtime', 'passed': True, 'scope': 'state', 'operation': ''}
        with self.assertRaises(ResultError):
            read_result(self.write_result(value))


if __name__ == '__main__':
    unittest.main()

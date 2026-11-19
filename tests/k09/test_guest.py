"""Validate real supervisor requests offline; never execute a guest scenario."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def load_guest(stage):
    def module(name, file):
        spec = importlib.util.spec_from_file_location(name, REPO / 'adapters/maccconc' / file)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value
    base = module('path_base_' + stage, 'k04_guest.py')
    if stage == 'k04':
        return base
    with patch.dict(sys.modules, {'k04_guest': base}):
        module('path_wrapper_' + stage, stage + '_guest.py')
    return base


@unittest.skipUnless(sys.platform == 'linux', 'POSIX guest path contract')
class GuestBuildRootTests(unittest.TestCase):
    def setUp(self):
        self.guest = load_guest('k09')
        self.run_id = 'a' * 32
        self.directory = self.guest.ROOT / ('run-' + self.run_id)
        self.request = dict(run_id=self.run_id,
            executable='/home/lab/k10-control/build-01/bin/kcov-execute-k09-ab',
            scenario_library='/home/lab/k10-control/build-01/bin/regmap-k06-disjoint-bits-split.so',
            plan_path=str(self.directory / 'plan.txt'), timeout_seconds=60, fault='none')

    def load(self, value=None, path=None, guest=None):
        guest = self.guest if guest is None else guest
        value = self.request if value is None else value
        path = self.directory / 'request.json' if path is None else path
        # Only filesystem facts and privilege are fixtures. The actual request,
        # root, normalized-path, field and ownership-argument checks run here.
        with patch.object(guest.os, 'geteuid', return_value=0), \
                patch.object(guest, '_no_symlinks'), \
                patch.object(guest.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)), \
                patch.object(guest, '_regular') as regular, \
                patch.object(guest.os, 'access', return_value=True), \
                patch.object(guest, '_read_regular', return_value=json.dumps(value).encode()) as read:
            result = guest.load_request(path)
            read.assert_called_once_with(path, guest.MAX_REQUEST, private=True)
            if value['plan_path'] is not None:
                regular.assert_any_call(Path(value['plan_path']), private=True)
            return result

    def test_old_control_and_repair_builds_pass_full_load_and_fixed_command(self):
        for root in ('/home/lab/k09', '/home/lab/k10-control', '/home/lab/k11'):
            for order in ('ab', 'ba'):
                with self.subTest(root=root, order=order):
                    value = dict(self.request,
                        executable=root + '/build-01/bin/kcov-execute-k09-' + order,
                        scenario_library=root + '/build-01/bin/regmap-k06-disjoint-bits-split.so')
                    path, loaded = self.load(value)
                    self.assertEqual(path, self.directory / 'request.json')
                    self.assertEqual(self.guest.command_for_request(loaded, path.parent),
                        [value['executable'], value['scenario_library'], '--k09-execute', order,
                         value['plan_path'], str(self.directory / 'trace')])

    def test_request_run_root_is_not_expanded(self):
        for root in ('/home/lab/k10-control', '/home/lab/k11', '/home/lab/k04', '/home/lab/k090'):
            path = Path(root) / ('run-' + self.run_id) / 'request.json'
            with self.subTest(path=path), self.assertRaises(self.guest.GuestError):
                self.load(path=path)

    def test_plan_must_stay_in_exact_original_run(self):
        for plan in ('/home/lab/k10-control/run-' + self.run_id + '/plan.txt',
                     '/home/lab/k09/run-' + 'b' * 32 + '/plan.txt',
                     str(self.directory / 'nested/plan.txt')):
            with self.subTest(plan=plan), self.assertRaises(self.guest.GuestError):
                self.load(dict(self.request, plan_path=plan))

    def test_nearby_or_nested_build_roots_rejected_for_both_fields(self):
        for field in ('executable', 'scenario_library'):
            for root in ('/home/lab/k10-control-extra', '/home/lab/k10', '/home/lab/k04',
                         '/home/lab/k10-control/nested', '/tmp/k10-control',
                         '/home/lab/k11-extra', '/home/lab/k11/nested', '/tmp/k11'):
                value = dict(self.request)
                value[field] = root + '/build-01/bin/' + Path(value[field]).name
                with self.subTest(field=field, root=root), self.assertRaises(self.guest.GuestError):
                    self.load(value)

    def test_build_and_bin_components_are_still_exact(self):
        for prefix in ('/home/lab/k10-control/build-/bin', '/home/lab/k10-control/other/bin',
                       '/home/lab/k10-control/build-01/other',
                       '/home/lab/k10-control/build-01/bin/nested'):
            with self.subTest(prefix=prefix), self.assertRaises(self.guest.GuestError):
                self.load(dict(self.request, executable=prefix + '/kcov-execute-k09-ab'))

    def test_aliases_traversal_and_relative_paths_rejected(self):
        for path in ('/home/lab/k09/../k10-control/build-01/bin/kcov-execute-k09-ab',
                     '/home/lab//k10-control/build-01/bin/kcov-execute-k09-ab',
                     '/home/lab/k10-control/./build-01/bin/kcov-execute-k09-ab',
                     'home/lab/k10-control/build-01/bin/kcov-execute-k09-ab'):
            with self.subTest(path=path), self.assertRaises(self.guest.GuestError):
                self.load(dict(self.request, executable=path))

    def test_mixed_allowed_builds_still_rejected_by_command_contract(self):
        for library in ('/home/lab/k09/build-01/bin/regmap-k06-disjoint-bits-split.so',
                        '/home/lab/k10-control/build-02/bin/regmap-k06-disjoint-bits-split.so'):
            path, loaded = self.load(dict(self.request, scenario_library=library))
            with self.subTest(library=library), self.assertRaises(self.guest.GuestError):
                self.guest.command_for_request(loaded, path.parent)

    def test_unknown_names_and_missing_plan_remain_rejected(self):
        for change in (dict(executable='/home/lab/k10-control/build-01/bin/arbitrary'),
                       dict(scenario_library='/home/lab/k10-control/build-01/bin/unknown.so'),
                       dict(plan_path=None)):
            path, loaded = self.load(dict(self.request, **change))
            with self.subTest(change=change), self.assertRaises(self.guest.GuestError):
                self.guest.command_for_request(loaded, path.parent)
        with self.assertRaises(self.guest.GuestError):
            self.load(dict(self.request, fault='setup'))

    def test_earlier_wrappers_default_to_their_current_root_only(self):
        for stage in ('k04', 'k05', 'k06', 'k07'):
            guest = load_guest(stage)
            self.assertIsNone(guest.BUILD_ROOTS)
            root = '/home/lab/' + stage
            directory = Path(root) / ('run-' + self.run_id)
            request = dict(self.request, executable=root + '/build-01/bin/executor',
                scenario_library=root + '/build-01/bin/scenario.so',
                plan_path=str(directory / 'plan.txt'))
            path, loaded = self.load(request, directory / 'request.json', guest)
            self.assertEqual(loaded, request)
            for field in ('executable', 'scenario_library'):
                value = dict(request)
                value[field] = '/home/lab/k10-control/build-01/bin/' + Path(value[field]).name
                with self.subTest(stage=stage, field=field), self.assertRaises(guest.GuestError):
                    self.load(value, path, guest)

    def test_sampler_explicit_repair_root_does_not_change_run_root_or_other_wrappers(self):
        guest = load_guest('k08')
        self.assertEqual(guest.BUILD_ROOTS, {Path('/home/lab/k08'), Path('/home/lab/k11')})
        directory = guest.ROOT / ('run-' + self.run_id)
        for root in ('/home/lab/k08', '/home/lab/k11'):
            request = dict(self.request, executable=root + '/build-01/bin/kcov-sample-k08-ab',
                scenario_library=root + '/build-01/bin/regmap-k07-different-registers-per-role.so', plan_path=None)
            path, loaded = self.load(request, directory / 'request.json', guest)
            self.assertEqual(guest.command_for_request(loaded, path.parent),
                [request['executable'], request['scenario_library'], '--k08-baseline', 'ab', str(directory / 'trace')])
        for root in ('/home/lab/k10-control', '/home/lab/k09', '/home/lab/k11-extra', '/home/lab/k11/nested'):
            request = dict(self.request, executable=root + '/build-01/bin/kcov-sample-k08-ab',
                scenario_library=root + '/build-01/bin/regmap-k07-different-registers-per-role.so', plan_path=None)
            with self.subTest(root=root), self.assertRaises(guest.GuestError):
                self.load(request, directory / 'request.json', guest)
        self.assertIsNone(load_guest('k04').BUILD_ROOTS)
        self.assertEqual(load_guest('k09').BUILD_ROOTS,
                         {Path('/home/lab/k09'), Path('/home/lab/k10-control'), Path('/home/lab/k11')})

    def test_explicit_empty_build_roots_fail_closed(self):
        with patch.object(self.guest, 'BUILD_ROOTS', set()), self.assertRaises(self.guest.GuestError):
            self.load()


if __name__ == '__main__':
    unittest.main()

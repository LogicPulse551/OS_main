"""K10 control executors are a second exact build root, not arbitrary guests paths."""
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))

from kconc.manifest import ManifestError, normalize_manifest


class ControlBuildManifestTests(unittest.TestCase):
    def task(self, operation, build):
        task = dict(schema_version=1, operation=operation, runtime=dict(
            lab_dir='/home/xzf/os-concurrency-k10-control-rmw', ssh_port=2235,
            build_lab='/build', kernel_build='/kernel',
            scenario_guest_build='/home/lab/k03/build-01',
            sample_guest_build='/home/lab/k08/build-01', search_guest_build=build))
        if operation == 'kernel.check':
            task.update(inputs=dict(pool='/pool.json', source_mapper='/mapper'),
                        scenario=dict(family='rmw', max_candidates=1))
        else:
            task.update(inputs=dict(bundle='/bundle', source_mapper='/mapper'),
                        scenario=dict(repetitions=20))
        return task

    def test_original_and_control_roots_support_check_and_replay(self):
        for operation in ('kernel.check', 'replay.run'):
            for build in ('/home/lab/k09/build-01', '/home/lab/k10-control/build-01',
                          '/home/lab/k10-control/build-control_02.a'):
                with self.subTest(operation=operation, build=build):
                    result = normalize_manifest(self.task(operation, build), REPO)
                    self.assertEqual(result['runtime']['search_guest_build'], build)

    def test_requires_exact_parent_without_nested_builds(self):
        for operation in ('kernel.check', 'replay.run'):
            for build in ('/home/lab/k10/build-01', '/home/lab/k10-control-extra/build-01',
                          '/home/lab/k090/build-01', '/home/lab/k10-control/build-01/nested',
                          '/home/lab/k10-control/extra/build-01', '/tmp/k10-control/build-01'):
                with self.subTest(operation=operation, build=build):
                    with self.assertRaises(ManifestError):
                        normalize_manifest(self.task(operation, build), REPO)

    def test_requires_nonempty_build_name_and_safe_characters(self):
        for build in ('/home/lab/k10-control', '/home/lab/k10-control/build-',
                      '/home/lab/k10-control/other', '/home/lab/k10-control/build-a b',
                      '/home/lab/k10-control/build-a;id', '/home/lab/k10-control/build-$(id)'):
            with self.subTest(build=build), self.assertRaises(ManifestError):
                normalize_manifest(self.task('replay.run', build), REPO)

    def test_traversal_relative_and_invalid_values_stay_rejected(self):
        for build in ('/home/lab/k09/../k10-control/build-01',
                      '/home/lab/k10-control/build-01/../build-02',
                      'home/lab/k10-control/build-01', '', True, None,
                      '/home/lab/k10-control/build-01\x00'):
            with self.subTest(build=build), self.assertRaises(ManifestError):
                normalize_manifest(self.task('kernel.check', build), REPO)

    def test_control_root_does_not_relax_sampler_root(self):
        task = self.task('replay.run', '/home/lab/k10-control/build-01')
        task['runtime']['sample_guest_build'] = '/home/lab/k10-control/build-01'
        with self.assertRaises(ManifestError):
            normalize_manifest(task, REPO)


if __name__ == '__main__':
    unittest.main()

"""Synthetic K11 evidence boundaries; not substitutes for QEMU regression runs."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from kconc import candidates as c, search_queue as q


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = load('k11_test_analysis', REPO / 'adapters/maccconc/k11_analysis.py')
fixtures = load('k11_sample_fixtures', REPO / 'tests/k08/test_analysis.py')


def profile(family):
    """Test-only construction. Production entrypoints require verify_profile."""
    patch = REPO / f'patches/maccconc/0004-k11-{family}-repair.patch'
    original = REPO / ('kernel/k06/kconc-regmap.c' if family == 'rmw' else 'kernel/k07/kconc-regmap.c')
    driver = a.apply_file_patch(original.read_text(), patch.read_text(), 'drivers/base/regmap/kconc-regmap.c')
    identity = dict(profile_id=a.PROFILE_ID, family=family, kernel_record_sha256='a'*64,
                    native_record_sha256='b'*64, driver_sha256=a.sha(driver.encode()), repair_patch_sha256=a.sha(patch.read_bytes()))
    line = next(i for i, row in enumerate(driver.splitlines(), 1) if 'WRITE_ONCE(role->checkpoint, epoch);' in row)
    marker = dict(file='drivers/base/regmap/kconc-regmap.c', symbol='kconc_regmap_checkpoint', line=line, source_sha256=identity['driver_sha256'])
    return a.VerifiedProfile(identity, marker, a._SEAL)


class AnalysisTests(unittest.TestCase):
    def fixture(self, family='rmw', order='ab', case=None, mode=None):
        helper = fixtures.AnalysisTests()
        self.addCleanup(helper.doCleanups)
        f = helper.fixture(family, order, case, mode)
        f.profile = profile(family)
        f.mapping[f.ips[2]]['line'] = f.profile.marker['line']
        if family == 'rmw' and f.phases[0]['mode'] == 'split':
            for slot in ('A', 'B'):
                f.events[slot] = [f.events[slot][2], f.events[slot][0], f.events[slot][1], f.events[slot][3]]
        if family == 'mutex':
            for rows, final in [(f.phases[2]['results'], f.phases[3]['final']),
                                (f.phases[4]['post_control_progress']['operations'], f.phases[4]['post_control_progress']['final'])]:
                for row in rows:
                    row['result']['gate_id'] = 0
                for row in final['roles']:
                    row['gate_id'] = 0
        f.write()
        return f

    def sample(self, f):
        return a.analyze_sample(f.trace, f.mapping, f.guest, f.family, f.order, f.profile)

    def candidate(self, f):
        report = self.sample(f)
        self.assertTrue(report['passed'], report)
        entry = c.get_input(c.load_catalog(), f.family, f.phases[0]['case_id'], f.phases[0]['mode'])
        source = dict(trace_path=str(f.trace), analysis_sha256=c.fingerprint(report),
                      trace_sha256={name: report['artifacts'][name] for name in c.TRACE_FILES})
        f.candidate = c.make_candidate(entry, dict(repair_profile=f.profile.identity), c.observed_initial_state(report), report, source)
        return f.candidate

    def execute(self, f, violation=False):
        self.candidate(f)
        (f.trace / 'plan.txt').write_bytes(q.make_plan(f.candidate))
        f.meta.update(sequential_A_B=False, plan_loaded_from_file=True, sampling_only=False, k09_schema_version=1,
                      candidate_execution_requested=True, requested_candidate_executions=1,
                      candidate_pattern='A-B-A' if f.order == 'ab' else 'B-A-B')
        at = next(i for i, e in enumerate(f.events['A']) if e['ip'] == f.ips[2])
        f.events['A'][at:at] = [dict(kind=k, record_type=r, flagidx=b, timed_out=False, thread='A')
                              for k, r, b in [('WAKE', '0x5000000000000000', 0), ('WAIT', '0x4000000000000000', 1)]]
        first, peer = (0, 1) if f.order == 'ab' else (1, 0)
        entry = f.candidate['identity']['input']
        if f.family == 'rmw':
            values = list(entry['initial'])
            for role in (peer, first):
                op = entry['operations'][role]
                before = values[op['reg']]
                values = a.k06.oracle.apply_update(values, op)
                if entry['mode'] == 'split':
                    f.phases[2]['results'][role].update(before=before, after=values[op['reg']])
            if violation:
                values[0] = 0
            allowed = a.k06.oracle.evaluate(entry['initial'], entry['operations'], values)['allowed']
            f.phases[3].update(values=values, allowed=allowed, natural_passed=allowed)
            f.sync_slots()
        else:
            ops, final = fixtures.mutex_fixture.observed(entry['case_id'], 'shared', 'overlap' if violation else 'busy')
            if f.order == 'ba':
                ops.reverse(); final['roles'].reverse()
                for e in final['events'][:final['event_count']]:
                    e['role'] = 1-e['role']
                for role, row in enumerate(ops):
                    row.update(entry['operations'][role])
                    row['result']['reg'] = entry['operations'][role]['reg']
                    final['roles'][role] = copy.deepcopy(row['result'])
                final['values'] = [0, 0, 0, 0]
                for row in ops:
                    if row['result']['outcome'] == 1:
                        final['values'][row['reg']] |= row['value']
            mode = a.k07.oracle.MODES[entry['mode']]
            for row in ops:
                row['mode'] = row['result']['mode'] = mode
                final['roles'][row['role']]['mode'] = mode
            f.phases[2]['results'] = ops
            f.phases[3].update(final=final, allowed=not violation)
            if not violation:
                e = copy.deepcopy(f.events['B'][1]); ip = '0xffffffff81858999'
                f.mapping[ip] = dict(f.mapping[f.ips[0]], raw_ip=ip, lookup_ip=f'0x{int(ip,16)-1:016x}',
                                     file='/linux/drivers/base/regmap/kconc-regmap.c', symbol='kconc_operation', line=319)
                e['ip'] = ip; e['stack'][-1]['ip'] = ip; f.events['B'] = [e]
        f.write(True)
        return a.analyze_execution(f.trace, f.mapping, f.guest, f.candidate, f.profile)

    def test_all_28_fresh_samples_keep_original_inputs(self):
        for entry in c.load_catalog()['inputs']:
            for order in ('ab', 'ba'):
                with self.subTest(input=entry['input_id'], order=order):
                    f = self.fixture(entry['family'], order, entry['case_id'], entry['mode'])
                    candidate = self.candidate(f)
                    self.assertEqual(candidate['identity']['input'], entry)
                    self.assertEqual(candidate['identity']['support']['repair_profile_id'], a.PROFILE_ID)

    def test_all_28_repaired_schedules_hit_and_hold_property(self):
        for entry in c.load_catalog()['inputs']:
            for order in ('ab', 'ba'):
                with self.subTest(input=entry['input_id'], order=order):
                    r = self.execute(self.fixture(entry['family'], order, entry['case_id'], entry['mode']))
                    self.assertTrue(r['candidate_hit'], r)
                    self.assertTrue(r['property_evaluated'], r)
                    self.assertFalse(r['property_violation'], r)
                    self.assertTrue(r['cleanup_verified'], r)

    def test_property_failure_is_not_hidden_as_candidate_miss(self):
        for family, mode in [('rmw', 'split'), ('mutex', 'per-role')]:
            for order in ('ab', 'ba'):
                with self.subTest(family=family, order=order):
                    r = self.execute(self.fixture(family, order, mode=mode), violation=True)
                    self.assertTrue(r['candidate_hit'], r)
                    self.assertTrue(r['property_evaluated'], r)
                    self.assertTrue(r['property_violation'], r)

    def test_structural_mismatch_still_prevents_property_claim(self):
        f = self.fixture()
        self.execute(f)
        f.events['A'][2]['stack'][0]['parent_idx'] = 9
        f.write(True)
        r = a.analyze_execution(f.trace, f.mapping, f.guest, f.candidate, f.profile)
        self.assertFalse(r['candidate_hit'])
        self.assertFalse(r['property_evaluated'])

    def test_plain_caller_cannot_enable_repair_with_boolean(self):
        f = self.fixture()
        with self.assertRaises(ValueError):
            a.analyze_sample(f.trace, f.mapping, f.guest, f.family, f.order, {'verified': True})
        with self.assertRaises(ValueError):
            a.VerifiedProfile(f.profile.identity, f.profile.marker)

    def test_original_modes_keep_original_validation(self):
        f = self.fixture('mutex', mode='per-role')
        r = a.k08.analyze(f.trace, f.mapping, f.guest, f.family, f.order)
        self.assertFalse(r['passed'])
        f = self.fixture('rmw', mode='split')
        self.assertFalse(a.k08.analyze(f.trace, f.mapping, f.guest, f.family, f.order)['passed'])

    def test_new_candidate_cannot_use_other_build_or_driver(self):
        f = self.fixture()
        self.execute(f)
        f.candidate['identity']['build_identity']['repair_profile']['kernel_record_sha256'] = 'e'*64
        f.candidate['candidate_id'] = c.fingerprint(f.candidate['identity'])
        r = a.analyze_execution(f.trace, f.mapping, f.guest, f.candidate, f.profile)
        self.assertFalse(r['candidate_hit'])
        self.assertFalse(r['property_evaluated'])
        f.candidate['identity']['build_identity']['repair_profile']['driver_sha256'] = 'e'*64
        f.candidate['candidate_id'] = c.fingerprint(f.candidate['identity'])
        with self.assertRaises(ValueError):
            c.validate_candidate(f.candidate)


class PatchTests(unittest.TestCase):
    def test_real_multifile_patches_stop_before_new_kunit_header(self):
        for family in ('rmw', 'mutex'):
            p = profile(family)
            self.assertGreater(p.marker['line'], 0)
            original = REPO / ('kernel/k06/kconc-regmap.c' if family == 'rmw' else 'kernel/k07/kconc-regmap.c')
            patch = (REPO / f'patches/maccconc/0004-k11-{family}-repair.patch').read_text()
            output = a.apply_file_patch(original.read_text(), patch, 'drivers/base/regmap/kconc-regmap.c')
            self.assertNotIn('+++ b/', output)
            self.assertIn('kconc-regmap-kunit.h', output)

    def test_native_patch_keeps_requested_mode_and_requires_macro(self):
        original = (REPO / a.TEAM_FILES['regmap-k07-cases.h']).read_text()
        output = a.apply_file_patch(original, (REPO / a.TEAM_FILES['k11-shared-gate-native.patch']).read_text(), 'regmap-k07-cases.h')
        self.assertIn('r->gate_id==0', output)
        self.assertIn('r->mode==mode', output)
        self.assertIn('#error', output)
        self.assertIn('r->gate_id==(mode?role+1:0)', original)

    def test_patch_context_and_counts_fail_closed(self):
        original = 'one\ntwo\n'
        patch = '--- a/file\n+++ b/file\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n'
        self.assertEqual(a.apply_file_patch(original, patch, 'file'), 'one\nthree\n')
        with self.assertRaises(ValueError):
            a.apply_file_patch('wrong\ntwo\n', patch, 'file')
        with self.assertRaises(ValueError):
            a.apply_file_patch(original, patch.replace('-1,2', '-1,3'), 'file')


def native_fixture():
    """Self-contained synthetic file hashes, never a real native build claim."""
    names = a._binary_names()
    current = {name: a.sha(('new-' + name).encode()) for name in names}
    mutex = {name for name in names if name.startswith('regmap-k07-')}
    inputs = dict(native_compile_defines=['KCONC_K11_SHARED_GATE=1'],
                  sampler_control_policy_id=a.SAMPLER_POLICY_ID,
                  team_files=[dict(build_copy=name, sha256=a.sha((REPO / path).read_bytes())) for name, path in a.TEAM_FILES.items()],
                  build_script_sha256=a.sha((REPO / 'scripts/build-k11-guest.sh').read_bytes()))
    parentfacts = {}
    for key, (rh, mh, kind, task) in a.PINNED.items():
        parent_names = {name for name in names if name.endswith('.so') or ('sample' if key == 'k08' else 'execute') in name}
        hashes = {name: a.sha(('old-' + name).encode()) if name in mutex or name.startswith('kcov-sample-') else current[name] for name in parent_names}
        record = dict(kind=kind, task=task, passed=True, binaries=[dict(name=name, sha256=value) for name, value in sorted(hashes.items())])
        source_hashes = {'synthetic.cpp': '1'*64, 'runner-common.h': ('2' if key == 'k08' else '3')*64}
        sources = [dict(path=name, sha256=value) for name, value in source_hashes.items()]
        inputs['accepted_' + key] = dict(path='/synthetic/' + key, result_sha256=rh, effective_manifest_sha256=mh,
                                         record=record, effective_sources=sources)
        parentfacts[key] = dict(result_sha256=rh, effective_manifest_sha256=mh, binaries=hashes, source_hashes=source_hashes)
    inputs['copied_binaries'] = [dict(name=name, accepted_build='k10', sha256=current[name])
                                 for name in sorted(names - mutex) if not name.startswith('kcov-sample-')]
    current['kcov-sample-k08-ba'] = current['kcov-sample-k08-ab']
    source_hashes = {'synthetic.cpp': '1'*64, 'runner-common.h': '3'*64}
    for name, path in a.TEAM_FILES.items():
        data = (REPO / path).read_bytes()
        if name == 'regmap-k07-cases.h':
            data = a.apply_file_patch(data.decode(), (REPO / a.TEAM_FILES['k11-shared-gate-native.patch']).read_text(), name).encode()
        source_hashes[name] = a.sha(data)
    manifest = [dict(path=name, sha256=value) for name, value in sorted(source_hashes.items())]
    record = dict(kind='kconc.regression-native.build', task='K11', profile_id=a.PROFILE_ID, passed=True, exit_code=0,
                  inputs=inputs, binaries=[dict(name=name, sha256=value) for name, value in sorted(current.items())],
                  scenario_recompiled=sorted(mutex), accepted_inputs_modified=False, executor_recompiled=False, sampler_recompiled=True)
    return record, current, manifest, source_hashes, parentfacts


class BindingTests(unittest.TestCase):
    def test_old_sampler_binary_and_unfixed_runner_are_rejected(self):
        values = list(native_fixture())
        old = a._hash_rows(values[0]['inputs']['accepted_k08']['record']['binaries'])
        for name in ('kcov-sample-k08-ab', 'kcov-sample-k08-ba'):
            values[1][name] = old['kcov-sample-k08-ab']
            next(row for row in values[0]['binaries'] if row['name'] == name)['sha256'] = old['kcov-sample-k08-ab']
        with self.assertRaises(ValueError):
            a.verify_native(*values)
        values = list(native_fixture())
        original_runner = a._hash_rows(values[0]['inputs']['accepted_k08']['effective_sources'], 'path')['runner-common.h']
        values[3]['runner-common.h'] = original_runner
        next(row for row in values[2] if row['path'] == 'runner-common.h')['sha256'] = original_runner
        with self.assertRaises(ValueError):
            a.verify_native(*values)

    def test_sampler_recompile_and_control_policy_are_required(self):
        for damage in ('copied', 'policy'):
            values = list(native_fixture())
            if damage == 'copied': values[0]['sampler_recompiled'] = False
            else: values[0]['inputs']['sampler_control_policy_id'] = 'unverified'
            with self.assertRaises(ValueError):
                a.verify_native(*values)

    def test_native_identity_requires_actual_sources_and_both_parents(self):
        values = native_fixture()
        self.assertTrue(a.verify_native(*values)['passed'])
        for part, key in [(1, 'kcov-execute-k09-ab'), (3, 'regmap-k07-cases.h')]:
            bad = copy.deepcopy(values)
            bad[part][key] = '0'*64
            with self.assertRaises(ValueError):
                a.verify_native(*bad)
        bad = copy.deepcopy(values)
        bad[4]['k10']['result_sha256'] = '0'*64
        with self.assertRaises(ValueError):
            a.verify_native(*bad)

    def test_native_macro_unknown_profile_or_missing_binary_rejected(self):
        for damage in ('macro', 'profile', 'binary', 'scenario'):
            bad = list(native_fixture())
            if damage == 'macro': bad[0]['inputs']['native_compile_defines'] = []
            if damage == 'profile': bad[0]['profile_id'] = 'anything'
            if damage == 'binary': bad[0]['binaries'].pop()
            if damage == 'scenario': bad[0]['scenario_recompiled'] = []
            with self.assertRaises(ValueError):
                a.verify_native(*bad)

    def binding(self, family):
        temp = tempfile.TemporaryDirectory(prefix='k11-profile-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        patch_name = f'patches/maccconc/0004-k11-{family}-repair.patch'
        patch_hash = a.sha((REPO / patch_name).read_bytes())
        original = REPO / ('kernel/k06/kconc-regmap.c' if family == 'rmw' else 'kernel/k07/kconc-regmap.c')
        driver = a.apply_file_patch(original.read_text(), (REPO / patch_name).read_text(), 'drivers/base/regmap/kconc-regmap.c').encode()
        built_path = '/synthetic/linux/drivers/base/regmap/kconc-regmap.c'
        kernel = dict(kind='kconc.repaired-kernel.build', task='K11', profile_id=a.PROFILE_ID, passed=True, family=family,
                      repair_patch=dict(path=patch_name, sha256=patch_hash),
                      repaired_driver=dict(path=built_path, sha256=a.sha(driver)),
                      regmap_sources=[dict(path=built_path, sha256=a.sha(driver))],
                      team_inputs=[dict(path=patch_name, sha256=patch_hash)])
        native = native_fixture()[0]
        binding = dict(profile_id=a.PROFILE_ID, family=family)
        for key, data in [('kernel_record', json.dumps(kernel).encode()), ('native_record', json.dumps(native).encode()), ('repaired_driver', driver)]:
            path = root / key
            path.write_bytes(data)
            binding[key] = dict(path=str(path), sha256=a.sha(data))
        return binding

    def test_archived_profile_reconstructs_driver_from_registered_patch(self):
        for family in ('rmw', 'mutex'):
            binding = self.binding(family)
            verified = a.verify_profile(binding)
            self.assertEqual(verified.identity, profile(family).identity | dict(
                kernel_record_sha256=binding['kernel_record']['sha256'], native_record_sha256=binding['native_record']['sha256']))

    def test_self_assertion_changed_bytes_and_relabelled_family_rejected(self):
        with self.assertRaises(ValueError):
            a.verify_profile(dict(verified=True, profile_id=a.PROFILE_ID))
        binding = self.binding('rmw')
        Path(binding['repaired_driver']['path']).write_text('wrong source\n')
        with self.assertRaises(ValueError):
            a.verify_profile(binding)
        binding['repaired_driver']['sha256'] = a.sha(b'wrong source\n')
        with self.assertRaises(ValueError):
            a.verify_profile(binding)
        binding = self.binding('rmw')
        binding['family'] = 'mutex'
        with self.assertRaises(ValueError):
            a.verify_profile(binding)


if __name__ == '__main__':
    unittest.main()

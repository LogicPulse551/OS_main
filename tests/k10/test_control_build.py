"""Reject a repaired controller that loses its original build provenance."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from kconc.control_build import native_checks


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.parent_hashes={f'scenario-{i}.so':f'{i:064x}' for i in range(14)}
        self.parent_hashes.update({'kcov-execute-k09-ab':'a'*64,'kcov-execute-k09-ba':'a'*64})
        self.parent=dict(inputs=dict(accepted_k08={'record':'original sampler'},copied_scenarios=[{'source':'original SO'}]))
        sources=[dict(path='runner-common.h',sha256='b'*64),dict(path='k10-control.patch',sha256='c'*64)]
        hashes=dict(self.parent_hashes,**{'kcov-execute-k09-ab':'d'*64,'kcov-execute-k09-ba':'d'*64})
        self.observed=dict(current_hashes=hashes,parent_result_sha256='e'*64,parent_manifest_sha256='f'*64,
            parent_sources=[dict(path='runner-common.h',sha256='1'*64)],parent_sources_intact=True,
            sources=sources,source_hashes={r['path']:r['sha256'] for r in sources},manifest_sha256='2'*64)
        origin=dict(record=copy.deepcopy(self.parent),result_sha256='e'*64,effective_manifest_sha256='f'*64,
                    effective_sources=copy.deepcopy(self.observed['parent_sources']))
        self.record=dict(passed=True,task='K10',kind='kconc.executor.control-build',
            inputs=dict(copy.deepcopy(self.parent['inputs']),accepted_k09=origin,control_patch_sha256='c'*64,build_script_sha256='3'*64),
            binaries=[dict(name=n,sha256=h) for n,h in hashes.items()],effective_manifest_sha256='2'*64)

    def checks(self):return native_checks(self.record,self.observed,self.parent,self.parent_hashes,'c'*64,'3'*64)
    def test_separate_executor_with_exact_original_scenarios_is_accepted(self):
        self.assertTrue(all(self.checks().values()))
    def test_forged_original_record_rejected(self):
        self.record['inputs']['accepted_k09']['record']['extra']='different'
        self.assertFalse(self.checks()['control_parent_record'])
    def test_changed_parent_sources_rejected(self):
        self.observed['parent_sources_intact']=False
        self.assertFalse(self.checks()['control_parent_sources_intact'])
    def test_changed_copied_scenario_rejected_even_if_new_record_agrees(self):
        self.observed['current_hashes']['scenario-0.so']='4'*64
        self.record['binaries'][0]['sha256']='4'*64
        self.assertFalse(self.checks()['control_original_scenario_bytes'])
    def test_changed_sampler_bridge_rejected(self):
        self.record['inputs']['accepted_k08']={'record':'different sampler'}
        self.assertFalse(self.checks()['control_original_sampler_bridge'])
    def test_different_executor_alias_bytes_rejected(self):
        self.observed['current_hashes']['kcov-execute-k09-ba']='4'*64
        self.assertFalse(self.checks()['control_executor_aliases'])
    def test_wrong_patch_or_script_rejected(self):
        self.record['inputs']['control_patch_sha256']='4'*64
        self.record['inputs']['build_script_sha256']='4'*64
        self.assertFalse(self.checks()['control_patch']);self.assertFalse(self.checks()['control_build_script'])
    def test_missing_effective_source_rejected(self):
        del self.observed['source_hashes']['runner-common.h']
        self.assertFalse(self.checks()['control_effective_sources'])
    def test_failed_build_rejected(self):
        self.record['passed']=False
        self.assertFalse(self.checks()['control_build_passed'])
    def test_duplicate_binary_manifest_rejected(self):
        self.record['binaries'].append(dict(self.record['binaries'][0]))
        self.assertFalse(self.checks()['control_expected_binary_set'])
    def test_parent_record_and_manifest_hashes_are_bound(self):
        self.observed['parent_result_sha256']='4'*64;self.observed['parent_manifest_sha256']='5'*64
        self.assertFalse(self.checks()['control_parent_record_hash']);self.assertFalse(self.checks()['control_parent_manifest_hash'])


if __name__=='__main__':unittest.main()

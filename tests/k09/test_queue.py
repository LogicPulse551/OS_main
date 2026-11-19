"""K09 import/budget/attempt contracts; synthetic traces are not kernel evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from kconc import candidates as c, search_queue as q


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


k08 = load('queue_k08_candidate_fixtures', REPO/'tests/k08/test_candidates.py')
k03 = load('queue_k03_plan_reader', REPO/'adapters/maccconc/k03_analysis.py')


def identity():
    names = ['kcov-sample-k08-ab', 'kcov-sample-k08-ba'] + [x['native_so'] for x in c.load_catalog()['inputs']]
    return dict(kernel_and_k03={'kernel_image':'1'*64, 'vmlinux':'2'*64},
        binaries={name:hashlib.sha256(name.encode()).hexdigest() for name in names},
        inputs={'synthetic_accepted_input':True}, catalog_sha256=q._sha(c.CATALOG))


def runtime(old):
    result = dict(passed=True, kind='kconc.sampler.build', task='K08', inputs=copy.deepcopy(old['inputs']),
        binaries=[dict(name=k, sha256=v) for k, v in old['binaries'].items()])
    return dict(kernel_and_k03=copy.deepcopy(old['kernel_and_k03']), catalog_sha256=old['catalog_sha256'],
        inputs={'accepted_k08':{'record':result}},
        binaries={**{k:v for k,v in old['binaries'].items() if k.endswith('.so')},
                  'kcov-execute-k09-ab':'3'*64, 'kcov-execute-k09-ba':'3'*64})


def candidate(family='rmw', case='disjoint-bits', mode='split', order='ab'):
    args = k08.fixture(family, case, mode, order);args[1] = identity()
    return c.make_candidate(*args)


class QueueTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='k09-queue-');self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.a = candidate();self.b = candidate(order='ba')
        self.other = candidate('mutex', 'shared-register', 'shared', 'ba')
        self.rt = runtime(self.a['identity']['build_identity'])

    def pool(self, rows=None):
        path = self.base/(uuid.uuid4().hex + '.json')
        return c.export_candidates(path, [self.a, self.b, self.other] if rows is None else rows)

    def queue(self, budget=2):
        return q.make_queue(self.pool(), 'rmw', budget, self.rt)

    def test_pool_summary_recomputed_not_trusted(self):
        pool = self.pool()
        self.assertIs(q.validate_pool(pool), pool)
        for key, value in [('source_records',4), ('executed_candidates',1), ('complete_search',True),
                           ('observed_baselines',True), ('unobserved_branches','none')]:
            with self.subTest(field=key):
                changed = copy.deepcopy(pool);changed['summary'][key] = value
                with self.assertRaises(ValueError):q.validate_pool(changed)

    def test_catalog_hash_and_full_identity_corruption_rejected(self):
        pool = self.pool()
        for mutate in [lambda p:p.update(catalog_sha256='f'*64),
                       lambda p:p['catalog'].update(orders=['ab']),
                       lambda p:p['candidates'][0].update(candidate_id='f'*64),
                       lambda p:p['candidates'][0]['identity']['input'].update(mode='bad'),
                       lambda p:p.update(schema_version=True),
                       lambda p:p.update(extra='unrecognized')]:
            changed=copy.deepcopy(pool);mutate(changed)
            with self.assertRaises(ValueError):q.validate_pool(changed)

    def test_source_records_preserved_and_duplicate_identity_rows_rejected(self):
        pool = self.pool([self.a, self.a, self.b])
        q.validate_pool(pool)
        self.assertEqual(len(pool['candidates']),2)
        self.assertEqual(len(pool['candidates'][0]['sources']),2)
        duplicate=copy.deepcopy(pool);duplicate['candidates'].append(copy.deepcopy(duplicate['candidates'][0]))
        with self.assertRaises(ValueError):q.validate_pool(duplicate)

    def test_different_actual_prefix_retains_separate_queue_entry(self):
        args=k08.fixture();args[1]=identity()
        args[3]['observations']['observed_prefix']['events'][1]['timestamp']='0x0000000000000033'
        changed=c.make_candidate(*args)
        pool=self.pool([self.a,changed]);ledger=q.make_queue(pool,'rmw',2,self.rt)
        self.assertEqual(len(ledger['candidates']),2)
        self.assertNotEqual(ledger['candidates'][0]['candidate_id'],ledger['candidates'][1]['candidate_id'])

    def test_all_28_plans_use_original_stack_and_physical_slot(self):
        for entry in c.load_catalog()['inputs']:
            for order in ('ab','ba'):
                row=candidate(entry['family'],entry['case_id'],entry['mode'],order)
                content=q.make_plan(row);path=self.base/(uuid.uuid4().hex+'.plan');path.write_bytes(content)
                parsed=k03.read_plan(path)
                self.assertEqual(parsed['stack'],row['identity']['target']['event']['stack'])
                self.assertIn(b'role A\n',content)
                self.assertIn(b'spin_limit 1000000\n',content)
                self.assertEqual(row['identity']['target']['logical_role'],order[0].upper())

    def test_plan_invalid_spin_or_candidate_rejected(self):
        for spin in [0,-1,True,1.0,1000000001]:
            with self.assertRaises(ValueError):q.make_plan(self.a,spin)
        broken=copy.deepcopy(self.a);broken['identity']['target']['event']['stack'][0]['ip']='0x1234'
        with self.assertRaises(ValueError):q.make_plan(broken)

    def test_new_executor_is_explicit_bridge_not_equal_old_sampler(self):
        support=q.eligibility(self.a,self.rt)
        self.assertTrue(support['supported'],support)
        self.assertNotIn('kcov-sample-k08-ab',self.rt['binaries'])
        self.assertTrue(support['checks']['old_k08_binaries_exact'])

    def test_kernel_old_sampler_inputs_and_any_reused_so_mismatch_unsupported(self):
        changes=[lambda r:r['kernel_and_k03'].update(vmlinux='f'*64),
            lambda r:r.update(catalog_sha256='f'*64),
            lambda r:r['inputs']['accepted_k08']['record']['inputs'].update(extra=True),
            lambda r:r['inputs']['accepted_k08']['record']['binaries'][0].update(sha256='f'*64),
            lambda r:r['inputs']['accepted_k08']['record'].update(passed=False),
            lambda r:r['binaries'].update({'regmap-k07-shared-register-shared.so':'f'*64})]
        for mutate in changes:
            changed=copy.deepcopy(self.rt);mutate(changed)
            support=q.eligibility(self.a,changed)
            self.assertFalse(support['supported'])
            self.assertTrue(support['failed_checks'])
            self.assertTrue(support['reason'].startswith('incompatible:'))

    def test_scope_exclusion_distinct_from_unsupported_and_budget(self):
        ledger=self.queue(budget=1)
        self.assertEqual([x['status'] for x in ledger['candidates']],['pending','budget-unexplored','scope-excluded'])
        summary=q.summarize(ledger)
        self.assertEqual(summary['candidate_status']['unsupported'],0)
        self.assertEqual(summary['in_scope_candidates'],2)
        self.assertEqual(summary['attempts'],0)

    def test_incompatible_candidate_unsupported_not_counted_in_attempt_budget(self):
        bad=copy.deepcopy(self.a);bad['identity']['build_identity']['kernel_and_k03']['vmlinux']='f'*64
        bad['candidate_id']=c.fingerprint(bad['identity'])
        ledger=q.make_queue(self.pool([bad,self.b]),'rmw',1,self.rt)
        self.assertEqual([x['status'] for x in ledger['candidates']],['unsupported','pending'])

    def test_zero_budget_and_bad_budget(self):
        ledger=self.queue(0)
        q.finalize(ledger)
        self.assertEqual(ledger['summary']['candidate_status']['budget-unexplored'],2)
        for budget in [-1,True,1.0,4097]:
            with self.assertRaises(ValueError):self.queue(budget)

    def test_frozen_fifo_rejects_skip_and_parallel_attempt(self):
        ledger=self.queue()
        with self.assertRaises(ValueError):q.begin_attempt(ledger,self.b['candidate_id'],'second')
        a=q.begin_attempt(ledger,self.a['candidate_id'],'first')
        self.assertEqual(a['ordinal'],1)
        with self.assertRaises(ValueError):q.begin_attempt(ledger,self.b['candidate_id'],'second')

    def test_completed_attempt_is_preserved_and_cannot_be_overwritten_or_retried(self):
        ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'first')
        q.finish_attempt(ledger,'first','miss',guest_started=True,cleanup_confirmed=True)
        before=copy.deepcopy(ledger['attempts'])
        with self.assertRaises(ValueError):q.finish_attempt(ledger,'first','hit',guest_started=True,cleanup_confirmed=True)
        with self.assertRaises(ValueError):q.begin_attempt(ledger,self.a['candidate_id'],'retry')
        self.assertEqual(ledger['attempts'],before)

    def test_property_failure_and_control_failure_are_separate(self):
        ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'first')
        q.finish_attempt(ledger,'first','hit',guest_started=True,cleanup_confirmed=True,
            property_evaluated=True,property_violation=True,evidence={'analysis':'first/analysis.json'})
        q.begin_attempt(ledger,self.b['candidate_id'],'second')
        q.finish_attempt(ledger,'second','miss',guest_started=True,cleanup_confirmed=True)
        result=q.finalize(ledger)['summary']
        self.assertEqual(result['attempts'],2)
        self.assertEqual(result['property_evaluated'],1)
        self.assertEqual(result['property_violations'],1)
        self.assertEqual(result['attempt_outcomes']['hit'],1)
        self.assertEqual(result['attempt_outcomes']['miss'],1)
        self.assertFalse(result['complete_search']);self.assertFalse(result['coverage_claimed'])

    def test_invalid_and_timeout_are_kept_in_attempt_denominator(self):
        ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'one')
        q.finish_attempt(ledger,'one','timeout',guest_started=True,cleanup_confirmed=False)
        q.begin_attempt(ledger,self.b['candidate_id'],'two')
        q.finish_attempt(ledger,'two','invalid',guest_started=True,cleanup_confirmed=True)
        s=q.finalize(ledger)['summary']
        self.assertEqual(s['attempts'],2);self.assertEqual(s['attempt_outcomes']['timeout'],1)
        self.assertEqual(s['attempt_outcomes']['invalid'],1);self.assertEqual(s['cleanup_unconfirmed'],1)

    def test_launch_failure_retained_as_infrastructure_not_miss(self):
        ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'one')
        with self.assertRaises(ValueError):q.finish_attempt(ledger,'one','miss',guest_started=False,cleanup_confirmed=True)
        q.finish_attempt(ledger,'one','infrastructure-error',guest_started=False,cleanup_confirmed=False)
        q.finalize(ledger,'runtime requires recovery')
        self.assertEqual(ledger['summary']['attempts'],1)
        self.assertEqual(ledger['summary']['guest_started'],0)
        self.assertEqual(ledger['candidates'][1]['status'],'unattempted-interrupted')

    def test_nonmatching_or_unclean_execution_cannot_claim_property_hit(self):
        ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'one')
        for kwargs in [dict(outcome='hit',guest_started=True,cleanup_confirmed=False),
            dict(outcome='miss',guest_started=True,cleanup_confirmed=True,property_evaluated=True,property_violation=False),
            dict(outcome='hit',guest_started=True,cleanup_confirmed=True,property_evaluated=False,property_violation=False),
            dict(outcome='hit',guest_started=1,cleanup_confirmed=True)]:
            with self.assertRaises(ValueError):q.finish_attempt(ledger,'one',**kwargs)
        self.assertEqual(ledger['attempts'][0]['outcome'],'running')

    def test_finalize_never_masks_pending_or_running(self):
        ledger=self.queue()
        with self.assertRaises(ValueError):q.finalize(ledger)
        q.begin_attempt(ledger,self.a['candidate_id'],'one')
        with self.assertRaises(ValueError):q.finalize(ledger,'stop')
        q.finish_attempt(ledger,'one','invalid',guest_started=True,cleanup_confirmed=False)
        q.finalize(ledger,'stop')
        with self.assertRaises(ValueError):q.begin_attempt(ledger,self.b['candidate_id'],'two')
        with self.assertRaises(ValueError):q.finalize(ledger)

    def test_queue_creation_does_not_mutate_source_pool(self):
        pool=self.pool();before=copy.deepcopy(pool)
        ledger=q.make_queue(pool,'rmw',1,self.rt)
        q.begin_attempt(ledger,self.a['candidate_id'],'one')
        q.finish_attempt(ledger,'one','hit',guest_started=True,cleanup_confirmed=True)
        q.finalize(ledger)
        self.assertEqual(pool,before)


class ImportIntegrationTests(unittest.TestCase):
    def setUp(self):
        fixtures=load('queue_archive_fixtures',REPO/'tests/k08/test_runtime.py')
        self.helper=fixtures.ExportIntegrationTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.base=self.helper.base

    def archive(self, family='rmw', case='disjoint-bits', mode='split', order='ab'):
        return self.helper.archived_sample(c.get_input(c.load_catalog(),family,case,mode),order)

    def pool_path(self, rows):
        path=self.base/(uuid.uuid4().hex+'.pool.json');c.export_candidates(path,rows);return path

    def test_all_28_sources_revalidated_readonly_with_duplicate_provenance(self):
        rows=[];roots=[]
        for entry in c.load_catalog()['inputs']:
            for order in ('ab','ba'):
                root,row=self.helper.archived_sample(entry,order);roots.append(root);rows.append(row)
        path=self.pool_path(rows+[rows[0]])
        before={str(p):q._sha(p) for root in roots for p in root.rglob('*') if p.is_file()}
        with patch('kconc.sampling.SampleRuntime',side_effect=AssertionError('Import must not create a VM')):
            pool=q.load_pool(path)
            result=q.revalidate_sources(pool)
        self.assertTrue(result['passed']);self.assertEqual(result['source_records'],29)
        self.assertEqual(result['distinct_source_records'],28)
        self.assertFalse(result['candidate_executed']);self.assertFalse(result['current_vm_checked'])
        self.assertEqual(before,{str(p):q._sha(p) for root in roots for p in root.rglob('*') if p.is_file()})

    def test_changed_raw_file_rejected_before_candidate_execution(self):
        root,row=self.archive();path=self.pool_path([row])
        (root/'guest/trace/baseline/A.words').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'Source trace bytes changed'):q.load_pool(path)

    def test_missing_or_changed_provenance_binding_rejected(self):
        root,row=self.archive();row['sources'][0].pop('guest_sha256');path=self.pool_path([row])
        with self.assertRaisesRegex(ValueError,'Source binding changed'):q.load_pool(path)

    def test_changed_candidate_file_does_not_become_supported_input(self):
        root,row=self.archive();path=self.pool_path([row])
        candidate_file=root/'candidate.json';data=json.loads(candidate_file.read_text());data['summary']['executed_candidates']=99
        candidate_file.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Source candidate file differs'):q.load_pool(path)

    def test_missing_raw_archives_can_only_use_explicit_format_only_mode(self):
        row=candidate();path=self.pool_path([row])
        self.assertEqual(q.load_pool(path,verify_sources=False)['candidates'][0]['candidate_id'],row['candidate_id'])
        with self.assertRaises(ValueError):q.load_pool(path)

    def test_forged_summary_rejected_before_opening_any_archive(self):
        row=candidate();path=self.pool_path([row]);value=json.loads(path.read_text());value['summary']['unique_candidates']=2
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'Pool summary'):q.load_pool(path)


if __name__ == '__main__':
    unittest.main()

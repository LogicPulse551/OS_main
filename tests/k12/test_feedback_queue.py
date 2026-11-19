"""Finite scheduling checks using synthetic accesses, never kernel evidence."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from kconc import candidates as c, feedback_queue as q

spec = importlib.util.spec_from_file_location('k12_candidate_fixtures', REPO/'tests/k08/test_candidates.py')
fixtures = importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)


def sample(*, order='ab', mode='split', case='disjoint-bits', variant=0, line=70):
    args = fixtures.fixture(case=case, mode=mode, order=order)
    args[3]['observations']['observed_prefix']['events'][1]['timestamp'] = f'0x{variant+1:016x}'
    candidate = c.make_candidate(*args)
    analysis = copy.deepcopy(args[3]);obs = analysis['observations'];obs['target'] = candidate['identity']['target']
    def row(slot, address, access, at):
        return dict(physical_slot=slot, logical_role=slot, event=dict(thread=slot, kind='MEMORY',
            address=f'0x{address:016x}', size=4, flags=272 if access=='write' else 256,
            word_index=at, value='0x0000000000000000', timestamp='0x0000000000000001'),
            source=dict(found=True, file='/source/drivers/base/regmap/regmap.c', line=line,
                symbol='real_regmap_access'))
    obs['projection'] = dict(zip(order.upper(),([row('A', 4096, 'read', 10)],[row('B', 4098, 'write', 15)])))
    return candidate, analysis


def pool(rows):
    catalog = c.load_catalog();expected={(e['input_id'],o) for e in catalog['inputs'] for o in catalog['orders']}
    merged = c.merge_candidates(rows);observed={(r['identity']['input']['input_id'],r['identity']['baseline_order']) for r in merged}
    return dict(schema_version=1, kind='kconc.candidate-pool', catalog=catalog,
        catalog_sha256=c.fingerprint(catalog), candidates=merged,
        summary=dict(expected_baselines=len(expected), observed_baselines=len(observed),
            unobserved_baselines=[dict(input_id=i,order=o) for i,o in sorted(expected-observed)],
            unique_candidates=len(merged), source_records=sum(len(r['sources']) for r in merged),
            executed_candidates=0,unobserved_branches='unknown',interleavings_covered=None,complete_search=False))


def as_execution(candidate, sample_analysis):
    actual = copy.deepcopy(sample_analysis)
    actual.update(candidate_id=candidate['candidate_id'],classification='hit',candidate_hit=True,
        execution_valid=True,control_valid=True,target_matches=True,prefix_matches=True,
        schedule_valid=True,cleanup_verified=True,property_evaluated=True,recovery_required=False)
    observed = actual['observations'].pop('projection')
    projection = {physical:observed[logical] for physical,logical in actual['observations']['slot_to_role'].items()}
    actual['observations'].pop('target',None);actual['observations'].pop('observed_prefix',None)
    return q.feature(candidate,actual,projection=projection)


def history(candidate, ident='old', outcome='hit', **extra):
    hit = outcome=='hit'
    _,analysis=sample(order=candidate['identity']['baseline_order'])
    observed=as_execution(candidate,analysis) if hit else None
    return dict(candidate_id=candidate['candidate_id'],attempt_id=ident,outcome=outcome,
        candidate_hit=hit,guest_started=True,cleanup_confirmed=True,property_evaluated=hit,
        property_violation=False if hit else None,recovery_required=False,observed_feature=observed,**extra)


class FeatureTests(unittest.TestCase):
    def test_overlap_requires_shared_bytes_and_a_write(self):
        candidate,analysis=sample();record=q.feature(candidate,analysis)
        self.assertEqual(len(record['pairs']),1)
        pair=record['pairs'][0]
        self.assertEqual(pair['identity']['first']['access'],'read')
        self.assertEqual(pair['identity']['peer']['access'],'write')
        self.assertEqual(pair['witness']['overlapping_address'],'0x1002')
        analysis['observations']['projection']['B'][0]['event']['address']='0x0000000000001004'
        self.assertEqual(q.feature(candidate,analysis)['pairs'],[])
        analysis['observations']['projection']['B'][0]['event'].update(address='0x0000000000001002',flags=256)
        self.assertEqual(q.feature(candidate,analysis)['pairs'],[])

    def test_values_timestamps_and_addresses_do_not_establish_order_or_reads_from(self):
        candidate,analysis=sample();before=q.feature(candidate,analysis)
        for rows in analysis['observations']['projection'].values():
            for row in rows:
                row['event']['value']='0xffffffffffffffff';row['event']['timestamp']='0xffffffffffffffff'
                row['event']['address']=f"0x{int(row['event']['address'],16)+8192:016x}"
        after=q.feature(candidate,analysis)
        self.assertEqual(before['pairs'][0]['pair_id'],after['pairs'][0]['pair_id'])
        self.assertFalse(after['global_order_inferred']);self.assertFalse(after['reads_from_inferred'])
        self.assertEqual(after['unobserved_conflicts'],'unknown')

    def test_non_regmap_noise_excluded_and_occurrences_preserved(self):
        candidate,analysis=sample();rows=analysis['observations']['projection']
        rows['A'].append(copy.deepcopy(rows['A'][0]));rows['A'].append(copy.deepcopy(rows['A'][0]))
        rows['A'][-1]['source']['file']='/source/kernel/random.c'
        record=q.feature(candidate,analysis)
        self.assertEqual(record['pairs'][0]['observations'],2)
        self.assertEqual(record['regmap_accesses'],dict(A=2,B=1))

    def test_rejects_unverified_or_mismatched_analysis(self):
        candidate,analysis=sample()
        for change in (lambda a:a.update(passed=False),lambda a:a.update(errors=['failure']),
                lambda a:a['observations'].update(order='ba'),lambda a:a['observations']['target'].update(access_index=9)):
            altered=copy.deepcopy(analysis);change(altered)
            with self.assertRaises(ValueError):q.feature(candidate,altered)

    def test_direction_and_build_have_separate_feature_namespaces(self):
        a,aa=sample();b,ab=sample(order='ba')
        self.assertNotEqual(q.feature(a,aa)['pairs'][0]['pair_id'],q.feature(b,ab)['pairs'][0]['pair_id'])

    def test_function_only_source_is_unknown_and_never_gets_a_guessed_line(self):
        candidate,analysis=sample();analysis['observations']['projection']['B'][0]['source']['line']=0
        result=q.feature(candidate,analysis)
        self.assertEqual(result['pairs'],[])
        self.assertEqual(result['unmapped_regmap_accesses'],dict(A=0,B=1))
        self.assertEqual(result['unobserved_conflicts'],'unknown')

    def test_ba_sample_reindexes_logical_projection_to_real_physical_slots(self):
        candidate,analysis=sample(order='ba')
        self.assertEqual(analysis['observations']['projection']['B'][0]['event']['thread'],'A')
        result=q.feature(candidate,analysis)
        self.assertEqual(result['pairs'][0]['identity']['first']['access'],'read')
        self.assertEqual(result['pairs'][0]['identity']['peer']['access'],'write')
        analysis['observations']['slot_to_role']={'A':'A','B':'B'}
        with self.assertRaises(ValueError):q.feature(candidate,analysis)

    def test_execution_uses_its_actual_projection_and_strict_hit_axes(self):
        candidate,analysis=sample();actual=copy.deepcopy(analysis)
        actual.update(candidate_id=candidate['candidate_id'],classification='hit',candidate_hit=True,
            execution_valid=True,control_valid=True,target_matches=True,prefix_matches=True,
            schedule_valid=True,cleanup_verified=True,property_evaluated=True,recovery_required=False)
        projection=actual['observations'].pop('projection')
        actual['observations'].pop('target');actual['observations'].pop('observed_prefix')
        projection['B']=[]
        record=q.feature(candidate,actual,projection=projection)
        self.assertEqual(record['pairs'],[]);self.assertEqual(record['observation_kind'],'execution')
        for key in ('candidate_hit','execution_valid','control_valid','target_matches','prefix_matches',
                'schedule_valid','cleanup_verified','property_evaluated'):
            altered=copy.deepcopy(actual);altered[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):q.feature(candidate,altered,projection=projection)
        with self.assertRaises(ValueError):q.feature(candidate,actual)


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.a,self.aa=sample(variant=0,line=70)
        self.b,self.ab=sample(variant=1,line=70)
        self.c,self.ac=sample(variant=2,line=80)
        self.d,self.ad=sample(order='ba',variant=3,line=90)

    def queue(self, rows=None, *, total_budget=4,pool_limit=4,per_input_budget=4,feedback=True,old=None,eligible=None):
        entries=[(self.a,self.aa),(self.b,self.ab),(self.c,self.ac),(self.d,self.ad)] if rows is None else rows
        p=pool([r[0] for r in entries]);features={r[0]['candidate_id']:q.feature(*r) for r in entries}
        return q.make_queue(p,'rmw',total_budget,pool_limit=pool_limit,per_input_budget=per_input_budget,
            feedback=feedback,features=features,history=[] if old is None else old,
            eligible={r['candidate_id']:True for r in p['candidates']} if eligible is None else eligible)

    def attempt(self, ledger, outcome='hit', ident=None):
        row=q.next_candidate(ledger);self.assertIsNotNone(row)
        ident=ident or 'new-'+str(len(ledger['attempts']))
        q.begin_attempt(ledger,row['candidate_id'],ident)
        q.finish_attempt(ledger,ident,outcome,guest_started=True,cleanup_confirmed=True,
            candidate_hit=outcome=='hit',property_evaluated=outcome=='hit',
            property_violation=False if outcome=='hit' else None,recovery_required=False,
            observed_feature=dict(copy.deepcopy(ledger['features'][row['candidate_id']]),observation_kind='execution') if outcome=='hit' else None)
        return row['candidate_id']

    def test_disabled_feedback_retains_exact_pool_order(self):
        ledger=self.queue(feedback=False,old=[history(self.a)])
        actual=[self.attempt(ledger) for _ in range(4)]
        self.assertEqual(actual,[r['candidate_id'] for r in (self.a,self.b,self.c,self.d)])
        self.assertTrue(all(s['reason']=='feedback-disabled-pool-order' for s in ledger['selections']))

    def test_dynamic_hit_reduces_same_coarse_feature_priority_without_deleting(self):
        ledger=self.queue()
        self.assertEqual(self.attempt(ledger),self.a['candidate_id'])
        self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.c['candidate_id'])
        self.assertEqual(len(ledger['candidates']),4)
        self.assertEqual(ledger['candidates'][1]['status'],'pending')
        self.assertEqual(ledger['features'][self.a['candidate_id']]['pairs'][0]['pair_id'],
            ledger['features'][self.b['candidate_id']]['pairs'][0]['pair_id'])

    def test_miss_invalid_timeout_and_launch_failures_do_not_increase_seen_features(self):
        for outcome in ('miss','invalid','timeout','infrastructure-error'):
            ledger=self.queue();before=copy.deepcopy(ledger['feature_hits'])
            self.attempt(ledger,outcome)
            self.assertEqual(ledger['feature_hits'],before)
            self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.b['candidate_id'])
            self.assertEqual(len(ledger['attempts']),1)

    def test_property_violation_is_still_a_valid_observed_pair_not_a_new_coverage_claim(self):
        ledger=self.queue();row=q.next_candidate(ledger);q.begin_attempt(ledger,row['candidate_id'],'broken')
        q.finish_attempt(ledger,'broken','hit',guest_started=True,cleanup_confirmed=True,
            property_evaluated=True,property_violation=True,recovery_required=False,
            observed_feature=as_execution(self.a,self.aa))
        self.assertEqual(q.summarize(ledger)['property_violations'],1)
        self.assertEqual(sum(ledger['feature_hits'].values()),1)
        self.assertFalse(q.summarize(ledger)['complete_search'])

    def test_every_third_slot_rotates_old_candidate_even_if_rare_work_remains(self):
        ledger=self.queue(old=[history(self.a,'old-a'),history(self.b,'old-b')])
        self.assertEqual(self.attempt(ledger),self.c['candidate_id'])
        self.assertEqual(self.attempt(ledger),self.d['candidate_id'])
        self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.a['candidate_id'])
        self.attempt(ledger)
        self.assertEqual(ledger['selections'][-1]['reason'],'old-candidate-rotation')

    def test_pool_cap_retains_all_rows_and_rotates_across_verified_history(self):
        ledger=self.queue(pool_limit=1,total_budget=1)
        self.assertEqual(self.attempt(ledger),self.a['candidate_id']);q.finalize(ledger)
        self.assertEqual(ledger['summary']['candidate_status']['pool-unexplored'],3)
        later=self.queue(pool_limit=1,total_budget=1,old=ledger['attempts'])
        self.assertEqual(q.next_candidate(later)['candidate_id'],self.b['candidate_id'])

    def test_per_input_budget_counts_directions_together(self):
        ledger=self.queue(total_budget=4,per_input_budget=1)
        self.attempt(ledger);self.assertIsNone(q.next_candidate(ledger));q.finalize(ledger)
        self.assertEqual(ledger['summary']['attempts'],1)
        self.assertEqual(ledger['summary']['candidate_status']['input-budget-unexplored'],3)
        self.assertEqual(ledger['summary']['per_input'][0]['unattempted'],3)

    def test_total_and_zero_budgets_retain_unexplored_candidates(self):
        for budget in (0,1):
            ledger=self.queue(total_budget=budget)
            for _ in range(budget):self.attempt(ledger)
            self.assertIsNone(q.next_candidate(ledger));q.finalize(ledger)
            self.assertEqual(ledger['summary']['candidate_status']['budget-unexplored'],4-budget)
            self.assertEqual(ledger['summary']['attempts'],budget)

    def test_zero_pool_and_input_limits_are_explicit(self):
        for name in ('pool_limit','per_input_budget'):
            ledger=self.queue(**{name:0});self.assertIsNone(q.next_candidate(ledger));q.finalize(ledger)
            self.assertEqual(ledger['summary']['attempts'],0)
            self.assertEqual(ledger['summary']['candidate_status']['pool-unexplored' if name=='pool_limit' else 'input-budget-unexplored'],4)

    def test_duplicate_complete_sources_merge_but_distinct_prefixes_do_not(self):
        ledger=self.queue(rows=[(self.a,self.aa),(self.a,self.aa),(self.b,self.ab)])
        self.assertEqual(len(ledger['candidates']),2)
        self.assertEqual(ledger['candidates'][0]['feature_ids'],ledger['candidates'][1]['feature_ids'])

    def test_cross_family_and_unsupported_rows_stay_separate(self):
        p=pool([self.a,self.b]);eligible={self.a['candidate_id']:False,self.b['candidate_id']:True}
        ledger=self.queue(rows=[(self.a,self.aa),(self.b,self.ab)],eligible=eligible)
        self.assertEqual(ledger['candidates'][0]['status'],'unsupported')
        self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.b['candidate_id'])

    def test_full_outcome_and_interruption_denominators(self):
        ledger=self.queue();self.attempt(ledger,'timeout');q.finalize(ledger,'Recovery required')
        self.assertEqual(ledger['summary']['attempts'],1)
        self.assertEqual(ledger['summary']['attempt_outcomes']['timeout'],1)
        self.assertEqual(ledger['summary']['candidate_status']['unattempted-interrupted'],3)

    def test_cannot_skip_order_double_finish_or_finalize_active(self):
        ledger=self.queue()
        with self.assertRaises(ValueError):q.begin_attempt(ledger,self.b['candidate_id'],'skip')
        q.begin_attempt(ledger,self.a['candidate_id'],'one')
        with self.assertRaises(ValueError):q.next_candidate(ledger)
        with self.assertRaises(ValueError):q.finalize(ledger,'stop')
        q.finish_attempt(ledger,'one','miss',guest_started=True,cleanup_confirmed=True)
        with self.assertRaises(ValueError):q.finish_attempt(ledger,'one','miss',guest_started=True,cleanup_confirmed=True)
        with self.assertRaises(ValueError):q.finalize(ledger)

    def test_preview_does_not_consume_budget_and_source_inputs_are_unchanged(self):
        p=pool([self.a,self.b]);features={a['candidate_id']:q.feature(a,b) for a,b in ((self.a,self.aa),(self.b,self.ab))}
        before=copy.deepcopy((p,features))
        ledger=q.make_queue(p,'rmw',1,pool_limit=2,per_input_budget=2,feedback=True,features=features,
            eligible={a['candidate_id']:True for a in (self.a,self.b)})
        q.next_candidate(ledger);q.next_candidate(ledger)
        self.assertEqual(ledger['attempts'],[]);self.assertEqual(ledger['input_attempts'],{})
        self.assertEqual((p,features),before)

    def test_history_rejects_stats_duplicates_unknown_candidates_and_forged_hit(self):
        bads=[{},[history(self.a),history(self.a)], [dict(history(self.a),candidate_id='f'*64)],
            [dict(history(self.a,outcome='miss'),property_evaluated=True)],
            [dict(history(self.a),candidate_hit=False)], [dict(history(self.a),guest_started=1)]]
        for bad in bads:
            with self.subTest(history=bad),self.assertRaises(ValueError):self.queue(old=bad)

    def test_invalid_boolean_budgets_and_feature_bindings_rejected(self):
        for kwargs in (dict(total_budget=True),dict(pool_limit=-1),dict(per_input_budget=4097),dict(feedback=1)):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.queue(**kwargs)
        p=pool([self.a]);features={self.a['candidate_id']:q.feature(self.b,self.ab)}
        with self.assertRaises(ValueError):q.make_queue(p,'rmw',1,pool_limit=1,per_input_budget=1,
            feedback=True,features=features,eligible={self.a['candidate_id']:True})

    def test_no_observed_pair_is_unknown_not_completed_coverage(self):
        analysis=copy.deepcopy(self.aa);analysis['observations']['projection']['B']=[]
        ledger=self.queue(rows=[(self.a,analysis)],total_budget=1)
        self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.a['candidate_id'])
        self.attempt(ledger);q.finalize(ledger)
        self.assertEqual(ledger['selections'][0]['reason'],'no-observed-pair-unknown')
        self.assertEqual(ledger['summary']['observed_pair_signatures'],0)
        self.assertFalse(ledger['summary']['coverage_claimed'])

    def test_actual_execution_subset_does_not_mark_unobserved_sample_pairs_seen(self):
        ledger=self.queue();row=q.next_candidate(ledger)
        q.begin_attempt(ledger,row['candidate_id'],'actual-subset')
        observed=as_execution(self.a,self.aa);observed['pairs']=[]
        q.finish_attempt(ledger,'actual-subset','hit',guest_started=True,cleanup_confirmed=True,
            property_evaluated=True,property_violation=False,recovery_required=False,observed_feature=observed)
        self.assertEqual(ledger['feature_hits'],{})
        self.assertEqual(q.next_candidate(ledger)['candidate_id'],self.b['candidate_id'])
        later=self.queue(old=ledger['attempts'])
        self.assertEqual(later['feature_hits'],{})

    def test_hit_without_actual_feature_or_with_sample_feature_is_rejected(self):
        for observed in (None,q.feature(self.a,self.aa)):
            ledger=self.queue();q.begin_attempt(ledger,self.a['candidate_id'],'bad-feature')
            with self.assertRaises(ValueError):q.finish_attempt(ledger,'bad-feature','hit',guest_started=True,
                cleanup_confirmed=True,property_evaluated=True,property_violation=False,observed_feature=observed)
            self.assertEqual(ledger['attempts'][0]['outcome'],'running')


if __name__ == '__main__':unittest.main()

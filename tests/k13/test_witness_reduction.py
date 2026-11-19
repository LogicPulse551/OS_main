"""Finite reduction contracts. These fixtures are not actual kernel executions."""
import copy
from pathlib import Path
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from kconc import candidates as c, witness_reduction as r, regmap_oracle


def entry(case='disjoint-bits',mode='split',family='rmw'):
    return c.get_input(c.load_catalog(),family,case,mode)


def observation(**changes):
    value=dict(actual_execution=True,control_valid=True,schedule_validated=True,
        candidate_hit=True,property_evaluated=True,property_violation=True,
        cleanup_verified=True,recovery_required=False,property_id=r.RMW_PROPERTY)
    value.update(changes);return value


class Edits(unittest.TestCase):
    def test_disjoint_to_zero_is_one_bit_effect_deletion(self):
        before=entry();edits=r.input_edits(before)
        self.assertEqual(len(edits),1);edit=edits[0]
        self.assertEqual(edit['after_input'],entry('zero-mask'))
        self.assertEqual(edit['removed_bits'],[dict(role=0,mask=1)])
        self.assertEqual((edit['cost_before'],edit['cost_after']),(2,1))
        self.assertEqual(edit['operation_calls_removed'],0)
        self.assertTrue(r.is_input_deletion(before,edit['after_input']))

    def test_old_seed_and_catalog_are_unchanged(self):
        before=entry();saved=copy.deepcopy(before);catalog=c.load_catalog();old=copy.deepcopy(catalog)
        edits=r.input_edits(before,catalog);edits[0]['after_input']['operations'][0]['mask']=99
        self.assertEqual(before,saved);self.assertEqual(catalog,old)

    def test_initial_register_mode_changes_and_expansion_are_not_deletions(self):
        for other in (entry('high-bits'),entry('different-registers'),entry(mode='update-bits')):
            self.assertFalse(r.is_input_deletion(entry(),other))
        self.assertFalse(r.is_input_deletion(entry('zero-mask'),entry()))
        self.assertFalse(r.is_input_deletion(entry(),entry()))

    def test_zero_and_mutex_have_no_registered_input_deletion(self):
        self.assertEqual(r.input_edits(entry('zero-mask')),[])
        self.assertEqual(r.input_edits(entry('different-registers','per-role','mutex')),[])

    def test_overlap_subsets_are_only_matching_value_projections(self):
        edits=r.input_edits(entry('overlap-bits'))
        self.assertEqual({e['after_input']['case_id'] for e in edits},{'zero-mask','disjoint-bits'})
        self.assertTrue(all(e['cost_after'] < e['cost_before'] for e in edits))

    def test_schedule_removal_preserves_each_logical_direction(self):
        for order,old,new in [('ab','A-B-A','A-B'),('ba','B-A-B','B-A')]:
            edit=r.schedule_edits(order)[0]
            self.assertEqual((edit['before_pattern'],edit['after_pattern']),(old,new))
            self.assertEqual((edit['cost_before'],edit['cost_after']),(1,0))
            self.assertEqual(edit['input_operations_removed'],0)

    def test_stack_or_role_deletions_cannot_be_forged_as_supported(self):
        for kind in ('drop-stack-frame','delete-role','change-initial'):
            with self.assertRaises(ValueError):r.validate_edit(dict(policy_id=r.POLICY_ID,kind=kind))
        edit=r.input_edits(entry())[0];edit['cost_after']=0
        with self.assertRaises(ValueError):r.validate_edit(edit)

    def test_unregistered_input_and_invalid_order_fail_closed(self):
        before=entry();before['operations'][0]['mask']=0
        with self.assertRaises(ValueError):r.input_edits(before)
        for order in ('aa','AB',None):
            with self.assertRaises(ValueError):r.schedule_edits(order)


class Decisions(unittest.TestCase):
    def setUp(self):self.edit=r.input_edits(entry())[0]

    def test_valid_hit_same_violation_is_acceptance_not_minimum_proof(self):
        result=r.decide(self.edit,observation(),r.RMW_PROPERTY)
        self.assertTrue(result['accepted']);self.assertFalse(result['global_minimum_proved'])
        self.assertFalse(result['source_correctness_proved']);self.assertFalse(result['original_path_replay'])

    def test_miss_timeout_unclean_and_unevaluated_never_accept(self):
        cases=[dict(actual_execution=False),dict(candidate_hit=False),dict(control_valid=False),
            dict(schedule_validated=False),dict(property_evaluated=False),dict(property_violation=False),
            dict(cleanup_verified=False),dict(recovery_required=True)]
        for changes in cases:
            self.assertFalse(r.decide(self.edit,observation(**changes),r.RMW_PROPERTY)['accepted'])

    def test_different_failure_property_cannot_keep_reduction(self):
        result=r.decide(self.edit,observation(property_id=r.MUTEX_PROPERTY),r.RMW_PROPERTY)
        self.assertFalse(result['accepted']);self.assertEqual(result['reason'],'different-property')

    def test_input_edit_cannot_change_oracle_family(self):
        with self.assertRaises(ValueError):
            r.decide(self.edit,observation(property_id=r.MUTEX_PROPERTY),r.MUTEX_PROPERTY)

    def test_serial_candidate_hit_unknown_must_be_explicit(self):
        value=observation();value.pop('candidate_hit')
        with self.assertRaises(ValueError):r.decide(r.schedule_edits('ab')[0],value,r.RMW_PROPERTY)

    def test_serial_trial_uses_new_control_validation_not_old_candidate_hit(self):
        edit=r.schedule_edits('ab')[0]
        result=r.decide(edit,observation(candidate_hit=None,property_violation=False),r.RMW_PROPERTY)
        self.assertFalse(result['accepted']);self.assertEqual(result['reason'],'violation-not-preserved')
        result=r.decide(edit,observation(candidate_hit=None),r.RMW_PROPERTY)
        self.assertTrue(result['accepted']);self.assertFalse(result['original_path_replay'])

    def test_axes_must_be_explicit_booleans(self):
        for key in ('actual_execution','control_valid','schedule_validated','property_evaluated',
                    'property_violation','cleanup_verified','recovery_required'):
            value=observation();value[key]=1
            with self.assertRaises(ValueError):r.decide(self.edit,value,r.RMW_PROPERTY)
        with self.assertRaises(ValueError):r.decide(self.edit,observation(), 'any-failure')

    def test_zero_mask_can_still_erase_peer_update_under_ab(self):
        # A no-bit-effect request is still a split read/write. A reads zero,
        # B writes two, then A writes its stale zero. Legal serial final is two.
        after=self.edit['after_input']
        lost=regmap_oracle.evaluate(after['initial'],after['operations'],[0,0,0,0])
        preserved=regmap_oracle.evaluate(after['initial'],after['operations'],[2,0,0,0])
        self.assertFalse(lost['allowed']);self.assertEqual(lost['error_type'],r.RMW_PROPERTY)
        self.assertTrue(preserved['allowed'])

    def test_normal_trial_is_rejected_without_proving_seed_correct(self):
        result=r.decide(self.edit,observation(property_violation=False),r.RMW_PROPERTY)
        self.assertFalse(result['accepted']);self.assertFalse(result['source_correctness_proved'])


if __name__=='__main__':unittest.main()

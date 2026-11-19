"""K13 finite witness edits and acceptance decisions; never executes a guest.

Only registered masked-update bit deletions and removal of the one declared
preemption are supported. Callers must verify raw trial evidence before making
an observation. An unsuccessful trial is retained, never a correctness proof.
"""
from __future__ import annotations

import copy
from . import candidates

POLICY_ID = 'kconc.k13.finite-witness-deletion-v1'
RMW_PROPERTY = 'nonserializable-masked-update'
MUTEX_PROPERTY = 'mutual-exclusion-violation'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def input_cost(entry):
    """Count requested mask bits; zero-mask still executes its real ioctl."""
    candidates.validate_input(entry)
    return sum(row['mask'].bit_count() for row in entry['operations'])


def is_input_deletion(before, after):
    """Delete bit effects only; preserve roles, registers, initial state and API."""
    candidates.validate_input(before); candidates.validate_input(after)
    if before['family'] != 'rmw' or after['family'] != 'rmw':
        return False
    fixed = ('family', 'scenario', 'abi', 'mode', 'initial')
    if any(before[key] != after[key] for key in fixed):
        return False
    if len(before['operations']) != 2 or len(after['operations']) != 2:
        return False
    for old, new in zip(before['operations'], after['operations']):
        if (old['role'] != new['role'] or old['reg'] != new['reg']
                or new['mask'] & ~old['mask']
                or new['value'] != old['value'] & new['mask']):
            return False
    return input_cost(after) < input_cost(before)


def _edit(fields):
    data = dict(policy_id=POLICY_ID, **copy.deepcopy(fields))
    return dict(edit_id=candidates.fingerprint(data), **data)


def input_edits(entry, catalog=None):
    """Enumerate registered strict bit-effect subsets, not arbitrary mutations."""
    candidates.validate_input(entry)
    catalog = candidates.load_catalog() if catalog is None else candidates.validate_catalog(catalog)
    require(entry in catalog['inputs'], 'Original input is outside the registered catalog')
    result = []
    for after in catalog['inputs']:
        if not is_input_deletion(entry, after):
            continue
        removed = [dict(role=old['role'], mask=old['mask'] & ~new['mask'])
            for old,new in zip(entry['operations'],after['operations']) if old['mask'] != new['mask']]
        result.append(_edit(dict(kind='input-mask-subset', before_input=entry,
            after_input=after, removed_bits=removed, cost_before=input_cost(entry),
            cost_after=input_cost(after), measure='requested-mask-bit-count',
            operation_calls_removed=0, initialization_preserved=True)))
    return sorted(result, key=lambda row:(row['cost_after'],row['after_input']['input_id']))


def schedule_edits(order):
    """Remove the sole mid-operation preemption, preserving logical order.

    The new serial schedule is validated as serial execution. It is not claimed
    to hit the original interrupted candidate or replay the original path.
    """
    require(order in ('ab','ba'), 'Expected a declared AB or BA direction')
    first, peer = order[0].upper(), order[1].upper()
    return [_edit(dict(kind='remove-preemption', order=order,
        before_pattern=f'{first}-{peer}-{first}', after_pattern=f'{first}-{peer}',
        cost_before=1, cost_after=0, measure='mid-operation-preemption-count',
        input_operations_removed=0, initialization_preserved=True))]


def validate_edit(edit):
    require(isinstance(edit,dict) and edit.get('policy_id') == POLICY_ID, 'Unknown reduction policy')
    if edit.get('kind') == 'input-mask-subset':
        allowed = input_edits(edit.get('before_input'))
    elif edit.get('kind') == 'remove-preemption':
        allowed = schedule_edits(edit.get('order'))
    else:
        raise ValueError('Unsupported deletion; roles, initial state and stack frames are not optional edits')
    require(any(candidates.canonical(edit) == candidates.canonical(row) for row in allowed),
        'Edit differs from its strictly enumerated deletion')
    return edit


def decide(edit, observation, property_id):
    """Accept only a smaller, actually executed, valid and still failing trial.

    Observation is a normalized result of raw verification by the runtime, not
    a user-provided success assertion. The original failing seed is separately
    verified before enumeration. No conclusion about untested edits is made.
    """
    validate_edit(edit)
    require(property_id in (RMW_PROPERTY,MUTEX_PROPERTY), 'Unknown declared failure property')
    require(isinstance(observation,dict), 'Missing verified trial observation')
    fields = ('actual_execution','control_valid','schedule_validated','property_evaluated',
              'property_violation','cleanup_verified','recovery_required')
    require(all(type(observation.get(key)) is bool for key in fields),
        'Every execution, control, property and cleanup axis must be explicit')
    require('candidate_hit' in observation and (observation['candidate_hit'] is None
            or type(observation['candidate_hit']) is bool),
        'Candidate-hit must be a boolean or explicitly unavailable for serial trials')
    require(edit['kind'] != 'input-mask-subset' or property_id == RMW_PROPERTY,
        'Masked-update input deletion must retain its declared masked-update property')
    reason = 'same-property-preserved'
    if not observation['actual_execution']:
        reason = 'not-executed'
    elif observation['recovery_required'] or not observation['cleanup_verified']:
        reason = 'incomplete-or-unclean'
    elif not observation['control_valid'] or not observation['schedule_validated']:
        reason = 'control-unconfirmed'
    elif edit['kind'] == 'input-mask-subset' and observation.get('candidate_hit') is not True:
        reason = 'new-input-candidate-not-hit'
    elif not observation['property_evaluated']:
        reason = 'property-unevaluated'
    elif observation.get('property_id') != property_id:
        reason = 'different-property'
    elif not observation['property_violation']:
        reason = 'violation-not-preserved'
    accepted = reason == 'same-property-preserved'
    return dict(policy_id=POLICY_ID, edit_id=edit['edit_id'], accepted=accepted, reason=reason,
        property_id=property_id, cost_before=edit['cost_before'], cost_after=edit['cost_after'],
        original_path_replay=False, global_minimum_proved=False, source_correctness_proved=False,
        scope='Only this registered edit and verified trial; failed and unattempted edits remain in the ledger')


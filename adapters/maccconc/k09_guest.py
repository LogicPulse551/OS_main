#!/usr/bin/env python3
"""One validated marker plan under the accepted K04 process supervisor."""
from pathlib import Path
import k04_guest as supervisor

supervisor.ROOT = Path('/home/lab/k09')
supervisor.BUILD_ROOTS = {supervisor.ROOT, Path('/home/lab/k10-control'), Path('/home/lab/k11')}
supervisor.FAULTS = {'none'}
RMW_CASES = {'disjoint-bits', 'overlap-bits', 'different-registers', 'zero-mask', 'high-bits'}
NAMES = {f'regmap-k06-{case}-{mode}.so' for case in RMW_CASES for mode in ('split', 'update-bits')}
NAMES |= {f'regmap-k07-{case}-{mode}.so' for case in ('different-registers', 'shared-register') for mode in ('shared', 'per-role')}

def command_for_request(request, directory):
    exe, library = Path(request['executable']), Path(request['scenario_library'])
    orders = {'kcov-execute-k09-ab': 'ab', 'kcov-execute-k09-ba': 'ba'}
    if (request['fault'] != 'none' or request['plan_path'] is None or exe.name not in orders
            or library.name not in NAMES or exe.parent != library.parent):
        raise supervisor.GuestError('Only fixed K09 scenarios with an explicit saved plan are accepted')
    return [str(exe), str(library), '--k09-execute', orders[exe.name], request['plan_path'], str(directory/'trace')]

supervisor.command_for_request = command_for_request
if __name__ == '__main__':
    raise SystemExit(supervisor.main())

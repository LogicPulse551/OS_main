#!/usr/bin/env python3
"""K08 serial sampler using the accepted K04 cleanup and cancellation supervisor."""
from pathlib import Path
import k04_guest as supervisor

supervisor.ROOT = Path('/home/lab/k08')
supervisor.BUILD_ROOTS = {supervisor.ROOT, Path('/home/lab/k11')}
supervisor.FAULTS = {'none'}
RMW_CASES = {'disjoint-bits', 'overlap-bits', 'different-registers', 'zero-mask', 'high-bits'}
NAMES = {f'regmap-k06-{case}-{mode}.so' for case in RMW_CASES for mode in ('split', 'update-bits')}
NAMES |= {f'regmap-k07-{case}-{mode}.so' for case in ('different-registers', 'shared-register') for mode in ('shared', 'per-role')}

def command_for_request(request, directory):
    exe, library = Path(request['executable']), Path(request['scenario_library'])
    orders = {'kcov-sample-k08-ab': 'ab', 'kcov-sample-k08-ba': 'ba'}
    if (request['fault'] != 'none' or request['plan_path'] is not None or exe.name not in orders
            or library.name not in NAMES or exe.parent != library.parent):
        raise supervisor.GuestError('Only fixed K08 serial samples are accepted; candidate execution is not connected')
    return [str(exe), str(library), '--k08-baseline', orders[exe.name], str(directory/'trace')]

supervisor.command_for_request = command_for_request
if __name__ == '__main__':
    raise SystemExit(supervisor.main())

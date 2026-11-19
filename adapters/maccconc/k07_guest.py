#!/usr/bin/env python3
"""K07 fixed case binaries under the accepted K04 process supervisor."""
from pathlib import Path
import k04_guest as supervisor

supervisor.ROOT = Path('/home/lab/k07')
supervisor.FAULTS = {'none'}
CASES = {'different-registers', 'shared-register'}
MODES = {'shared', 'per-role'}

def command_for_request(request, directory):
    exe, library = Path(request['executable']), Path(request['scenario_library'])
    if request['fault'] != 'none':
        raise supervisor.GuestError('K07 accepts only declared critical-region cases')
    if exe == library and exe.name == 'regmap-k07-client':
        if request['plan_path'] is not None:
            raise supervisor.GuestError('Matrix client does not accept a control plan')
        return [str(exe), 'matrix']
    names = {f'regmap-k07-{case}-{mode}.so' for case in CASES for mode in MODES}
    if exe.name != 'kcov-autorace-k07' or library.name not in names or exe.parent != library.parent:
        raise supervisor.GuestError('Only fixed K07 scenario binaries may execute')
    command = [str(exe), str(library)]
    if request['plan_path'] is not None:
        return command + ['--k03-replay', request['plan_path'], str(directory/'trace')]
    return command + ['--k05-baseline', str(directory/'trace')]

supervisor.command_for_request = command_for_request
if __name__ == '__main__':
    raise SystemExit(supervisor.main())

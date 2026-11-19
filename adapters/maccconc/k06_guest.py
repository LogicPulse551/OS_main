#!/usr/bin/env python3
"""K06 fixed case binaries under the accepted K04 process supervisor."""
from pathlib import Path
import k04_guest as supervisor

supervisor.ROOT = Path('/home/lab/k06')
supervisor.FAULTS = {'none'}
CASES = {'disjoint-bits', 'overlap-bits', 'different-registers', 'zero-mask', 'high-bits'}
MODES = {'split', 'update-bits'}

def command_for_request(request, directory):
    exe, library = Path(request['executable']), Path(request['scenario_library'])
    if request['fault'] != 'none':
        raise supervisor.GuestError('K06 accepts only declared masked-update cases')
    if exe == library and exe.name == 'regmap-k06-client':
        if request['plan_path'] is not None:
            raise supervisor.GuestError('Matrix client does not accept a control plan')
        return [str(exe), 'matrix']
    names = {f'regmap-k06-{case}-{mode}.so' for case in CASES for mode in MODES}
    if exe.name != 'kcov-autorace-k06' or library.name not in names or exe.parent != library.parent:
        raise supervisor.GuestError('Only fixed K06 scenario binaries may execute')
    command = [str(exe), str(library)]
    if request['plan_path'] is not None:
        return command + ['--k03-replay', request['plan_path'], str(directory/'trace')]
    return command + ['--k05-baseline', str(directory/'trace')]

supervisor.command_for_request = command_for_request
if __name__ == '__main__':
    raise SystemExit(supervisor.main())

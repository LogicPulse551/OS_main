#!/usr/bin/env python3
"""K05 command adapter reusing K04's process supervision and ownership checks."""
from pathlib import Path
import k04_guest as supervisor

supervisor.ROOT = Path('/home/lab/k05')
supervisor.FAULTS = {'none', 'setup'}


def command_for_request(request, directory):
    exe, library = Path(request['executable']), Path(request['scenario_library'])
    if exe.name == library.name == 'regmap-client' and exe == library:
        if request['plan_path'] is not None:
            raise supervisor.GuestError('Client does not accept a control plan')
        return [str(exe), 'fault-reset'] if request['fault'] == 'setup' else [str(exe), 'baseline', '--rounds', '20']
    if exe.name != 'kcov-autorace-k05' or library.name != 'regmap-v1.so' or exe.parent != library.parent:
        raise supervisor.GuestError('Only the fixed K05 scenario or client may execute')
    command = [str(exe), str(library)]
    if request['plan_path'] is not None:
        return command + ['--k03-replay', request['plan_path'], str(directory/'trace')]
    return command + ['--k05-baseline', str(directory/'trace')]


supervisor.command_for_request = command_for_request
if __name__ == '__main__':
    raise SystemExit(supervisor.main())

"""Process boundary around K03's existing identity checks, without a scenario."""
import argparse
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {'passed': False, 'scope': 'current fixed K03 build identity; no testcase executed'}
    try:
        runtime = json.loads(args.task.read_text())['runtime']
        spec = importlib.util.spec_from_file_location('k03_identity_backend', REPO / 'scripts/maccconc-k03.py')
        k03 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(k03)
        session = k03.Session(SimpleNamespace(output=args.output,
            guest_build=Path(runtime['scenario_guest_build']), build_lab=Path(runtime['build_lab']),
            kernel_build=Path(runtime['kernel_build'])))
        result.update(passed=True, binding=session.identity())
    except Exception as error:
        result.update(passed=False, error={'type': type(error).__name__, 'message': str(error)})
    # Session may fail during construction, after creating its evidence directory.
    if args.output.is_dir():
        (args.output / 'worker-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

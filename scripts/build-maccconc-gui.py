#!/usr/bin/env python3
"""Build the pinned host GUI and read-only source mapper; never launch the GUI."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / 'configs/maccconc.lock.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--build-dir', type=Path,
                        help='New external output directory; existing builds are preserved')
    parser.add_argument('--helper-only', action='store_true',
                        help='Reuse a verified GUI build and build only the read-only source mapper')
    parser.add_argument('--ui-scale-override', action='store_true',
                        help='Explicitly apply the optional MACCCONC_UI_SCALE display-only patch')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error('--jobs must be between 1 and 16')
    lab = Path(os.environ.get('LAB_DIR', str(Path.home() / 'os-concurrency-lab'))).expanduser().resolve()
    lock = json.loads(LOCK_PATH.read_text())
    upstream = lock['sources']['maccconc']
    source = lab / 'sources/k01' / upstream['directory']
    build = (args.build_dir or lab / 'build/maccconc-gui-c17ba2d').expanduser().resolve()
    for destination in (lab, build):
        if destination.is_relative_to(REPO) or REPO.is_relative_to(destination):
            parser.error('Runtime paths must be outside the delivery repository and its ancestors')
    if build.is_relative_to(lab / 'sources') or (lab / 'sources').is_relative_to(build):
        parser.error('Build directory must be separate from the source cache')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    evidence = lab / 'evidence/k03' / ('gui-' + stamp)
    evidence.mkdir(parents=True)
    result = {'task': 'K03', 'scope': 'host GUI/source-map build only; not a runtime or replay check',
              'mode': 'source-map-only' if args.helper_only else 'gui-and-source-map',
              'ui_scale_override': args.ui_scale_override,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed': False, 'build_directory': str(build), 'evidence_directory': str(evidence),
              'source_commit': upstream['commit'], 'submodules': upstream['submodules'],
              'team_patches_applied': [], 'lock_sha256': digest(LOCK_PATH),
              'builder_sha256': digest(Path(__file__).resolve()), 'steps': []}
    result['attribution'] = {
        'upstream': 'MAccConc', 'commit': upstream['commit'],
        'copyright': '2026 Google LLC', 'license': 'Apache-2.0',
        'imgui_license': 'MIT', 'team_change': 'source-map helper and optional GUI display scale only'}

    def save():
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    def run(name, command, cwd=None):
        entry = {'name': name, 'command': [str(x) for x in command], 'cwd': str(cwd or REPO),
                 'log': str(evidence / (name + '.log')), 'status': 'running'}
        result['steps'].append(entry)
        save()
        print(f'{name}: {entry["log"]}', flush=True)
        with Path(entry['log']).open('w') as log:
            process = subprocess.run(entry['command'], cwd=cwd or REPO,
                                     stdout=log, stderr=subprocess.STDOUT)
        entry.update(exit_code=process.returncode, status='passed' if process.returncode == 0 else 'failed')
        save()
        if process.returncode:
            raise RuntimeError(f'{name} failed; see {entry["log"]}')
        return Path(entry['log']).read_text()

    try:
        run('verify-sources', [sys.executable, REPO / 'scripts/maccconc-sources.py',
                              'verify', '--component', 'maccconc', '--source-root', lab / 'sources/k01'])
        work = build / 'source'
        if args.helper_only:
            references = []
            for path in sorted((lab / 'evidence/k03').glob('gui-*/result.json')):
                previous = json.loads(path.read_text())
                if previous.get('passed') and previous.get('source_commit') == upstream['commit'] and \
                        previous.get('mode') != 'source-map-only' and \
                        previous.get('ui_scale_override', False) == args.ui_scale_override and \
                        previous.get('binary', {}).get('path') == str(work / 'kcov-gui'):
                    references.append((path, previous))
            if not references:
                raise RuntimeError('--helper-only requires a successful GUI build at --build-dir')
            path, previous = references[-1]
            if digest(work / 'kcov-gui') != previous['binary']['sha256']:
                raise RuntimeError('Existing GUI differs from its successful build record')
            result['reused_gui_record'] = {'path': str(path), 'sha256': digest(path)}
            result['binary'] = previous['binary']
            result['team_patches_applied'] = previous.get('team_patches_applied', [])
            result['gui_reused_without_compilation'] = True
        else:
            if build.exists():
                raise RuntimeError('Build directory already exists; preserve it and choose a new --build-dir')
            build.mkdir(parents=True)
            work.mkdir()
            archives = []
            components = [(source, upstream['commit'], work, 'maccconc')]
            components.extend((source / item['path'], item['commit'], work / item['path'], 'imgui')
                              for item in upstream['submodules'])
            for checkout, commit, destination, name in components:
                archive = build / (name + '.tar')
                run('archive-' + name, ['git', '-C', checkout, 'archive', '--format=tar',
                                        '--output=' + str(archive), commit])
                destination.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive) as stream:
                    stream.extractall(destination, filter='data')
                archives.append({'component': name, 'commit': commit, 'sha256': digest(archive)})
            inputs = {p.relative_to(work).as_posix(): digest(p) for p in work.rglob('*') if p.is_file()}
            (evidence / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
            result['archives'] = archives
            if args.ui_scale_override:
                patch = REPO / 'patches/maccconc/0003-gui-scale.patch'
                patch_hash = digest(patch)
                run('apply-ui-scale-patch', ['patch', '--batch', '--forward', '--fuzz=0', '-p1',
                                           '-i', patch, '-d', work])
                if digest(patch) != patch_hash:
                    raise RuntimeError('GUI patch changed while applying it')
                result['team_patches_applied'] = [{'path': str(patch), 'sha256': patch_hash,
                    'scope': 'optional MACCCONC_UI_SCALE; display only, default unchanged',
                    'author': 'OS concurrency competition project', 'upstream_license': 'Apache-2.0'}]
            effective_inputs = {p.relative_to(work).as_posix(): digest(p) for p in work.rglob('*') if p.is_file()}
            changes = sorted(name for name in inputs if inputs[name] != effective_inputs.get(name))
            expected_changes = ['kcov-gui.cpp'] if args.ui_scale_override else []
            if changes != expected_changes or set(inputs) != set(effective_inputs):
                raise RuntimeError('Unexpected files changed by the GUI adaptation')
            (evidence / 'effective-source-inputs.json').write_text(json.dumps(effective_inputs, indent=2) + '\n')
            result['changed_upstream_files'] = changes
        run('host-packages', ['dpkg-query', '-W', '-f', '${binary:Package}\t${Version}\n',
                             'g++', 'make', 'pkg-config', 'libdw-dev', 'libelf-dev',
                             'libglfw3-dev', 'libgl-dev', 'libcapstone-dev'])
        run('compiler-version', ['g++', '--version'])
        run('pkg-config-versions', ['pkg-config', '--modversion', 'glfw3', 'libdw', 'capstone', 'gl'])
        if not args.helper_only:
            run('build', ['make', '-C', work, '-j' + str(args.jobs), 'CXX=g++', 'kcov-gui'])
        binary = work / 'kcov-gui'
        elf = run('elf-header', ['readelf', '-h', binary])
        dependencies = run('dynamic-libraries', ['ldd', binary])
        if 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in dependencies:
            raise RuntimeError('GUI ELF architecture or dynamic dependencies did not validate')
        if not args.helper_only:
            if any(digest(work / name) != expected for name, expected in effective_inputs.items()):
                raise RuntimeError('An extracted input file changed during the upstream build')
            result.update(input_file_count=len(inputs), effective_inputs_unchanged_by_build=True)
        helper_source = REPO / 'adapters/maccconc/source-map.cpp'
        result['helper_source'] = {'path': str(helper_source), 'sha256': digest(helper_source)}
        helper_dir = build / 'helpers' / stamp
        helper_dir.mkdir(parents=True)
        helper = helper_dir / 'source-map'
        run('source-map-build', ['g++', '-std=gnu++23', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                                helper_source, '-ldw', '-lelf', '-o', helper])
        helper_deps = run('source-map-libraries', ['ldd', helper])
        if 'not found' in helper_deps or digest(helper_source) != result['helper_source']['sha256']:
            raise RuntimeError('Source mapper has missing dependencies or input changed during build')
        result['helper_binary'] = {'path': str(helper), 'sha256': digest(helper), 'bytes': helper.stat().st_size}
        run('verify-sources-after', [sys.executable, REPO / 'scripts/maccconc-sources.py',
                                    'verify', '--component', 'maccconc', '--source-root', lab / 'sources/k01'])
        result.update(passed=True, binary={'path': str(binary), 'sha256': digest(binary),
                                          'bytes': binary.stat().st_size},
                      gui_launched=False, vsock_connected=False)
    except (Exception, KeyboardInterrupt) as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result['exit_code'] = 0 if result['passed'] else 1
    save()
    print(json.dumps(result, indent=2), flush=True)
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())

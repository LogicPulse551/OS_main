#!/usr/bin/env python3
"""Build the pinned LLVM or kernel, keeping all outputs outside the repository."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
LOCK = json.loads((REPO / 'configs/maccconc.lock.json').read_text())
LAB = Path(os.environ.get('LAB_DIR', str(Path.home() / 'os-concurrency-lab'))).resolve()
SRC = LAB / 'sources/k01'
LLVM = LAB / 'toolchains/llvm-dc5c6d008f48'
LLVM_BUILD = LAB / 'build/llvm-dc5c6d008f48'
KERNEL_BUILD = LAB / 'build/linux-2fc2e45b0cd7'
LLVM_TARGETS = ['clang', 'lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy', 'llvm-objdump',
                'llvm-readobj', 'llvm-size', 'llvm-strings', 'clang-resource-headers']
LLVM_COMPONENTS = LLVM_TARGETS + ['llvm-ranlib', 'llvm-readelf', 'llvm-strip']
KERNEL_TOOLS = ('clang', 'clang++', 'ld.lld', 'llvm-ar', 'llvm-ranlib', 'llvm-nm',
                'llvm-objcopy', 'llvm-objdump', 'llvm-readelf', 'llvm-strip')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha256_file(path), 'bytes': path.stat().st_size}


def installed_tools(prefix):
    result = {}
    for name in KERNEL_TOOLS:
        path = prefix / 'bin' / name
        if not path.is_file() or not path.resolve().is_relative_to(prefix.resolve()):
            raise RuntimeError(f'Missing tool or tool symlink escapes installation: {path}')
        result[name] = {'sha256': sha256_file(path), 'bytes': path.stat().st_size}
    return result


def resource_headers(prefix):
    major = LOCK['sources']['llvm']['version'].split('.')[0]
    root = prefix / 'lib/clang' / major / 'include'
    files = sorted(p for p in root.rglob('*') if p.is_file())
    if not files:
        raise RuntimeError(f'Missing installed Clang resource headers: {root}')
    digest = hashlib.sha256()
    for path in files:
        if not path.resolve().is_relative_to(prefix.resolve()):
            raise RuntimeError(f'Resource header escapes installation: {path}')
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(sha256_file(path).encode() + b'\n')
    return {'relative_path': root.relative_to(prefix).as_posix(),
            'file_count': len(files), 'sha256_tree': digest.hexdigest()}


def verify_llvm_build_result(path):
    path = Path(path).resolve()
    evidence_root = (LAB / 'evidence/k02').resolve()
    if not path.is_relative_to(evidence_root) or path.name != 'build-result.json':
        raise RuntimeError('LLVM build result must be inside this lab evidence directory')
    result = json.loads(path.read_text())
    if result.get('stage') != 'llvm' or result.get('source_commit') != LOCK['sources']['llvm']['commit']:
        raise RuntimeError('LLVM build result does not match the locked source commit')
    steps_path = Path(result['steps']).resolve()
    if steps_path != path.parent / 'steps.json':
        raise RuntimeError('LLVM build steps are not paired with this build result')
    steps = json.loads(steps_path.read_text())
    by_name = {step['name']: step for step in steps}
    required = {'configure', 'build', 'clang-version', 'coverage-feature'}
    required.update('install-' + component for component in LLVM_COMPONENTS)
    if len(by_name) != len(steps) or not required.issubset(by_name):
        raise RuntimeError('LLVM build/install/feature evidence is incomplete')
    for step in steps:
        log = Path(step['log']).resolve()
        if (step.get('exit_code') != 0 or step.get('status') != 'passed'
                or log != path.parent / (step['name'] + '.log') or not log.is_file()):
            raise RuntimeError(f'Unsuccessful or missing LLVM build step: {step["name"]}')
    recorded = set()
    for item in result['artifacts']:
        binary = Path(item['path'])
        if not binary.resolve().is_relative_to(LLVM.resolve()):
            raise RuntimeError('LLVM build result points outside the expected installation')
        if artifact(binary) != item:
            raise RuntimeError(f'Installed LLVM artifact differs from successful build: {binary}')
        recorded.add(binary)
    if not {LLVM / 'bin/clang', LLVM / 'bin/ld.lld'}.issubset(recorded):
        raise RuntimeError('LLVM build result lacks compiler/linker hashes')
    ir_path = path.parent / 'coverage-feature.ll'
    ir = ir_path.read_text()
    for callback in ('__sanitizer_cov_trace_pc_entry', '__sanitizer_cov_trace_pc_exit'):
        if not re.search(r'\bcall\b[^\n]*@' + callback + r'\(', ir):
            raise RuntimeError(f'Coverage feature IR lacks a call to {callback}')
    feature_command = by_name['coverage-feature']['command']
    if (feature_command[0] != str(LLVM / 'bin/clang')
            or '-fsanitize-coverage=trace-pc-entry-exit' not in feature_command):
        raise RuntimeError('Coverage feature check used an unexpected compiler or option')
    return {'build_result': artifact(path), 'steps': artifact(steps_path),
            'coverage_log': artifact(path.parent / 'coverage-feature.log'),
            'coverage_ir': artifact(ir_path),
            'clang_version_log': artifact(path.parent / 'clang-version.log'),
            'step_logs': [artifact(Path(step['log'])) for step in steps]}


def verify_llvm_identity(create=False, build_result=None, replace=False):
    """Check a saved identity, or bootstrap it from a completed build without compiling."""
    identity_path = LLVM / 'build-identity.json'
    if identity_path.is_symlink():
        raise RuntimeError('LLVM build identity must not be a symlink')
    if identity_path.exists() and not replace:
        identity = json.loads(identity_path.read_text())
        if (identity.get('schema_version') != 1
                or identity.get('source_commit') != LOCK['sources']['llvm']['commit']
                or identity.get('installation') != str(LLVM)):
            raise RuntimeError('LLVM build identity does not match the locked installation')
        result_path = Path(identity['evidence']['build_result']['path'])
        if build_result is not None and Path(build_result).resolve() != result_path.resolve():
            raise RuntimeError('Existing LLVM identity refers to a different build result')
        if verify_llvm_build_result(result_path) != identity['evidence']:
            raise RuntimeError('LLVM build evidence changed after identity creation')
        if installed_tools(LLVM) != identity['tools']:
            raise RuntimeError('Installed LLVM tool hashes differ from the saved identity')
        if resource_headers(LLVM) != identity['resource_headers']:
            raise RuntimeError('Installed Clang resource headers differ from the saved identity')
        return identity
    if not create:
        raise RuntimeError('No LLVM build identity; run build-maccconc.py verify-llvm first')
    if build_result is None:
        results = sorted((LAB / 'evidence/k02').glob('llvm-*/build-result.json'))
        if not results:
            raise RuntimeError('No successful LLVM build-result.json; cannot create an identity')
        build_result = results[-1]
    evidence = verify_llvm_build_result(build_result)
    current_tools = installed_tools(LLVM)
    current_headers = resource_headers(LLVM)
    # An old build-result may have hashed only clang/lld. Re-install the existing
    # build outputs into a scratch prefix and compare every required tool. CMake
    # legitimately changes ELF RPATH during install, so raw build/bin hashes are
    # not interchangeable with installed-file hashes. This never invokes a build.
    with tempfile.TemporaryDirectory(prefix='llvm-identity-', dir=LAB / 'build') as temp:
        scratch = Path(temp)
        print('Verifying installed LLVM against existing build outputs; no compilation.', flush=True)
        for component in LLVM_COMPONENTS:
            result = subprocess.run(['cmake', '--install', str(LLVM_BUILD), '--prefix',
                                     str(scratch), '--component', component],
                                    capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(f'Could not verify installed component {component}: {result.stderr}')
        if installed_tools(scratch) != current_tools:
            raise RuntimeError('Installed LLVM tools differ from the successful build outputs')
        if resource_headers(scratch) != current_headers:
            raise RuntimeError('Installed Clang headers differ from the successful build outputs')
    if (verify_llvm_build_result(build_result) != evidence or installed_tools(LLVM) != current_tools
            or resource_headers(LLVM) != current_headers):
        raise RuntimeError('LLVM artifacts changed during identity creation')
    identity = {'schema_version': 1, 'source_commit': LOCK['sources']['llvm']['commit'],
                'installation': str(LLVM),
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'evidence': evidence, 'tools': current_tools, 'resource_headers': current_headers,
                'validation': 'Successful build and feature evidence; scratch component install compared without compilation'}
    with tempfile.NamedTemporaryFile(mode='w', dir=LLVM, prefix='.build-identity-',
                                     suffix='.json', delete=False) as stream:
        json.dump(identity, stream, indent=2)
        stream.write('\n')
        pending = Path(stream.name)
    pending.replace(identity_path)
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['llvm', 'kernel', 'verify-llvm'])
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--llvm-result', type=Path,
                        help='Existing successful build-result.json for verify-llvm; no compilation')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error('jobs must be between 1 and 32')
    if LAB.is_relative_to(REPO) or REPO.is_relative_to(LAB):
        parser.error('LAB_DIR must be outside the delivery repository and its ancestors')
    if args.llvm_result is not None and args.stage != 'verify-llvm':
        parser.error('--llvm-result is only supported with verify-llvm')
    subprocess.run([sys.executable, str(REPO / 'scripts/maccconc-sources.py'),
                    'verify', '--component', 'linux' if args.stage == 'kernel' else 'llvm',
                    '--source-root', str(SRC)], check=True)
    if args.stage == 'verify-llvm':
        identity = verify_llvm_identity(create=True, build_result=args.llvm_result)
        print(json.dumps({'stage': 'verify-llvm', 'identity': str(LLVM / 'build-identity.json'),
                          'source_commit': identity['source_commit'], 'tools_verified': len(identity['tools'])}, indent=2))
        return
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    evidence = LAB / 'evidence/k02' / (args.stage + '-' + stamp)
    evidence.mkdir(parents=True, exist_ok=False)
    steps = []
    env = dict(os.environ)
    env['KCFLAGS'] = LOCK['build']['kernel']['kcflags']

    def save():
        (evidence / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')

    def run(name, argv, cwd=None):
        entry = {'name': name, 'command': [str(x) for x in argv],
                 'cwd': str(cwd or REPO), 'KCFLAGS': env['KCFLAGS'],
                 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'status': 'running', 'log': str(evidence / (name + '.log'))}
        steps.append(entry)
        save()
        print(f'{name}: {entry["log"]}', flush=True)
        with Path(entry['log']).open('w') as log:
            result = subprocess.run(entry['command'], cwd=cwd or REPO, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        entry.update(exit_code=result.returncode, status='passed' if not result.returncode else 'failed',
                     finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        save()
        if result.returncode:
            raise RuntimeError(f'{name} failed; inspect {entry["log"]}')

    if args.stage == 'llvm':
        run('configure', ['cmake', '-S', SRC / 'llvm-project/llvm', '-B', LLVM_BUILD,
            '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG',
            '-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG', '-DLLVM_ENABLE_PROJECTS=clang;lld',
            '-DLLVM_TARGETS_TO_BUILD=X86', '-DLLVM_INCLUDE_TESTS=OFF',
            '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF',
            '-DLLVM_INCLUDE_DOCS=OFF', '-DLLVM_ENABLE_BINDINGS=OFF',
            '-DLLVM_USE_LINKER=lld', '-DLLVM_PARALLEL_LINK_JOBS=1',
            '-DCMAKE_INSTALL_PREFIX=' + str(LLVM)])
        run('build', ['cmake', '--build', LLVM_BUILD, '--parallel', args.jobs, '--target', *LLVM_TARGETS])
        for component in LLVM_COMPONENTS:
            run('install-' + component, ['cmake', '--install', LLVM_BUILD, '--component', component])
        for binary in KERNEL_TOOLS:
            if not (LLVM / 'bin' / binary).is_file():
                raise RuntimeError(f'Missing installed tool: {binary}')
        run('clang-version', [LLVM / 'bin/clang', '--version'])
        probe = evidence / 'coverage-feature.c'
        probe.write_text('int f(int x) { return x + 1; }\n')
        run('coverage-feature', [LLVM / 'bin/clang', '-S', '-emit-llvm', '-O0',
            '-fsanitize-coverage=trace-pc-entry-exit', probe, '-o', evidence / 'coverage-feature.ll'])
        ir = (evidence / 'coverage-feature.ll').read_text()
        if '__sanitizer_cov_trace_pc_entry' not in ir or '__sanitizer_cov_trace_pc_exit' not in ir:
            raise RuntimeError('Pinned entry/exit instrumentation is missing from generated IR')
        artifacts = [LLVM / 'bin' / name for name in KERNEL_TOOLS]
    else:
        identity = verify_llvm_identity()
        (evidence / 'llvm-identity-verified.json').write_text(json.dumps(identity, indent=2)+'\n')
        make = ['make', '-C', SRC / 'linux', 'O=' + str(KERNEL_BUILD),
                'ARCH=x86_64', 'LLVM=' + str(LLVM / 'bin') + '/']
        if not (KERNEL_BUILD / '.config').exists():
            run('defconfig', [*make, 'defconfig'])
            run('kvm-guest-config', [*make, 'kvm_guest.config'])
        fragment = REPO / LOCK['build']['kernel']['fragment']
        run('merge-config', ['bash', SRC / 'linux/scripts/kconfig/merge_config.sh', '-m',
                            '-O', KERNEL_BUILD, KERNEL_BUILD / '.config', fragment], SRC / 'linux')
        run('olddefconfig', [*make, 'olddefconfig'])
        shutil.copy2(KERNEL_BUILD / '.config', evidence / 'effective.config')
        effective = (KERNEL_BUILD / '.config').read_text().splitlines()
        required = [line for line in fragment.read_text().splitlines()
                    if re.match(r'CONFIG_[A-Z0-9_]+=|# CONFIG_[A-Z0-9_]+ is not set$', line)]
        derived = ['CONFIG_KASAN_GENERIC=y', 'CONFIG_KASAN_REPORT_EVERY_ACCESS=y',
                   'CONFIG_FRAME_POINTER=y', 'CONFIG_CC_IS_CLANG=y']
        required.extend(line for line in derived if line not in required)
        missing = [line for line in required if line not in effective]
        (evidence / 'config-check.json').write_text(json.dumps(
            {'required': required, 'derived_dependencies': derived, 'missing': missing}, indent=2))
        if missing:
            raise RuntimeError(f'Required config did not take effect: {missing}')
        # Upstream tracing callbacks are not exported for loadable modules.
        # All tested components and boot drivers are built in; the default
        # make target would also request unrelated modules from defconfig.
        run('build', [*make, '-j' + str(args.jobs), 'bzImage'])
        run('kernelrelease', [*make, '-s', 'kernelrelease'])
        run('vmlinux-sections', [LLVM / 'bin/llvm-readelf', '--sections', '--wide',
                                 KERNEL_BUILD / 'vmlinux'])
        sections = (evidence / 'vmlinux-sections.log').read_text()
        if not all(re.search(r'\s' + re.escape(section) + r'\s', sections)
                   for section in ('.debug_info', '.debug_line')):
            raise RuntimeError('Built vmlinux lacks required debug information sections')
        artifacts = [KERNEL_BUILD / 'arch/x86/boot/bzImage', KERNEL_BUILD / 'vmlinux',
                     KERNEL_BUILD / '.config', KERNEL_BUILD / 'System.map']
        verify_llvm_identity()
    summary = {'stage': args.stage, 'source_commit': LOCK['sources'][args.stage if args.stage == 'llvm' else 'linux']['commit'],
               'artifacts': [artifact(p) for p in artifacts], 'steps': str(evidence / 'steps.json')}
    result_path = evidence / 'build-result.json'
    result_path.write_text(json.dumps(summary, indent=2) + '\n')
    if args.stage == 'llvm':
        verify_llvm_identity(create=True, build_result=result_path, replace=True)
    else:
        summary['llvm_identity'] = artifact(LLVM / 'build-identity.json')
        result_path.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()

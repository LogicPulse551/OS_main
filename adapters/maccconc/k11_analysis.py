"""Build-bound repair analysis using the original raw/control/matching checks.

The requested split/per-role operations are never rewritten. Only an explicitly
verified K11 repair profile selects the actual guarded-RMW/shared-gate contract.
Hashes provide local evidence integrity, not authentication of a remote build.
"""
from __future__ import annotations

import copy
import functools
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

REPO = Path(__file__).resolve().parents[2]
PROFILE_ID = 'kconc.k11.regmap-repair-v1'
SAMPLER_POLICY_ID = 'kconc.k11.sampler-ready-abort-v1'
RECORDER_POLICY_ID = 'kconc.k11.x86-irq-entry-guard-v1'
RECORDER_PATCH = 'patches/maccconc/0005-k11-irq-tail.patch'
RECORDER_BUILDER = 'scripts/build-k11-irqtail-kernel.py'
RECORDER_SOURCES = ('arch/x86/include/asm/idtentry.h', 'include/linux/kcov.h',
                    'include/linux/sched.h', 'kernel/kcov.c')
_SEAL = object()
PINNED = {
    'k08': ('1e9043665ff12a87cb61dbc402e1b9ad3493b7ec962921511c019145e00d517d',
            '433af065cee35d0067bd1d5c7b3cf924d36fa2baca4535fa2be9cdaf817c5636', 'kconc.sampler.build', 'K08'),
    'k10': ('0a6926a7892c0b048387969e37393a4d70411873590f5eb3eb399f40a4647ac1',
            'e4e72bf155f29ae033094a185a7adee4728ea4c7ab1b33ab2177d8503431c00a', 'kconc.executor.control-build', 'K10')}
TEAM_FILES = {'regmap-k07.c': 'scenarios/regmap-k07.c',
              'regmap-k07-cases.h': 'scenarios/regmap-k07-cases.h',
              'kconc-regmap.h': 'kernel/k07/kconc-regmap.h',
              'k11-shared-gate-native.patch': 'adapters/maccconc/k11-shared-gate-native.patch',
              'k11-sampler-control.patch': 'adapters/maccconc/k11-sampler-control.patch'}


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


k09 = _load('k11_k09_analysis', 'k09_analysis.py')
k08, k06, k07, candidates = k09.k08, k09.k06, k09.k08.k07, k09.candidates


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def _file(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Expected an absolute regular evidence file')
    return path.read_bytes()


def apply_file_patch(original, patch, target):
    """Apply exactly one file's unified hunks without fuzzy/context relocation."""
    rows = patch.splitlines(keepends=True)
    wanted = '+++ b/' + target
    starts = [i for i, row in enumerate(rows) if row.rstrip('\n\r') == wanted]
    require(len(starts) == 1, 'Patch must name exactly one expected target: ' + target)
    cursor = starts[0] + 1
    end = next((i for i in range(cursor, len(rows)) if rows[i].startswith(('diff --git ', '--- a/', '--- /dev/null'))), len(rows))
    source = original.splitlines(keepends=True)
    output, consumed, hunks = [], 0, 0
    while cursor < end:
        row = rows[cursor]
        match = re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', row)
        require(match is not None, 'Expected an exact unified hunk')
        start = int(match[1]) - 1
        old_count = int(match[2] or 1)
        new_count = int(match[4] or 1)
        require(consumed <= start <= len(source), 'Overlapping or out-of-range patch hunk')
        output.extend(source[consumed:start]); consumed = start
        cursor += 1; old_seen = new_seen = 0
        while cursor < end and not rows[cursor].startswith('@@ '):
            line = rows[cursor]
            require(line[:1] in (' ', '-', '+'), 'Unsupported unified patch line')
            if line[0] in ' -':
                require(consumed < len(source) and source[consumed] == line[1:], 'Patch context does not match accepted source')
                consumed += 1; old_seen += 1
            if line[0] in ' +':
                output.append(line[1:]); new_seen += 1
            cursor += 1
        require((old_seen, new_seen) == (old_count, new_count), 'Malformed hunk counts')
        hunks += 1
    require(hunks > 0, 'Patch has no implementation hunks')
    output.extend(source[consumed:])
    return ''.join(output)


def _binary_names():
    scenarios = {row['native_so'] for row in candidates.load_catalog()['inputs']}
    return scenarios | {'kcov-sample-k08-ab', 'kcov-sample-k08-ba', 'kcov-execute-k09-ab', 'kcov-execute-k09-ba'}


def _hash_rows(rows, name='name'):
    require(type(rows) is list and all(isinstance(row, dict) and type(row.get(name)) is str
            and candidates._sha(row.get('sha256')) for row in rows), 'Malformed file manifest')
    result = {row[name]: row['sha256'] for row in rows}
    require(len(result) == len(rows), 'Duplicate manifest entry')
    return result


def _native_contract(record):
    require(isinstance(record, dict) and record.get('kind') == 'kconc.regression-native.build'
            and record.get('task') == 'K11' and record.get('profile_id') == PROFILE_ID
            and record.get('passed') is True and type(record.get('exit_code')) is int
            and record['exit_code'] == 0, 'Not a successful K11 native build')
    inputs = record.get('inputs', {})
    require(inputs.get('native_compile_defines') == ['KCONC_K11_SHARED_GATE=1']
            and inputs.get('sampler_control_policy_id') == SAMPLER_POLICY_ID, 'Missing explicit native lock/control profile')
    hashes = _hash_rows(record.get('binaries'))
    require(set(hashes) == _binary_names(), 'K11 requires exactly eighteen native artifacts')
    recompiled = sorted(name for name in hashes if name.startswith('regmap-k07-'))
    require(sorted(record.get('scenario_recompiled', [])) == recompiled
            and record.get('accepted_inputs_modified') is False
            and record.get('executor_recompiled') is False and record.get('sampler_recompiled') is True,
            'Unexpected recompilation or accepted-input mutation')
    for key, (rh, mh, kind, task) in PINNED.items():
        accepted = inputs.get('accepted_' + key, {})
        old = accepted.get('record', {})
        require(accepted.get('result_sha256') == rh and accepted.get('effective_manifest_sha256') == mh
                and old.get('kind') == kind and old.get('task') == task and old.get('passed') is True,
                'Wrong accepted native parent: ' + key)
    copies = inputs.get('copied_binaries')
    copied = _hash_rows(copies)
    samplers = {'kcov-sample-k08-ab', 'kcov-sample-k08-ba'}
    require(set(copied) == set(hashes) - set(recompiled) - samplers, 'Unexpected copied artifact set')
    original_samplers = _hash_rows(inputs['accepted_k08']['record']['binaries'])
    require(hashes['kcov-sample-k08-ab'] == hashes['kcov-sample-k08-ba']
            and all(hashes[name] != original_samplers.get(name) for name in samplers),
            'Sampler is not the new byte-identical pair with the control fix')
    for row in copies:
        parent = 'k10'
        old = _hash_rows(inputs['accepted_' + parent]['record']['binaries'])
        require(row.get('accepted_build') == parent and row['sha256'] == hashes[row['name']] == old.get(row['name']),
                'Copied native bytes differ from the accepted parent')
    team = _hash_rows(inputs.get('team_files'), 'build_copy')
    require(set(team) == set(TEAM_FILES) and all(team[name] == sha((REPO / path).read_bytes()) for name, path in TEAM_FILES.items()),
            'Native inputs differ from the current explicitly registered adapter')
    require(inputs.get('build_script_sha256') == sha((REPO / 'scripts/build-k11-guest.sh').read_bytes()), 'K11 native build script differs')
    return hashes


def verify_native(record, current_hashes, manifest, source_hashes, parentfacts):
    """Validate live native observations; the caller supplies checked file reads.

    parentfacts keys k08/k10 each contain result_sha256,
    effective_manifest_sha256, binaries and source_hashes (name->SHA mappings).
    This function performs no SSH and cannot turn self-reported true into a pass.
    """
    expected = _native_contract(record)
    require(current_hashes == expected, 'Current native binaries differ from the K11 record')
    actual_sources = _hash_rows(manifest, 'path')
    original_sources = _hash_rows(record['inputs']['accepted_k08']['effective_sources'], 'path')
    control_sources = _hash_rows(record['inputs']['accepted_k10']['effective_sources'], 'path')
    require('runner-common.h' in original_sources and 'runner-common.h' in control_sources
            and original_sources['runner-common.h'] != control_sources['runner-common.h'], 'No accepted sampler/control source bridge')
    expected_sources = dict(original_sources, **{'runner-common.h': control_sources['runner-common.h']})
    for name, relative in TEAM_FILES.items():
        data = (REPO / relative).read_bytes()
        if name == 'regmap-k07-cases.h':
            data = apply_file_patch(data.decode(), (REPO / TEAM_FILES['k11-shared-gate-native.patch']).read_text(), name).encode()
        expected_sources[name] = sha(data)
    require(source_hashes == actual_sources == expected_sources, 'Unexpected native source modification or missing file')
    require(isinstance(parentfacts, dict) and set(parentfacts) == set(PINNED), 'Both accepted parents must be observed')
    for key, (rh, mh, _, _) in PINNED.items():
        actual, saved = parentfacts[key], record['inputs']['accepted_' + key]
        require(actual.get('result_sha256') == rh and actual.get('effective_manifest_sha256') == mh
                and actual.get('binaries') == _hash_rows(saved['record']['binaries'])
                and actual.get('source_hashes') == _hash_rows(saved['effective_sources'], 'path'),
                'Accepted parent changed: ' + key)
    return dict(passed=True, binary_count=18, copied_count=12, recompiled_mutex_count=4,
                recompiled_sampler_count=2, sampler_control_policy_id=SAMPLER_POLICY_ID,
                accepted_inputs_modified=False, profile_id=PROFILE_ID)


class VerifiedProfile:
    __slots__ = ('identity', 'family', 'marker', '_seal')

    def __init__(self, identity, marker, seal=None):
        require(seal is _SEAL, 'Repair profiles must be created by verify_profile')
        self.identity, self.family, self.marker, self._seal = identity, identity['family'], marker, seal


def verify_recorder_contract(kernel, team):
    """Bind the named recorder policy; live file checking remains in the runtime.

    The exact kernel-record hash in the profile binds these four source hashes.
    Old fixed-01 records have no policy metadata and retain their old meaning;
    an unknown or partially declared new policy is never treated as legacy.
    """
    keys = {'recorder_policy_id', 'recorder_patch', 'recorder_sources', 'parent_control_sha256'}
    if not any(key in kernel for key in keys):
        return None
    require(keys <= set(kernel) and kernel['recorder_policy_id'] == RECORDER_POLICY_ID,
            'Unknown or incomplete recorder policy')
    patch_sha = sha((REPO / RECORDER_PATCH).read_bytes())
    require(kernel['recorder_patch'] == dict(path=RECORDER_PATCH, sha256=patch_sha)
            and team.get(RECORDER_PATCH) == patch_sha, 'Recorder patch is not the registered implementation')
    require(kernel.get('build_script_path') == RECORDER_BUILDER
            and kernel.get('build_script_sha256') == team.get(RECORDER_BUILDER) == sha((REPO / RECORDER_BUILDER).read_bytes()),
            'Recorder builder does not bind the declared source reconstruction')
    source = kernel.get('source')
    require(type(source) is str and PurePosixPath(source).is_absolute()
            and str(PurePosixPath(source)) == source and '..' not in PurePosixPath(source).parts,
            'Recorder source root is not an exact absolute Linux path')
    sources = _hash_rows(kernel['recorder_sources'], 'path')
    require(set(sources) == {str(PurePosixPath(source) / name) for name in RECORDER_SOURCES},
            'Recorder must bind exactly the four implementation source files')
    require(candidates._sha(kernel['parent_control_sha256'])
            and kernel.get('patched_kcov_sha256') == sources[source + '/kernel/kcov.c']
            and kernel['patched_kcov_sha256'] != kernel['parent_control_sha256'],
            'Recorder kernel source did not change from its accepted parent')
    return dict(policy_id=RECORDER_POLICY_ID, patch_sha256=patch_sha,
                sources={name: sources[source + '/' + name] for name in RECORDER_SOURCES})


def verify_profile(binding):
    require(isinstance(binding, dict) and set(binding) == {'profile_id', 'family', 'kernel_record', 'native_record', 'repaired_driver'}
            and binding['profile_id'] == PROFILE_ID and binding['family'] in ('rmw', 'mutex'), 'Invalid repair binding')
    data = {}
    for key in ('kernel_record', 'native_record', 'repaired_driver'):
        item = binding[key]
        require(isinstance(item, dict) and set(item) == {'path', 'sha256'} and candidates._sha(item['sha256']), 'Malformed repair evidence reference')
        data[key] = _file(item['path'])
        require(sha(data[key]) == item['sha256'], 'Changed repair evidence: ' + key)
    kernel = k06._json(data['kernel_record'].decode())
    native = k06._json(data['native_record'].decode())
    family = binding['family']
    require(isinstance(kernel, dict) and kernel.get('kind') == 'kconc.repaired-kernel.build'
            and kernel.get('task') == 'K11' and kernel.get('profile_id') == PROFILE_ID
            and kernel.get('family') == family and kernel.get('passed') is True, 'Not the bound repaired kernel')
    patch_name = f'patches/maccconc/0004-k11-{family}-repair.patch'
    patch = (REPO / patch_name).read_bytes()
    require(kernel.get('repair_patch') == dict(path=patch_name, sha256=sha(patch)), 'Unregistered kernel repair patch')
    baseline = REPO / ('kernel/k06/kconc-regmap.c' if family == 'rmw' else 'kernel/k07/kconc-regmap.c')
    expected = apply_file_patch(baseline.read_text(), patch.decode(), 'drivers/base/regmap/kconc-regmap.c').encode()
    driver_hash = sha(expected)
    require(data['repaired_driver'] == expected and kernel.get('repaired_driver', {}).get('sha256') == driver_hash,
            'Built driver does not equal the accepted source plus declared repair')
    sources = _hash_rows(kernel.get('regmap_sources'), 'path')
    require(sources.get(kernel['repaired_driver']['path']) == driver_hash, 'Driver is not included in built source evidence')
    team = _hash_rows(kernel.get('team_inputs'), 'path')
    require(patch_name in team and team[patch_name] == sha(patch)
            and all((REPO / path).is_file() and sha((REPO / path).read_bytes()) == wanted for path, wanted in team.items()),
            'Kernel team inputs changed after build')
    verify_recorder_contract(kernel, team)
    _native_contract(native)
    lines = expected.decode().splitlines()
    stores = [i for i, line in enumerate(lines, 1) if 'WRITE_ONCE(role->checkpoint, epoch);' in line]
    require(len(stores) == 1, 'Repaired driver has no unique declared checkpoint')
    identity = dict(profile_id=PROFILE_ID, family=family,
                    kernel_record_sha256=binding['kernel_record']['sha256'], native_record_sha256=binding['native_record']['sha256'],
                    driver_sha256=driver_hash, repair_patch_sha256=sha(patch))
    marker = dict(file='drivers/base/regmap/kconc-regmap.c', symbol='kconc_regmap_checkpoint', line=stores[0], source_sha256=driver_hash)
    return VerifiedProfile(identity, marker, _SEAL)


class _Oracle:
    def __init__(self, original):
        self._original = original
        self.check_observation = functools.partial(original.check_observation, effective_shared_gate=True)
        self.validate_round = functools.partial(original.validate_round, effective_shared_gate=True)

    def __getattr__(self, name):
        return getattr(self._original, name)


class _Backend:
    def __init__(self, profile):
        self._profile = profile
        self._base = k08.FAMILIES[profile.family]
        self.oracle = self._base.oracle if profile.family == 'rmw' else _Oracle(self._base.oracle)

    def __getattr__(self, name):
        return getattr(self._base, name)

    def phase_checks(self, rows):
        if self._profile.family == 'rmw':
            return self._base.phase_checks(rows)
        return self._base.phase_checks(rows, observation_checker=self.oracle.check_observation, round_validator=self.oracle.validate_round)

    def inspect_trace(self, trace, mapping, replay, mode_or_entered):
        extra = dict(declared_marker=self._profile.marker)
        if self._profile.family == 'rmw':
            extra['guarded_split'] = True
        return self._base.inspect_trace(trace, mapping, replay, mode_or_entered, **extra)


def _profile(profile, family):
    require(isinstance(profile, VerifiedProfile) and profile._seal is _SEAL and profile.family == family,
            'Analysis requires a verified matching repair profile')
    require(profile.identity['driver_sha256'] == profile.marker['source_sha256'], 'Repair marker identity changed')
    return _Backend(profile)


def _annotate(result, profile):
    result['repair_profile'] = copy.deepcopy(profile.identity)
    result['artifacts']['k11_analysis_sha256'] = sha(Path(__file__).read_bytes())
    result['scope'] = 'One declared operation on the bound repaired regmap caller; finite observed schedules only, no original-path equality or general correctness claim'
    return result


def analyze_sample(trace, mapping, guest, family, order, profile):
    backend = _profile(profile, family)
    return _annotate(k08.analyze(trace, mapping, guest, family, order, backend=backend), profile)


def schedule_checks(rows, family, order):
    """Check the observed handoff without assuming that the repair worked.

    Actual WAKE/WAIT, target and prefix checks remain in the inherited analyzer.
    Final register values and exclusion are the independent property oracle's
    job; requiring them here would hide a regression as a candidate miss.
    """
    first, peer = (0, 1) if order == 'ab' else (1, 0)
    setup, _, operations, prop, _ = rows
    if family == 'mutex':
        events = prop['final']['events'][:prop['final']['event_count']]
        observed = [(e['role'], e['kind'], e['depth']) for e in events]
        entered = operations['results'][peer]['result']['outcome'] == 1
        expected = ([(first, 1, 1), (peer, 1, 2), (peer, 2, 1), (first, 2, 0)]
                    if entered else [(first, 1, 1), (peer, 3, 1), (first, 2, 0)])
        return dict(observed_boundaries_match_handoff=observed == expected)
    return dict(both_requested_operations_completed=k06._equal_int(prop.get('completed_mask'), 3)
                and k06._equal_int(prop.get('active'), 0))


def analyze_execution(trace, mapping, guest, candidate, profile):
    family = candidate.get('identity', {}).get('input', {}).get('family')
    backend = _profile(profile, family)
    def validate(value):
        candidates.validate_candidate(value)
        require(value['identity']['build_identity'].get('repair_profile') == profile.identity,
                'Candidate belongs to another build; old positions are mapping-invalid')
    result = k09.analyze(trace, mapping, guest, candidate, backend=backend,
                         schedule_checker=schedule_checks, candidate_validator=validate)
    return _annotate(result, profile)

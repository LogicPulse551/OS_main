"""Validate task inputs before execution so configuration errors are caught early.

Keeping validation offline lets users inspect a task while its VM is stopped.
The operation catalog and field checks share one definition across CLI commands.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any


MAX_MANIFEST_BYTES = 64 * 1024

CATALOG = {
    "env.status": {
        "supported": True, "project_task": "R00",
        "scope": "Current VM state only; not KCOV, ABI, or VSOCK verification.",
    },
    "env.check": {
        "supported": True, "project_task": "K02",
        "scope": "Existing K02 runtime probes; no concurrent kernel scenario.",
    },
    "build.identity": {
        "supported": True, "project_task": "K03",
        "scope": "Current K03 kernel and guest build identity; not correctness proof.",
    },
    "k03.record": {
        "supported": True, "project_task": "K03",
        "scope": "Fixed upstream dup/close sample and all observed A-B-A candidates.",
    },
    "k03.bind": {
        "supported": True, "project_task": "K03",
        "scope": "Bind the fixed sample's saved control plan before reexecution.",
    },
    "k03.replay": {
        "supported": True, "project_task": "K03",
        "scope": "Actual saved-plan reexecution of the fixed sample; not K10 stability.",
    },
    "k03.view": {
        "supported": True, "project_task": "K03",
        "scope": "Send archived trace to the existing GUI; not actual reexecution.",
    },
    "result.read": {
        "supported": True, "project_task": "F03",
        "scope": "Read historical results; no current runtime or correctness validation.",
    },
    "report.trace": {
        "supported": True, "project_task": "I02",
        "scope": "Offline source-linked report of an archived regmap fixture run and its historical replay evidence.",
    },
    "optimize.bma400": {
        "supported": True, "project_task": "C07",
        "scope": "Generate and check the scoped six-byte regmap source package, preserving the original on rejection.",
    },
    "demo.review": {
        "supported": True, "project_task": "C07",
        "scope": "Validate a saved competition demo and render its kernel traces, repair, proof and paired measurements offline.",
    },
    "runtime.initialize": {
        "supported": True, "project_task": "K04",
        "scope": "Register the current fixed lifecycle runtime after identity and health checks.",
    },
    "runtime.status": {
        "supported": True, "project_task": "K04",
        "scope": "Inspect lifecycle state; observation does not clear a recovery requirement.",
    },
    "runtime.recover": {
        "supported": True, "project_task": "K04",
        "scope": "Recover the registered experimental guest and recheck identity before another round.",
    },
    "scenario.run": {
        "supported": True, "project_task": "K04",
        "scope": "One saved-plan dup/close lifecycle round; not regmap or general kernel checking.",
    },
    "scenario.cancel": {
        "supported": True, "project_task": "K04",
        "scope": "Request cancellation of the identified active round; cancellation does not imply recovery.",
    },
    "kernel.check": {
        "supported": False, "project_task": "K09",
        "scope": "General kernel scenario checking is not connected yet.",
    },
    "kernel.regress": {
        "supported": False, "project_task": "K11",
        "scope": "Cross-build repair regression is not connected yet.",
    },
    "optimize": {
        "supported": False, "project_task": "O06",
        "scope": "The planned A-E optimization packages are not connected yet.",
    },
    "proof.check": {
        "supported": False, "project_task": "O02/O03",
        "scope": "Optimization proof artifacts are not connected yet.",
    },
    "performance.measure": {
        "supported": False, "project_task": "V02",
        "scope": "Comparable performance workloads and measurement are not connected yet.",
    },
}

LIFECYCLE_OPERATIONS = frozenset({"runtime.initialize", "runtime.status", "runtime.recover",
                                  "scenario.run", "scenario.cancel"})
REGMAP_OPERATIONS = frozenset({'regmap.initialize', 'regmap.status', 'regmap.recover',
    'regmap.baseline', 'regmap.fault-reset', 'regmap.record', 'regmap.replay', 'regmap.setup-fault'})
for _operation in REGMAP_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K05',
        'scope': 'Fixed real regmap entry and reset validation; no general bug search or K10 stability.'}
RMW_CASES = frozenset({'disjoint-bits', 'overlap-bits', 'different-registers', 'zero-mask', 'high-bits'})
RMW_MODES = frozenset({'split', 'update-bits'})
RMW_OPERATIONS = frozenset({'rmw.initialize', 'rmw.status', 'rmw.recover',
    'rmw.matrix', 'rmw.record', 'rmw.replay'})
for _operation in RMW_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K06',
        'scope': 'Constructed real regmap masked-update contrasts; bounded final-state oracle, not general search or K10 stability.'}
MUTEX_CASES = frozenset({'different-registers', 'shared-register'})
MUTEX_MODES = frozenset({'shared', 'per-role'})
MUTEX_OPERATIONS = frozenset({'mutex.initialize', 'mutex.status', 'mutex.recover',
    'mutex.matrix', 'mutex.record', 'mutex.replay'})
for _operation in MUTEX_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K07',
        'scope': 'Real regmap caller critical-region protocol; nonblocking admission and interval oracle, not general search or K10 stability.'}
SAMPLE_OPERATIONS = frozenset({'sample.initialize', 'sample.status', 'sample.recover', 'sample.run'})
for _operation in SAMPLE_OPERATIONS | {'candidate.export'}:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K08',
        'scope': 'Finite AB/BA serial samples and exact-identity ABA/BAB candidates; candidates unexecuted, unseen branches unknown.'}
SEARCH_OPERATIONS = frozenset({'search.initialize', 'search.status', 'search.recover', 'kernel.check'})
for _operation in SEARCH_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K09',
        'scope': 'Bounded FIFO execution of validated K08 regmap marker candidates; full structural prefix, target and handoff checked; no exhaustive coverage or K10 stability.'}
REPLAY_OPERATIONS = frozenset({'replay.initialize', 'replay.status', 'replay.recover', 'replay.bind', 'replay.run'})
for _operation in REPLAY_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K10',
        'scope': 'Original-build replay bundle and actual key-path matching of fixed regmap witnesses; all attempts retained, stability assessed separately from batch completion.'}
_TOP_LEVEL = {"schema_version", "operation", "name", "runtime", "inputs", "scenario"}
REGRESSION_OPERATIONS = frozenset({'regression.initialize', 'regression.status', 'regression.recover', 'kernel.regress'})
for _operation in REGRESSION_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K11',
        'scope': 'Fresh build-bound regmap candidates for the original logical inputs and property; old locations are never replayed across builds; bounded repair regression only.'}
_HOST_RUNTIME_PATHS = {"lab_dir", "build_lab", "kernel_build"}
_GUEST_RUNTIME_PATHS = {"probe_guest_build", "scenario_guest_build", "lifecycle_guest_build", "regmap_guest_build", "rmw_guest_build", "mutex_guest_build", "sample_guest_build", "search_guest_build"}
_RUNTIME_KEYS = _HOST_RUNTIME_PATHS | _GUEST_RUNTIME_PATHS | {"ssh_port"}
_INPUT_KEYS = {
    "result.read": {"result"},
    "report.trace": {"bundle", "source_root", "build_record"},
    "optimize.bma400": {"kernel_tree", "config", "clang", "compcert", "coq_bin"},
    "demo.review": {"bundle"},
    "k03.bind": {"record", "source_mapper"},
    "k03.replay": {"binding", "source_mapper"},
    "k03.view": {"trace"},
    "scenario.run": {"plan"},
}
_VM_RUNTIME = {"lab_dir", "ssh_port"}
for _operation in ('artifact.check', 'artifact.loaded'):
    CATALOG[_operation] = {'supported': True, 'project_task': 'I01',
        'scope': 'Content-bound build/config identity; loaded additionally checks a running local VM. No optimization correctness or speedup claim.'}
    _INPUT_KEYS[_operation] = {'identity'}
_KERNEL_RUNTIME = _VM_RUNTIME | {"build_lab", "kernel_build"}
_LIFECYCLE_RUNTIME = _KERNEL_RUNTIME | {"scenario_guest_build", "lifecycle_guest_build"}
_REQUIRED_RUNTIME = {
    "artifact.loaded": _VM_RUNTIME,
    "env.status": _VM_RUNTIME,
    "env.check": _KERNEL_RUNTIME | {"probe_guest_build"},
    "build.identity": _KERNEL_RUNTIME | {"scenario_guest_build"},
    "k03.record": _KERNEL_RUNTIME | {"scenario_guest_build"},
    "k03.bind": _KERNEL_RUNTIME | {"scenario_guest_build"},
    "k03.replay": _KERNEL_RUNTIME | {"scenario_guest_build"},
    "k03.view": _VM_RUNTIME,
    "runtime.initialize": _LIFECYCLE_RUNTIME,
    "runtime.status": _VM_RUNTIME,
    "runtime.recover": _LIFECYCLE_RUNTIME,
    "scenario.run": _LIFECYCLE_RUNTIME,
    "scenario.cancel": _VM_RUNTIME,
}
for _operation in REGMAP_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _KERNEL_RUNTIME | {'scenario_guest_build', 'regmap_guest_build'}
_INPUT_KEYS['regmap.record'] = {'source_mapper'}
_INPUT_KEYS['regmap.replay'] = {'binding', 'source_mapper'}
_INPUT_KEYS['regmap.setup-fault'] = {'source_mapper'}
for _operation in RMW_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _KERNEL_RUNTIME | {'scenario_guest_build', 'rmw_guest_build'}
_INPUT_KEYS['rmw.record'] = {'source_mapper'}
_INPUT_KEYS['rmw.replay'] = {'binding', 'source_mapper'}
for _operation in MUTEX_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _KERNEL_RUNTIME | {'scenario_guest_build', 'mutex_guest_build'}
_INPUT_KEYS['mutex.record'] = {'source_mapper'}
_INPUT_KEYS['mutex.replay'] = {'binding', 'source_mapper'}
for _operation in SAMPLE_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _KERNEL_RUNTIME | {'scenario_guest_build', 'sample_guest_build'}
_INPUT_KEYS['sample.run'] = {'source_mapper'}
_INPUT_KEYS['candidate.export'] = {'samples'}
for _operation in SEARCH_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _KERNEL_RUNTIME | {'scenario_guest_build', 'sample_guest_build', 'search_guest_build'}
_INPUT_KEYS['kernel.check'] = {'pool', 'source_mapper'}
for _operation in REPLAY_OPERATIONS - {'replay.bind'}:
    _REQUIRED_RUNTIME[_operation] = _REQUIRED_RUNTIME['kernel.check']
_INPUT_KEYS['replay.bind'] = {'attempt'}
_INPUT_KEYS['replay.run'] = {'bundle', 'source_mapper'}
for _operation in REGRESSION_OPERATIONS:
    _REQUIRED_RUNTIME[_operation] = _REQUIRED_RUNTIME['kernel.check']
_INPUT_KEYS['kernel.regress'] = {'bundle', 'source_mapper'}
FEEDBACK_OPERATIONS = frozenset({'feedback.initialize', 'feedback.status', 'feedback.recover', 'kernel.explore'})
for _operation in FEEDBACK_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K12',
        'scope': 'Bounded regmap candidate scheduling with optional feedback, rotation and explicit pool/input/attempt budgets; no coverage or performance guarantee.'}
    _REQUIRED_RUNTIME[_operation] = _REQUIRED_RUNTIME['kernel.check']
_INPUT_KEYS['kernel.explore'] = {'samples', 'history', 'source_mapper'}
REDUCTION_OPERATIONS = frozenset({'reduction.initialize', 'reduction.status', 'reduction.recover', 'kernel.reduce'})
for _operation in REDUCTION_OPERATIONS:
    CATALOG[_operation] = {'supported': True, 'project_task': 'K13',
        'scope': 'Finite registered bit-effect and preemption deletions, with actual replay, explicit rejection and complete attempt retention; no minimum or root-cause proof.'}
    _REQUIRED_RUNTIME[_operation] = _REQUIRED_RUNTIME['kernel.check']
_INPUT_KEYS['kernel.reduce'] = {'bundle', 'source_mapper'}


class ManifestError(ValueError):
    """A stable error code and a human-readable reason for rejecting a manifest."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _invalid(message: str) -> None:
    raise ManifestError("invalid_manifest", message)


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        _invalid(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        _invalid(f"{label} keys must be strings")
    return value


def _unknown_keys(value: dict, allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        _invalid(f"Unknown {label} fields: {', '.join(sorted(unknown))}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _invalid(f"{label} must be a nonempty string without NUL characters")
    return value


def _host_path(value: Any, base: Path, label: str) -> str:
    text = _string(value, label)
    try:
        path = Path(text).expanduser()
        if not path.is_absolute():
            path = base / path
        # strict=False normalizes names without requiring referenced files.
        return str(path.resolve(strict=False))
    except (OSError, RuntimeError, ValueError) as error:
        _invalid(f"{label} is not a usable host path: {error}")


def _guest_path(value: Any, label: str) -> str:
    text = _string(value, label)
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts:
        _invalid(f"{label} must be an absolute POSIX guest path without '..'")
    if label == "runtime.scenario_guest_build":
        root = PurePosixPath("/home/lab/k03")
        if path == root or not path.is_relative_to(root):
            _invalid("runtime.scenario_guest_build must be below /home/lab/k03")
    if label == "runtime.lifecycle_guest_build":
        root = PurePosixPath("/home/lab/k04")
        if path == root or not path.is_relative_to(root):
            _invalid("runtime.lifecycle_guest_build must be below /home/lab/k04/build-*")
        first = path.relative_to(root).parts[0]
        if not first.startswith("build-") or len(first) == len("build-"):
            _invalid("runtime.lifecycle_guest_build must be below /home/lab/k04/build-*")
    if label == 'runtime.regmap_guest_build':
        if path.parent != PurePosixPath('/home/lab/k05') or re.fullmatch(r'build-[A-Za-z0-9._-]+', path.name) is None:
            _invalid('runtime.regmap_guest_build must be /home/lab/k05/build-*')
    if label == 'runtime.rmw_guest_build':
        if path.parent != PurePosixPath('/home/lab/k06') or re.fullmatch(r'build-[A-Za-z0-9._-]+', path.name) is None:
            _invalid('runtime.rmw_guest_build must be /home/lab/k06/build-*')
    if label == 'runtime.mutex_guest_build':
        if path.parent != PurePosixPath('/home/lab/k07') or re.fullmatch(r'build-[A-Za-z0-9._-]+', path.name) is None:
            _invalid('runtime.mutex_guest_build must be /home/lab/k07/build-*')
    if label == 'runtime.sample_guest_build':
        if path.parent not in {PurePosixPath('/home/lab/k08'), PurePosixPath('/home/lab/k11')} or re.fullmatch(r'build-[A-Za-z0-9._-]+', path.name) is None:
            _invalid('runtime.sample_guest_build must be /home/lab/k08/build-* or /home/lab/k11/build-*')
    if label == 'runtime.search_guest_build':
        parents = {PurePosixPath('/home/lab/k09'), PurePosixPath('/home/lab/k10-control'), PurePosixPath('/home/lab/k11')}
        if path.parent not in parents or re.fullmatch(r'build-[A-Za-z0-9._-]+', path.name) is None:
            _invalid('runtime.search_guest_build must be /home/lab/k09/build-* or /home/lab/k10-control/build-*')
    return str(path)


def _scenario(obj: dict, operation: str) -> dict | None:
    if operation == 'kernel.reduce':
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'max_trials', 'replay_repetitions'}:
            _invalid('Reduction requires exactly max_trials and replay_repetitions')
        for key, low, high in [('max_trials', 0, 64), ('replay_repetitions', 1, 5)]:
            if type(value[key]) is not int or not low <= value[key] <= high:
                _invalid(key + ' is outside the finite reduction budget')
        return dict(value)
    if operation == 'kernel.explore':
        value = _object(obj.get('scenario'), 'scenario')
        fields = {'family', 'total_budget', 'pool_limit', 'per_input_budget', 'feedback', 'rotation_interval'}
        if set(value) != fields or value['family'] not in ('rmw', 'mutex') or type(value['feedback']) is not bool:
            _invalid('Explore requires family, feedback and three explicit budgets plus rotation_interval')
        for key in ('total_budget', 'pool_limit', 'per_input_budget'):
            if type(value[key]) is not int or not 0 <= value[key] <= 4096:
                _invalid(key + ' must be an integer from 0 to 4096')
        if type(value['rotation_interval']) is not int or not 1 <= value['rotation_interval'] <= 4096:
            _invalid('rotation_interval must be an integer from 1 to 4096')
        return dict(value)
    if operation in {'replay.run', 'kernel.regress'}:
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'repetitions'} or type(value['repetitions']) is not int or not 1 <= value['repetitions'] <= 1000:
            _invalid('Replay requires exactly repetitions, an integer from 1 to 1000')
        return dict(value)
    if operation == 'kernel.check':
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'family', 'max_candidates'}:
            _invalid('Kernel check requires exactly family and max_candidates')
        if not isinstance(value['family'], str) or value['family'] not in {'rmw', 'mutex'}:
            _invalid('Kernel check family must be rmw or mutex')
        if type(value['max_candidates']) is not int or not 0 <= value['max_candidates'] <= 4096:
            _invalid('max_candidates must be an integer from 0 to 4096')
        return dict(value)
    if operation == 'sample.run':
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'family', 'case_id', 'mode', 'order'}:
            _invalid('Sample scenario requires exactly family, case_id, mode, order')
        if any(not isinstance(v, str) for v in value.values()):
            _invalid('Sample scenario fields must be strings')
        families = {'rmw': (RMW_CASES, RMW_MODES), 'mutex': (MUTEX_CASES, MUTEX_MODES)}
        if value['family'] not in families or value['order'] not in {'ab', 'ba'}:
            _invalid('Unknown fixed sample family or order')
        cases, modes = families[value['family']]
        if value['case_id'] not in cases or value['mode'] not in modes:
            _invalid('Unknown finite input or mode')
        return dict(value)
    if operation in {'mutex.record', 'mutex.replay'}:
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'id', 'case_id', 'mode'}:
            _invalid('Mutex scenario requires exactly id, case_id, mode')
        if value['id'] != 'regmap-mutex-v1' or not isinstance(value['case_id'], str) or value['case_id'] not in MUTEX_CASES:
            _invalid('Unknown fixed mutex scenario or case')
        if not isinstance(value['mode'], str) or value['mode'] not in MUTEX_MODES:
            _invalid('Mutex mode must be shared or per-role')
        return dict(value)
    if operation in {'rmw.record', 'rmw.replay'}:
        value = _object(obj.get('scenario'), 'scenario')
        if set(value) != {'id', 'case_id', 'mode'}:
            _invalid('RMW scenario requires exactly id, case_id, mode')
        if value['id'] != 'regmap-rmw-v1' or not isinstance(value['case_id'], str) or value['case_id'] not in RMW_CASES:
            _invalid('Unknown fixed RMW scenario or case')
        if not isinstance(value['mode'], str) or value['mode'] not in RMW_MODES:
            _invalid('RMW mode must be split or update-bits')
        return dict(value)
    if operation == "scenario.run":
        value = _object(obj.get("scenario", {}), "scenario")
        _unknown_keys(value, {"id", "fault", "timeout_seconds"}, "scenario")
        result = {"id": "dup-close-v1", "fault": "none", "timeout_seconds": 30, **value}
        if result["id"] != "dup-close-v1":
            _invalid("scenario.id must be dup-close-v1")
        if not isinstance(result["fault"], str) or result["fault"] not in {"none", "setup", "hang", "cleanup", "property"}:
            _invalid("scenario.fault must be a known infrastructure fault mode")
        if type(result["timeout_seconds"]) is not int or not 1 <= result["timeout_seconds"] <= 120:
            _invalid("scenario.timeout_seconds must be an integer from 1 to 120")
        return result
    if operation == "scenario.cancel":
        value = _object(obj.get("scenario"), "scenario")
        _unknown_keys(value, {"run_id"}, "scenario")
        run_id = value.get("run_id")
        if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
            _invalid("scenario.run_id must be 32 lower-case hexadecimal characters")
        return {"run_id": run_id}
    if "scenario" in obj:
        _invalid("scenario is only permitted for scenario.run or scenario.cancel")
    return None


def normalize_manifest(obj: Any, base: Path) -> dict:
    """Validate a manifest and resolve its host paths relative to ``base``.

    Runtime fields may form a shared profile, but no unknown field is accepted.
    Unsupported catalog operations still normalize, so the caller can return a
    distinct unsupported result rather than pretending to execute them.
    """
    obj = _object(obj, "manifest")
    _unknown_keys(obj, _TOP_LEVEL, "manifest")
    if type(obj.get("schema_version")) is not int or obj["schema_version"] != 1:
        _invalid("schema_version must be the integer 1")
    operation = obj.get("operation")
    if not isinstance(operation, str) or operation not in CATALOG:
        _invalid("operation must name an operation in the command catalog")
    scenario = _scenario(obj, operation)
    if "name" in obj:
        if not isinstance(obj["name"], str) or len(obj["name"]) > 100:
            _invalid("name must be a string of at most 100 characters")
    runtime = _object(obj.get("runtime", {}), "runtime")
    inputs = _object(obj.get("inputs", {}), "inputs")
    _unknown_keys(runtime, _RUNTIME_KEYS, "runtime")
    allowed_inputs = _INPUT_KEYS.get(operation, set())
    optional_inputs = {"report.trace": {"attempt"}, "optimize.bma400": {"expect_certificate"}}.get(operation, set())
    _unknown_keys(inputs, allowed_inputs | optional_inputs, "inputs")
    missing_runtime = _REQUIRED_RUNTIME.get(operation, set()) - runtime.keys()
    if missing_runtime:
        _invalid(f"Missing runtime fields for {operation}: {', '.join(sorted(missing_runtime))}")
    missing_inputs = allowed_inputs - inputs.keys()
    if missing_inputs:
        _invalid(f"Missing inputs for {operation}: {', '.join(sorted(missing_inputs))}")
    try:
        base = Path(base).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        _invalid(f"Invalid manifest base directory: {error}")
    normalized_runtime = {}
    for key, value in runtime.items():
        if key in _HOST_RUNTIME_PATHS:
            normalized_runtime[key] = _host_path(value, base, "runtime." + key)
        elif key in _GUEST_RUNTIME_PATHS:
            normalized_runtime[key] = _guest_path(value, "runtime." + key)
        else:
            if type(value) is not int or not 1 <= value <= 65535:
                _invalid("runtime.ssh_port must be an integer between 1 and 65535")
            normalized_runtime[key] = value
    normalized = {
        "schema_version": 1,
        "operation": operation,
        "runtime": normalized_runtime,
        "inputs": {key: _host_path(value, base, "inputs." + key) for key, value in inputs.items()},
    }
    if "name" in obj:
        normalized["name"] = obj["name"]
    if scenario is not None:
        normalized["scenario"] = scenario
    return normalized


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            _invalid(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    _invalid(f"Non-finite JSON number is not permitted: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _invalid(f"Non-finite JSON number is not permitted: {value}")
    return parsed


def load_manifest(path: str | Path) -> dict:
    """Read at most 64 KiB of strict UTF-8 JSON and normalize its inputs."""
    try:
        path = Path(path).expanduser().resolve(strict=False)
        # A bounded read still blocks on a FIFO before it can reach the limit.
        if not path.is_file():
            raise ManifestError("manifest_read_error", "Manifest path must identify a regular file")
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ManifestError("manifest_read_error", "Manifest path must identify a regular file")
            if info.st_size > MAX_MANIFEST_BYTES:
                _invalid("Manifest exceeds the 64 KiB limit")
            data = stream.read(MAX_MANIFEST_BYTES + 1)
    except ManifestError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise ManifestError("manifest_read_error", f"Cannot read manifest: {error}") from error
    if len(data) > MAX_MANIFEST_BYTES:
        _invalid("Manifest exceeds the 64 KiB limit")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant, parse_float=_finite_float)
    except ManifestError:
        raise
    except (ValueError, RecursionError) as error:
        raise ManifestError("invalid_manifest", f"Manifest is not valid UTF-8 JSON: {error}") from error
    return normalize_manifest(obj, path.parent)

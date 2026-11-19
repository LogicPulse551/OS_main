"""Recheck accepted K10 evidence with its exact adapter revision, read-only.

Adapter source digests are part of the K10 report. A new analyzer must not silently
rewrite those digests to make an old witness validate. The archived code executes
only the offline bundle reader; it never starts a guest or changes the reference.
"""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import os
import subprocess
import tarfile

from .lifecycle import REPO, digest, persist, fail

REFERENCE_COMMIT = '14e0945f58280a2f18f88031cc848676c1f6a1b9'
# These 14 archived files were also checked against K11's original code digests.
PACKAGED_REFERENCE_SHA256 = 'ed39dcaede5186a8c9b9b2c06ff998400453840b33e87f5c94b174240002cec7'


def _reference_archive(output):
    command = ['git', '-C', str(REPO), 'archive', '--format=tar', REFERENCE_COMMIT]
    try:
        archive = subprocess.run(command, capture_output=True, check=False)
    except FileNotFoundError as error:
        (output/'reference-archive.stderr').write_text(str(error), encoding='utf-8')
    else:
        (output/'reference-archive.stderr').write_bytes(archive.stderr)
        if archive.returncode == 0:
            return archive.stdout, 'git-archive'

    # Squashed releases carry only the inputs used by the historical offline reader.
    packaged = Path(__file__).with_name('offline-reference.tar.gz')
    if not packaged.is_file():
        fail('reference_revision_unavailable', 'The accepted K10 offline verifier is required')
    data = packaged.read_bytes()
    if hashlib.sha256(data).hexdigest() != PACKAGED_REFERENCE_SHA256:
        fail('invalid_reference_archive', 'Packaged K10 verifier SHA-256 mismatch')
    return data, 'packaged-offline-files'


def load_reference(bundle, output):
    output = Path(output)
    root = output/'reference-code'
    if root.exists():
        fail('reference_code_exists', 'Reference verifier output must be fresh')
    archive, archive_source = _reference_archive(output)
    root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:*') as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                fail('invalid_reference_archive', 'Unexpected archive entry')
            target = root.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as dest:
                    dest.write(stream.extractfile(member).read())
    verifier = """import json,sys
from kconc.replay_bundle import load_bundle
value=load_bundle(sys.argv[1])
print(json.dumps(value,ensure_ascii=False))
"""
    script = output/'reference-validator.py'
    script.write_text(verifier, encoding='utf-8')
    env = dict(os.environ, PYTHONPATH=str(root/'src'), PYTHONDONTWRITEBYTECODE='1')
    import sys
    command = [sys.executable, '-B', str(script), str(Path(bundle).resolve())]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=180)
    (output/'reference-validation.stdout').write_bytes(result.stdout)
    (output/'reference-validation.stderr').write_bytes(result.stderr)
    record = dict(commit=REFERENCE_COMMIT, archive_source=archive_source, command=command, exit_code=result.returncode,
        passed=result.returncode == 0, code_files={str(p.relative_to(root)):digest(p)
            for p in sorted(root.rglob('*')) if p.is_file()},
        validator_sha256=digest(script), original_evidence_modified=False,
        scope='Exact accepted offline verifier; no original-build or cross-build guest execution')
    persist(output/'reference-validation.json', record)
    if result.returncode:
        fail('invalid_regression_reference', 'Original K10 witness failed its archived verifier; inspect retained logs')
    return json.loads(result.stdout)

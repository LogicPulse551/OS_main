"""Observe the K11 kernel, native artifacts and unchanged accepted parents."""
from pathlib import Path
from types import SimpleNamespace
import uuid

from .lifecycle import REPO, read, persist, digest, fail, load
from . import candidates


def current_identity(runtime):
    config=runtime.runtime
    build=config['sample_guest_build']
    if build!=config['search_guest_build'] or Path(build).parent.as_posix()!='/home/lab/k11':
        fail('repair_build_required','K11 requires one explicitly registered sampler/executor build under /home/lab/k11')
    evidence=runtime.out/('identity-'+uuid.uuid4().hex[:8])
    args=SimpleNamespace(output=evidence,guest_build=Path(config['scenario_guest_build']),
        build_lab=Path(config['build_lab']),kernel_build=Path(config['kernel_build']))
    original=runtime.k03.Session(args).identity()
    checked=read(evidence/'identity.json')
    kernel_path=Path(checked['kernel']['build_result'])
    kernel=read(kernel_path)
    if kernel.get('task')!='K11' or kernel.get('family') not in ('rmw','mutex'):
        fail('repair_build_required','Guest must run a verified repaired kernel')
    names=sorted({row['native_so'] for row in candidates.load_catalog()['inputs']}|
        {'kcov-sample-k08-ab','kcov-sample-k08-ba','kcov-execute-k09-ab','kcov-execute-k09-ba'})
    facts=runtime.guest(f"""import pathlib,json,hashlib,os
p=pathlib.Path({build!r})
def checked(base,name):
 rel=pathlib.PurePosixPath(name)
 assert not rel.is_absolute() and '..' not in rel.parts
 f=base/rel
 assert f.is_file() and not f.is_symlink() and f.resolve().is_relative_to(base.resolve())
 return f
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
recordfile=checked(p,'result.json');record=json.loads(recordfile.read_text())
manifestfile=checked(p,'effective-sources.json');manifest=json.loads(manifestfile.read_text())
hashes={{n:sha(checked(p/'bin',n)) for n in {names!r}}}
parents={{}}
for key in ('k08','k10'):
 saved=record['inputs']['accepted_'+key];old=pathlib.Path(saved['path'])
 parents[key]={{'result_sha256':sha(checked(old,'result.json')),
 'effective_manifest_sha256':sha(checked(old,'effective-sources.json')),
 'binaries':{{r['name']:sha(checked(old/'bin',r['name'])) for r in saved['record']['binaries']}},
 'source_hashes':{{r['path']:sha(checked(old/'source-work',r['path'])) for r in saved['effective_sources']}}}}
print(json.dumps({{'record':record,'record_text':recordfile.read_text(),'record_sha256':sha(recordfile),
 'manifest':manifest,'manifest_sha256':sha(manifestfile),'hashes':hashes,'parents':parents,
 'source_hashes':{{r['path']:sha(checked(p/'source-work',r['path'])) for r in manifest}},
 'executors_executable':all(os.access(checked(p/'bin',n),os.X_OK) for n in {names!r} if n.startswith('kcov-')),
 'device':pathlib.Path('/dev/kconc-regmap').is_char_device()}}))
""")
    analyzer=load('k11_identity_analysis',REPO/'adapters/maccconc/k11_analysis.py')
    native_check=analyzer.verify_native(facts['record'],facts['hashes'],facts['manifest'],facts['source_hashes'],facts['parents'])
    if (facts['device'] is not True or facts['executors_executable'] is not True
        or facts['record']['effective_manifest_sha256']!=facts['manifest_sha256']):
        fail('repair_native_mismatch','Native source manifest, execute permissions or real device differs')
    native_path=runtime.out/'native-build-record.json'
    native_path.write_bytes(facts['record_text'].encode())
    if digest(native_path)!=facts['record_sha256']:fail('repair_native_mismatch','Exported native record differs')
    # Save exact source bytes and records, so offline trace checking does not
    # require SSH or access to a mutable Linux build directory.
    kernel_copy=runtime.out/'kernel-build-record.json';kernel_copy.write_bytes(kernel_path.read_bytes())
    driver=Path(kernel['repaired_driver']['path'])
    driver_copy=runtime.out/'repaired-driver.c';driver_copy.write_bytes(driver.read_bytes())
    binding=dict(profile_id=analyzer.PROFILE_ID,family=kernel['family'],
        kernel_record=dict(path=str(kernel_copy),sha256=digest(kernel_copy)),
        native_record=dict(path=str(native_path),sha256=digest(native_path)),
        repaired_driver=dict(path=str(driver_copy),sha256=digest(driver_copy)))
    profile=analyzer.verify_profile(binding)
    identity=dict(kernel_and_k03=original,binaries=facts['hashes'],inputs=facts['record']['inputs'],
        catalog_sha256=digest(candidates.CATALOG),repair_profile=profile.identity)
    persist(runtime.out/'repair-identity.json',dict(passed=True,native_checks=native_check,
        live_native_facts=facts,identity=identity,kernel_identity_evidence=str(evidence/'identity.json')))
    return identity,binding

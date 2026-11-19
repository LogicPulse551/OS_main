#!/usr/bin/env bash
# Build one-plan K09 execution from the pinned K08 sources; keep all old SO bytes.
set -Eeuo pipefail
if [[ $# -ne 3 ]]; then
  printf 'Usage: %s K08_BUILD EXECUTOR_PATCH NEW_OUTPUT\n' "$0" >&2
  exit 2
fi
K08_BUILD="$(realpath -- "$1")"
EXECUTOR_PATCH="$(realpath -- "$2")"
OUTPUT_DIR="$(realpath -m -- "$3")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
[[ ! -e "$OUTPUT_DIR" ]] || { printf 'Output must be a new directory\n' >&2; exit 2; }
if [[ ! -d "$K08_BUILD" || "$OUTPUT_DIR/" == "$K08_BUILD/"* || "$K08_BUILD/" == "$OUTPUT_DIR/"* ]]; then
  printf 'Output must be separate from the accepted K08 input build\n' >&2
  exit 2
fi
for file in "$EXECUTOR_PATCH" "$BUILD_SCRIPT"; do
  [[ -f "$file" && "$file" != "$OUTPUT_DIR/"* ]] || { printf 'Invalid input\n' >&2; exit 2; }
done
mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
mkdir -- "$OUTPUT_DIR"
mkdir -- "$OUTPUT_DIR/bin" "$OUTPUT_DIR/logs" "$OUTPUT_DIR/source-work"
phase=preflight
trap 'rc=$?; if [[ $rc -ne 0 ]]; then printf "{\"passed\":false,\"phase\":\"%s\",\"exit_code\":%s}\n" "$phase" "$rc" > "$OUTPUT_DIR/result.json"; fi' EXIT
run_logged() {
  local name="$1"; shift
  printf '%q ' "$@" >> "$OUTPUT_DIR/commands.log"
  printf '\n' >> "$OUTPUT_DIR/commands.log"
  local rc=0
  "$@" > "$OUTPUT_DIR/logs/$name.log" 2>&1 || rc=$?
  printf '%s %s\n' "$name" "$rc" >> "$OUTPUT_DIR/exit-codes.txt"
  if [[ $rc -ne 0 ]]; then cat "$OUTPUT_DIR/logs/$name.log" >&2; fi
  return "$rc"
}
run_logged platform python3 -c 'import pathlib,platform; text=pathlib.Path("/etc/os-release").read_text(); print(text); print(platform.uname()); assert "openEuler" in text and platform.machine()=="x86_64"'
run_logged cxx-version g++ --version
run_logged cxx-predefines g++ -dM -E -x c++ /dev/null
run_logged compiler-major python3 - "$OUTPUT_DIR/logs/cxx-predefines.log" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text().splitlines()
if '#define __GNUC__ 12' not in lines or any(x.startswith('#define __clang__ ') for x in lines):
 raise SystemExit('K09 native executor requires the accepted GNU g++ 12 toolchain')
PY
phase=input-identity
run_logged input-identity python3 - "$K08_BUILD" "$EXECUTOR_PATCH" "$OUTPUT_DIR" "$BUILD_SCRIPT" <<'PY'
import hashlib,json,pathlib,shutil,sys
old,patch,out,script=map(pathlib.Path,sys.argv[1:])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def checked_file(base,name,wanted=None):
 relative=pathlib.PurePosixPath(name)
 if relative.is_absolute() or '..' in relative.parts:
  raise SystemExit('Invalid accepted file path')
 path=base/relative
 if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(base.resolve()) or (wanted is not None and sha(path)!=wanted):
  raise SystemExit('Accepted file differs: '+str(path))
 return path
# These hashes identify source bytes, not a machine-specific build path or log.
expected_sources={
 'LICENSE':'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30',
 'README.md':'babb7745969af615f30693f7ebf099663d4c5274aae0fac265ba0155294e8b16',
 'basic.h':'128435d953fa15cd102f90d1a72b2772a4e8372952e33398996a15d395f821a6',
 'common.h':'6fcbdc9f18f558e1e8311ff60f8ed652c1b95573a546b48330e5804c1cdac4b3',
 'k03-evidence.h':'668731c9e4a4198a6a241a6df9a4aa270db9038469c78772ecf11e9e574425b8',
 'k03-evidence.patch':'eca89f80e1ec9013da83f1a4859de763c907d938575820ce32f6e136430bae71',
 'k08-executor.patch':'ed27d8468e47f8215f10a7db77e153d8ac720ee894b0116388825fa830661f99',
 'kcov-autorace.cpp':'952dbc4906b0ed041effa5990c72e8371cb55928d7da07201d2bd394befaba20',
 'kcov-common.h':'460d76ad4322d43b5c7996686a69d27ee0c1a08d0f23b6bf19cd25a86834e308',
 'runner-common.h':'e99df9bfa3295b9349750df465792867728f3272d1761865447f4ca126298c56',
 'testcase/child-exit.c':'d7c9bdaabc5d205cb13bfa660c139ba4e56ba1c9f292983479d6456965e0d87a',
 'testcase/demo-dup-vs-close.c':'c0aea1a5e24f93c968e48f630459183836b2996962044b4ea41978a5bedbcb0d',
 'third_party/kcov.h':'4fda145e48bc8357d1e2325d02291236377965b81b809e4e84309516e4b86b05'}
record_path=checked_file(old,'result.json');manifest_path=checked_file(old,'effective-sources.json')
record=json.loads(record_path.read_text());sources=json.loads(manifest_path.read_text())
if record.get('passed') is not True or record.get('kind')!='kconc.sampler.build' or record.get('task')!='K08' or record.get('inputs',{}).get('upstream_commit')!='c17ba2d68167d1a892dbdec326bd6cfec32ec9f1':
 raise SystemExit('Expected a successful K08 build from the pinned upstream commit')
if len(sources)!=len(expected_sources) or {item['path']:item['sha256'] for item in sources}!=expected_sources:
 raise SystemExit('K08 effective sources differ from the fixed adapter baseline')
for item in sources:
 source=checked_file(old/'source-work',item['path'],item['sha256'])
 target=out/'source-work'/item['path'];target.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(source,target)
names=[f'regmap-k06-{case}-{mode}.so' for case in ['disjoint-bits','overlap-bits','different-registers','zero-mask','high-bits'] for mode in ['split','update-bits']]
names += [f'regmap-k07-{case}-{mode}.so' for case in ['different-registers','shared-register'] for mode in ['shared','per-role']]
expected_names={'kcov-sample-k08-ab','kcov-sample-k08-ba',*names}
if len(record['binaries'])!=16 or {item['name'] for item in record['binaries']}!=expected_names:
 raise SystemExit('K08 build does not contain exactly the expected sampler and fourteen scenarios')
hashes={item['name']:item['sha256'] for item in record['binaries']}
for name,wanted in hashes.items(): checked_file(old/'bin',name,wanted)
if hashes['kcov-sample-k08-ab']!=hashes['kcov-sample-k08-ba']:
 raise SystemExit('K08 sampler entrypoints have different bytes')
original_copies=record['inputs']['copied_scenarios']
if len(original_copies)!=14 or {item['name']:item['sha256'] for item in original_copies}!={name:hashes[name] for name in names}:
 raise SystemExit('K08 copied scenarios do not bind to original build inputs')
copied=[]
for name in names:
 source=checked_file(old/'bin',name,hashes[name]);shutil.copyfile(source,out/'bin'/name)
 copied.append({'name':name,'family':'k06' if name.startswith('regmap-k06-') else 'k07','input_path':str(source),'sha256':sha(source)})
shutil.copyfile(patch,out/'source-work/k09-executor.patch')
inputs={'upstream_commit':'c17ba2d68167d1a892dbdec326bd6cfec32ec9f1','upstream_license':'Apache-2.0',
 'accepted_k08':{'path':str(old),'result_sha256':sha(record_path),'effective_manifest_sha256':sha(manifest_path),'record':record,'effective_sources':sources},
 'copied_scenarios':copied,'executor_patch_path':str(patch),'executor_patch_sha256':sha(patch),
 'build_script_path':str(script),'build_script_sha256':sha(script),
 'scope':'One supplied plan per process; original logical callback mapping and scenario bytes retained. No new kernel, scenario recompilation or automatic enumeration. Host must bind the archived K08 candidate to this executor and the live kernel.'}
(out/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print(json.dumps(inputs))
PY
phase=apply-k09-executor-patch
run_logged apply-patch patch --batch --forward --fuzz=0 -p1 \
  -i "$OUTPUT_DIR/source-work/k09-executor.patch" -d "$OUTPUT_DIR/source-work"
phase=compile-executor
run_logged executor-build g++ -std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function \
  -pthread "$OUTPUT_DIR/source-work/kcov-autorace.cpp" -ldw -lcapstone -lelf -ldl \
  -o "$OUTPUT_DIR/bin/kcov-execute-k09-ab"
run_logged copy-executor cp -- "$OUTPUT_DIR/bin/kcov-execute-k09-ab" "$OUTPUT_DIR/bin/kcov-execute-k09-ba"
phase=elf-and-loader
binaries=(kcov-execute-k09-ab kcov-execute-k09-ba)
for path in "$OUTPUT_DIR"/bin/*.so; do binaries+=("$(basename -- "$path")"); done
for name in "${binaries[@]}"; do
  run_logged "$name-elf" readelf -h "$OUTPUT_DIR/bin/$name"
  run_logged "$name-ldd" ldd "$OUTPUT_DIR/bin/$name"
  if [[ "$name" == *.so ]]; then
    run_logged "$name-symbols" nm -D --defined-only "$OUTPUT_DIR/bin/$name"
  fi
done
phase=usage-entrypoint
for order in ab ba; do
  if run_logged "executor-$order-usage" "$OUTPUT_DIR/bin/kcov-execute-k09-$order"; then rc=0; else rc=$?; fi
  printf '%s %s\n' "$order" "$rc" >> "$OUTPUT_DIR/usage-exit-codes.txt"
done
phase=final-validation
run_logged final-validation python3 - "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1]);inputs=json.loads((out/'inputs.json').read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
names=['kcov-execute-k09-ab','kcov-execute-k09-ba']+[item['name'] for item in inputs['copied_scenarios']]
binaries=[]
for name in names:
 path=out/'bin'/name;elf=(out/'logs'/f'{name}-elf.log').read_text();deps=(out/'logs'/f'{name}-ldd.log').read_text()
 if not path.is_file() or path.is_symlink() or 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in deps:
  raise SystemExit('Wrong binary type/architecture or unresolved dependency: '+name)
 binaries.append({'name':name,'sha256':sha(path)})
 if name.endswith('.so'):
  symbols={line.split()[-1] for line in (out/'logs'/f'{name}-symbols.log').read_text().splitlines() if line.split()}
  if not {'test_setup','test_thread1','test_thread2','test_end'}.issubset(symbols):
   raise SystemExit('Scenario does not export original four callbacks: '+name)
if sha(out/'bin/kcov-execute-k09-ab')!=sha(out/'bin/kcov-execute-k09-ba'):
 raise SystemExit('Executor entrypoints are not identical bytes')
for item in inputs['copied_scenarios']:
 if sha(out/'bin'/item['name'])!=item['sha256'] or sha(pathlib.Path(item['input_path']))!=item['sha256']:
  raise SystemExit('Original or copied scenario changed: '+item['name'])
codes=dict(line.split() for line in (out/'usage-exit-codes.txt').read_text().splitlines())
for order in ['ab','ba']:
 text=(out/'logs'/f'executor-{order}-usage.log').read_text()
 if codes.get(order)!='1' or '--k09-execute ab|ba PLAN NEW_DIR' not in text or '--k08-baseline' in text or '--k03-record' in text:
  raise SystemExit('Executor usage check failed: '+order)
accepted=inputs['accepted_k08'];old=pathlib.Path(accepted['path'])
if sha(old/'result.json')!=accepted['result_sha256'] or sha(old/'effective-sources.json')!=accepted['effective_manifest_sha256']:
 raise SystemExit('Original K08 build record changed')
for item in accepted['effective_sources']:
 if sha(old/'source-work'/item['path'])!=item['sha256']:
  raise SystemExit('Original K08 source changed: '+item['path'])
 if item['path'] not in {'kcov-autorace.cpp','k03-evidence.h'} and sha(out/'source-work'/item['path'])!=item['sha256']:
  raise SystemExit('Unexpected change outside the K09 main/metadata patch: '+item['path'])
for item in accepted['record']['binaries']:
 if sha(old/'bin'/item['name'])!=item['sha256']:
  raise SystemExit('Original K08 binary changed: '+item['name'])
if sha(pathlib.Path(inputs['executor_patch_path']))!=inputs['executor_patch_sha256'] or sha(out/'source-work/k09-executor.patch')!=inputs['executor_patch_sha256'] or sha(pathlib.Path(inputs['build_script_path']))!=inputs['build_script_sha256']:
 raise SystemExit('K09 team input changed during build')
effective=[{'path':p.relative_to(out/'source-work').as_posix(),'sha256':sha(p)} for p in sorted((out/'source-work').rglob('*')) if p.is_file()]
(out/'effective-sources.json').write_text(json.dumps(effective,indent=2)+'\n')
record={'schema_version':1,'kind':'kconc.executor.build','task':'K09','passed':True,'exit_code':0,
 'inputs':inputs,'binaries':binaries,'compiler':'GNU g++ 12','cxx_standard':'gnu++23',
 'kernel_testcase_executed':False,'accepted_inputs_modified':False,'scenario_recompiled':False,
 'usage':{'actual_exit_codes':codes,'expected_exit_code':1,'scope':'usage only'},
 'scope':'Native one-plan executor and byte-identical reused scenarios; real candidate execution and exact archived/live identity binding must be verified separately'}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(item['sha256']+'  bin/'+item['name']+'\n' for item in binaries))
print(json.dumps(record))
PY

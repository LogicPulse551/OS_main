#!/usr/bin/env bash
# Build only a K08 sampler. Reuse byte-identical K06/K07 four-callback SO files.
set -Eeuo pipefail
if [[ $# -ne 5 ]]; then
  printf 'Usage: %s K03_BUILD K06_BUILD K07_BUILD EXECUTOR_PATCH NEW_OUTPUT\n' "$0" >&2
  exit 2
fi
K03_BUILD="$(realpath -- "$1")"
K06_BUILD="$(realpath -- "$2")"
K07_BUILD="$(realpath -- "$3")"
EXECUTOR_PATCH="$(realpath -- "$4")"
OUTPUT_DIR="$(realpath -m -- "$5")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
[[ ! -e "$OUTPUT_DIR" ]] || { printf 'Output must be a new directory\n' >&2; exit 2; }
for old in "$K03_BUILD" "$K06_BUILD" "$K07_BUILD"; do
  if [[ ! -d "$old" || "$OUTPUT_DIR/" == "$old/"* || "$old/" == "$OUTPUT_DIR/"* ]]; then
    printf 'Output must be separate from every accepted input build\n' >&2
    exit 2
  fi
done
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
 raise SystemExit('K08 native sampler requires the accepted GNU g++ 12 toolchain')
PY
phase=input-identity
run_logged input-identity python3 - "$K03_BUILD" "$K06_BUILD" "$K07_BUILD" "$EXECUTOR_PATCH" "$OUTPUT_DIR" "$BUILD_SCRIPT" <<'PY'
import hashlib,json,pathlib,shutil,sys
k03,k06,k07,patch,out,script=map(pathlib.Path,sys.argv[1:])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
commit='c17ba2d68167d1a892dbdec326bd6cfec32ec9f1'
accepted={
 'k03':('547c991009cebb043f0ba3e781f1704cec7466a8cd782ee751ed85762dfb652a','43790e9938df1b980f869c787a381eea4febacf04f2cd95e7f8e24dc117b18db'),
 'k06':('86e39913076ae9f5733e64594e3f36a8f781df94095aaf26ec4de519e2102735','0741f4549916fc417ca49d98c8a94f3c8677c7466d4ea6d0d2851a4da7bc4ba8'),
 'k07':('7ad5eea94bb1b5cbddc85157c118b54bd2af3e7e819d6159be675777f087c169','ba527ff9e50526910f36be570a934bc73e3657bd1df465ba1a770f488903e33f')}
def checked_file(base,name,wanted):
 relative=pathlib.PurePosixPath(name)
 if relative.is_absolute() or '..' in relative.parts:
  raise SystemExit('Invalid accepted file path')
 path=base/relative
 if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(base.resolve()) or sha(path)!=wanted:
  raise SystemExit('Accepted file differs: '+str(path))
 return path
builds={};records={}
for kind,old in [('k03',k03),('k06',k06),('k07',k07)]:
 result_hash,manifest_hash=accepted[kind]
 checked_file(old,'result.json',result_hash)
 checked_file(old,'effective-sources.json',manifest_hash)
 record=json.loads((old/'result.json').read_text())
 if record.get('passed') is not True or (record.get('upstream_commit') or record.get('inputs',{}).get('upstream_commit'))!=commit:
  raise SystemExit('Unaccepted build: '+kind)
 sources=json.loads((old/'effective-sources.json').read_text())
 for item in sources:
  source=checked_file(old/'source-work',item['path'],item['sha256'])
  if kind=='k03':
   target=out/'source-work'/item['path'];target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copyfile(source,target)
 for item in record['binaries']:
  checked_file(old/'bin',item['name'],item['sha256'])
 builds[kind]={'path':str(old),'result_sha256':result_hash,'effective_manifest_sha256':manifest_hash,
  'effective_sources':sources,'binaries':record['binaries'],'inputs':record.get('inputs',{})}
 records[kind]=record
names={
 'k06':[f'regmap-k06-{case}-{mode}.so' for case in ['disjoint-bits','overlap-bits','different-registers','zero-mask','high-bits'] for mode in ['split','update-bits']],
 'k07':[f'regmap-k07-{case}-{mode}.so' for case in ['different-registers','shared-register'] for mode in ['shared','per-role']]}
copied=[]
for kind,old in [('k06',k06),('k07',k07)]:
 for name in names[kind]:
  matches=[item for item in records[kind]['binaries'] if item['name']==name]
  if len(matches)!=1: raise SystemExit('Missing or duplicate accepted SO: '+name)
  source=checked_file(old/'bin',name,matches[0]['sha256'])
  shutil.copyfile(source,out/'bin'/name)
  copied.append({'name':name,'family':kind,'input_path':str(source),'sha256':sha(source)})
shutil.copyfile(patch,out/'source-work/k08-executor.patch')
inputs={'upstream_commit':commit,'upstream_license':'Apache-2.0','accepted_builds':builds,
 'k03_build':str(k03),'k03_build_result_sha256':accepted['k03'][0],
 'k03_effective_manifest_sha256':accepted['k03'][1],
 'k03_executor_sha256':sha(k03/'bin/kcov-autorace-k03'),
 'copied_scenarios':copied,'executor_patch_path':str(patch),'executor_patch_sha256':sha(patch),
 'build_script_path':str(script),'build_script_sha256':sha(script),
 'scope':'Sampling only; logical callback identities are unchanged. No SO recompilation, no kernel build, no automatic conflict execution or replay.'}
(out/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print(json.dumps(inputs))
PY
phase=apply-k08-sampler-patch
run_logged apply-patch patch --batch --forward --fuzz=0 -p1 \
  -i "$OUTPUT_DIR/source-work/k08-executor.patch" -d "$OUTPUT_DIR/source-work"
phase=compile-sampler
run_logged sampler-build g++ -std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function \
  -pthread "$OUTPUT_DIR/source-work/kcov-autorace.cpp" -ldw -lcapstone -lelf -ldl \
  -o "$OUTPUT_DIR/bin/kcov-sample-k08-ab"
run_logged copy-sampler cp -- "$OUTPUT_DIR/bin/kcov-sample-k08-ab" "$OUTPUT_DIR/bin/kcov-sample-k08-ba"
phase=elf-and-loader
binaries=(kcov-sample-k08-ab kcov-sample-k08-ba)
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
  if run_logged "sampler-$order-usage" "$OUTPUT_DIR/bin/kcov-sample-k08-$order"; then rc=0; else rc=$?; fi
  printf '%s %s\n' "$order" "$rc" >> "$OUTPUT_DIR/usage-exit-codes.txt"
done
phase=final-validation
run_logged final-validation python3 - "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1]);inputs=json.loads((out/'inputs.json').read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
names=['kcov-sample-k08-ab','kcov-sample-k08-ba']+[item['name'] for item in inputs['copied_scenarios']]
binaries=[]
for name in names:
 path=out/'bin'/name
 elf=(out/'logs'/f'{name}-elf.log').read_text();deps=(out/'logs'/f'{name}-ldd.log').read_text()
 if not path.is_file() or path.is_symlink() or 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in deps:
  raise SystemExit('Wrong binary type/architecture or unresolved dependency: '+name)
 binaries.append({'name':name,'sha256':sha(path)})
 if name.endswith('.so'):
  symbols={line.split()[-1] for line in (out/'logs'/f'{name}-symbols.log').read_text().splitlines() if line.split()}
  if not {'test_setup','test_thread1','test_thread2','test_end'}.issubset(symbols):
   raise SystemExit('Scenario does not export original four callbacks: '+name)
if sha(out/'bin/kcov-sample-k08-ab')!=sha(out/'bin/kcov-sample-k08-ba'):
 raise SystemExit('Sampler entrypoints are not identical bytes')
for item in inputs['copied_scenarios']:
 if sha(out/'bin'/item['name'])!=item['sha256'] or sha(pathlib.Path(item['input_path']))!=item['sha256']:
  raise SystemExit('Original or copied scenario changed: '+item['name'])
codes=dict(line.split() for line in (out/'usage-exit-codes.txt').read_text().splitlines())
for order in ['ab','ba']:
 text=(out/'logs'/f'sampler-{order}-usage.log').read_text()
 if codes.get(order)!='1' or '--k08-baseline ab|ba NEW_DIR' not in text or '--k03-replay' in text or '--k03-record' in text:
  raise SystemExit('Sampler usage check failed: '+order)
for kind,build in inputs['accepted_builds'].items():
 old=pathlib.Path(build['path'])
 if sha(old/'result.json')!=build['result_sha256'] or sha(old/'effective-sources.json')!=build['effective_manifest_sha256']:
  raise SystemExit('Original build record changed: '+kind)
 for item in build['effective_sources']:
  if sha(old/'source-work'/item['path'])!=item['sha256']:
   raise SystemExit('Original source changed: '+kind+'/'+item['path'])
 for item in build['binaries']:
  if sha(old/'bin'/item['name'])!=item['sha256']:
   raise SystemExit('Original binary changed: '+kind+'/'+item['name'])
if sha(pathlib.Path(inputs['executor_patch_path']))!=inputs['executor_patch_sha256'] or sha(out/'source-work/k08-executor.patch')!=inputs['executor_patch_sha256'] or sha(pathlib.Path(inputs['build_script_path']))!=inputs['build_script_sha256']:
 raise SystemExit('K08 team input changed during build')
effective=[{'path':p.relative_to(out/'source-work').as_posix(),'sha256':sha(p)} for p in sorted((out/'source-work').rglob('*')) if p.is_file()]
(out/'effective-sources.json').write_text(json.dumps(effective,indent=2)+'\n')
record={'schema_version':1,'kind':'kconc.sampler.build','task':'K08','passed':True,'exit_code':0,
 'inputs':inputs,'binaries':binaries,'compiler':'GNU g++ 12','cxx_standard':'gnu++23',
 'kernel_testcase_executed':False,'accepted_inputs_modified':False,'scenario_recompiled':False,
 'usage':{'actual_exit_codes':codes,'expected_exit_code':1,'scope':'usage only'},
 'scope':'Native sampler and byte-identical reused scenarios; real AB/BA collection is verified separately'}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(item['sha256']+'  bin/'+item['name']+'\n' for item in binaries))
print(json.dumps(record))
PY

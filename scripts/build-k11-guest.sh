#!/usr/bin/env bash
# New K11 directory only: copy the accepted control executor and RMW SOs;
# rebuild the sampler with the accepted K10 ready/abort fix and four mutex SOs.
set -Eeuo pipefail
if [[ $# -ne 8 ]]; then
  printf 'Usage: %s K08_BUILD K10_BUILD SCENARIO_C CASES_H UAPI_H NATIVE_PATCH SAMPLER_CONTROL_PATCH NEW_OUTPUT\n' "$0" >&2
  exit 2
fi
K08_BUILD="$(realpath -- "$1")"
K10_BUILD="$(realpath -- "$2")"
SCENARIO_C="$(realpath -- "$3")"
CASES_H="$(realpath -- "$4")"
UAPI_H="$(realpath -- "$5")"
NATIVE_PATCH="$(realpath -- "$6")"
SAMPLER_PATCH="$(realpath -- "$7")"
OUTPUT_DIR="$(realpath -m -- "$8")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
[[ ! -e "$OUTPUT_DIR" ]] || { printf 'Output must be a new directory\n' >&2; exit 2; }
for old in "$K08_BUILD" "$K10_BUILD"; do
  [[ -d "$old" && "$OUTPUT_DIR/" != "$old/"* && "$old/" != "$OUTPUT_DIR/"* ]] || { printf 'Output must be separate from accepted builds\n' >&2; exit 2; }
done
for file in "$SCENARIO_C" "$CASES_H" "$UAPI_H" "$NATIVE_PATCH" "$SAMPLER_PATCH" "$BUILD_SCRIPT"; do
  [[ -f "$file" && "$file" != "$OUTPUT_DIR/"* ]] || { printf 'Invalid build input\n' >&2; exit 2; }
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
run_logged cc-version gcc --version
run_logged cc-predefines gcc -dM -E -x c /dev/null
run_logged cxx-version g++ --version
run_logged cxx-predefines g++ -dM -E -x c++ /dev/null
run_logged compiler-major python3 - "$OUTPUT_DIR/logs/cc-predefines.log" "$OUTPUT_DIR/logs/cxx-predefines.log" <<'PY'
import pathlib,sys
for file in sys.argv[1:]:
 lines=pathlib.Path(file).read_text().splitlines()
 if '#define __GNUC__ 12' not in lines or any(x.startswith('#define __clang__ ') for x in lines):
  raise SystemExit('K11 native adapter requires the accepted GNU gcc/g++ 12 toolchain')
PY
phase=input-identity
run_logged input-identity python3 - "$K08_BUILD" "$K10_BUILD" "$SCENARIO_C" "$CASES_H" "$UAPI_H" "$NATIVE_PATCH" "$SAMPLER_PATCH" "$BUILD_SCRIPT" "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,shutil,sys
k08,k10,scenario,cases,header,patch,sampler_patch,script,out=map(pathlib.Path,sys.argv[1:])
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def checked(base,name,wanted):
 relative=pathlib.PurePosixPath(name)
 if relative.is_absolute() or '..' in relative.parts:raise SystemExit('Invalid accepted path')
 p=base/relative
 if not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(base.resolve()) or sha(p)!=wanted:raise SystemExit('Accepted file differs: '+str(p))
 return p
# Accepted records were sealed outside the code repository after K08/K10.
pinned={
 'k08':('1e9043665ff12a87cb61dbc402e1b9ad3493b7ec962921511c019145e00d517d','433af065cee35d0067bd1d5c7b3cf924d36fa2baca4535fa2be9cdaf817c5636','kconc.sampler.build','K08'),
 'k10':('0a6926a7892c0b048387969e37393a4d70411873590f5eb3eb399f40a4647ac1','e4e72bf155f29ae033094a185a7adee4728ea4c7ab1b33ab2177d8503431c00a','kconc.executor.control-build','K10')}
accepted={}
for key,old in [('k08',k08),('k10',k10)]:
 rh,mh,kind,task=pinned[key]
 record=json.loads(checked(old,'result.json',rh).read_text())
 sources=json.loads(checked(old,'effective-sources.json',mh).read_text())
 if record.get('passed') is not True or record.get('kind')!=kind or record.get('task')!=task:raise SystemExit('Wrong accepted build: '+key)
 for item in sources:
  source=checked(old/'source-work',item['path'],item['sha256'])
  if key=='k08':
   target=out/'source-work'/item['path'];target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copyfile(source,target)
 for item in record['binaries']:checked(old/'bin',item['name'],item['sha256'])
 accepted[key]=dict(path=str(old),result_sha256=rh,effective_manifest_sha256=mh,record=record,effective_sources=sources)
copies=[]
for key,names in [('k10',['kcov-execute-k09-ab','kcov-execute-k09-ba']+[f'regmap-k06-{case}-{mode}.so' for case in ['disjoint-bits','overlap-bits','different-registers','zero-mask','high-bits'] for mode in ['split','update-bits']])]:
 old=pathlib.Path(accepted[key]['path']);hashes={r['name']:r['sha256'] for r in accepted[key]['record']['binaries']}
 for name in names:
  source=checked(old/'bin',name,hashes[name]);target=out/'bin'/name;shutil.copyfile(source,target)
  target.chmod(source.stat().st_mode & 0o777)
  copies.append(dict(name=name,accepted_build=key,input_path=str(source),sha256=hashes[name]))
team=[]
for source,name in [(scenario,'regmap-k07.c'),(cases,'regmap-k07-cases.h'),(header,'kconc-regmap.h'),(patch,'k11-shared-gate-native.patch'),(sampler_patch,'k11-sampler-control.patch')]:
 shutil.copyfile(source,out/'source-work'/name)
 team.append(dict(input_path=str(source),build_copy=name,sha256=sha(source)))
inputs=dict(upstream_commit='c17ba2d68167d1a892dbdec326bd6cfec32ec9f1',upstream_license='Apache-2.0',
 accepted_k08=accepted['k08'],accepted_k10=accepted['k10'],copied_binaries=copies,team_files=team,
 native_compile_defines=['KCONC_K11_SHARED_GATE=1'],sampler_control_policy_id='kconc.k11.sampler-ready-abort-v1',build_script_path=str(script),build_script_sha256=sha(script),
 scope='Original requests and callbacks retained. The sampler uses the accepted K10 runner readiness/abort fix; the K10 executor and ten RMW libraries are byte-identical copies. Mutex adapter checks actual gate_id=0.')
(out/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print(json.dumps(inputs))
PY
phase=apply-native-repair-expectation
run_logged apply-patch patch --batch --forward --fuzz=0 -p1 -i "$OUTPUT_DIR/source-work/k11-shared-gate-native.patch" -d "$OUTPUT_DIR/source-work"
phase=apply-sampler-control-fix
run_logged apply-sampler-patch patch --batch --forward --fuzz=0 -p1 -i "$OUTPUT_DIR/source-work/k11-sampler-control.patch" -d "$OUTPUT_DIR/source-work"
run_logged sampler-source-reuse python3 - "$OUTPUT_DIR" "$K10_BUILD" <<'PY'
import pathlib,sys
out,old=map(pathlib.Path,sys.argv[1:])
if (out/'source-work/runner-common.h').read_bytes()!=(old/'source-work/runner-common.h').read_bytes():
 raise SystemExit('Sampler runner differs from the accepted K10 control implementation')
print('Patched K08 runner equals the accepted K10 runner byte for byte')
PY
phase=compile-sampler
run_logged sampler-build g++ -std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function \
  -pthread "$OUTPUT_DIR/source-work/kcov-autorace.cpp" -ldw -lcapstone -lelf -ldl \
  -o "$OUTPUT_DIR/bin/kcov-sample-k08-ab"
run_logged copy-sampler cp -- "$OUTPUT_DIR/bin/kcov-sample-k08-ab" "$OUTPUT_DIR/bin/kcov-sample-k08-ba"
phase=compile-mutex-scenarios
case_ids=(different-registers shared-register)
mode_ids=(shared per-role)
for case_index in "${!case_ids[@]}"; do
  for mode_index in "${!mode_ids[@]}"; do
    name="regmap-k07-${case_ids[$case_index]}-${mode_ids[$mode_index]}.so"
    run_logged "$name-build" gcc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
      -pthread -I "$OUTPUT_DIR/source-work" -DKCONC_K11_SHARED_GATE=1 \
      -DKCONC_CASE_INDEX="$case_index" -DKCONC_MODE="$mode_index" \
      "$OUTPUT_DIR/source-work/regmap-k07.c" -o "$OUTPUT_DIR/bin/$name"
  done
done
phase=elf-and-loader
for path in "$OUTPUT_DIR"/bin/*; do
  name="$(basename -- "$path")"
  run_logged "$name-elf" readelf -h "$path"
  run_logged "$name-ldd" ldd "$path"
  if [[ "$name" == *.so ]]; then run_logged "$name-symbols" nm -D --defined-only "$path"; fi
done
phase=usage-entrypoints
for kind in sample-k08 execute-k09; do
  for order in ab ba; do
    name="kcov-$kind-$order"
    if run_logged "$name-usage" "$OUTPUT_DIR/bin/$name"; then rc=0; else rc=$?; fi
    printf '%s %s\n' "$name" "$rc" >> "$OUTPUT_DIR/usage-exit-codes.txt"
  done
done
phase=final-validation
run_logged final-validation python3 - "$OUTPUT_DIR" <<'PY'
import hashlib,json,os,pathlib,sys
out=pathlib.Path(sys.argv[1]);inputs=json.loads((out/'inputs.json').read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
new_names=[f'regmap-k07-{case}-{mode}.so' for case in ['different-registers','shared-register'] for mode in ['shared','per-role']]
names=[item['name'] for item in inputs['copied_binaries']]+['kcov-sample-k08-ab','kcov-sample-k08-ba']+new_names
if len(names)!=18 or len(set(names))!=18 or {p.name for p in (out/'bin').iterdir()}!=set(names):raise SystemExit('Expected exactly eighteen native artifacts')
binaries=[]
for name in names:
 path=out/'bin'/name;elf=(out/'logs'/f'{name}-elf.log').read_text();deps=(out/'logs'/f'{name}-ldd.log').read_text()
 if not path.is_file() or path.is_symlink() or 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in deps:raise SystemExit('Wrong binary or unresolved dependency: '+name)
 if name.startswith('kcov-') and not os.access(path,os.X_OK):raise SystemExit('Copied native entrypoint is not executable: '+name)
 binaries.append(dict(name=name,sha256=sha(path)))
 if name.endswith('.so'):
  symbols={line.split()[-1] for line in (out/'logs'/f'{name}-symbols.log').read_text().splitlines() if line.split()}
  if not {'test_setup','test_thread1','test_thread2','test_end'}.issubset(symbols):raise SystemExit('Missing four callbacks: '+name)
for item in inputs['copied_binaries']:
 if sha(out/'bin'/item['name'])!=item['sha256'] or sha(pathlib.Path(item['input_path']))!=item['sha256']:raise SystemExit('Copied or original binary changed')
 if (out/'bin'/item['name']).stat().st_mode & 0o777 != pathlib.Path(item['input_path']).stat().st_mode & 0o777:raise SystemExit('Copied permissions differ from accepted binary')
if sha(out/'bin/kcov-sample-k08-ab')!=sha(out/'bin/kcov-sample-k08-ba'):raise SystemExit('Sampler entrypoints have different bytes')
for key in ['accepted_k08','accepted_k10']:
 accepted=inputs[key];old=pathlib.Path(accepted['path'])
 if sha(old/'result.json')!=accepted['result_sha256'] or sha(old/'effective-sources.json')!=accepted['effective_manifest_sha256']:raise SystemExit('Accepted record changed')
 for item in accepted['effective_sources']:
  if sha(old/'source-work'/item['path'])!=item['sha256']:raise SystemExit('Accepted source changed')
  if key=='accepted_k08' and item['path']!='runner-common.h' and sha(out/'source-work'/item['path'])!=item['sha256']:raise SystemExit('Unexpected sampler source modification')
 for item in accepted['record']['binaries']:
  if sha(old/'bin'/item['name'])!=item['sha256']:raise SystemExit('Accepted binary changed')
for item in inputs['team_files']:
 if sha(pathlib.Path(item['input_path']))!=item['sha256']:raise SystemExit('Team input changed')
 if item['build_copy']!='regmap-k07-cases.h' and sha(out/'source-work'/item['build_copy'])!=item['sha256']:raise SystemExit('Unexpected copied-source change')
if sha(pathlib.Path(inputs['build_script_path']))!=inputs['build_script_sha256']:raise SystemExit('Build script changed')
if sha(out/'source-work/runner-common.h')!=sha(pathlib.Path(inputs['accepted_k10']['path'])/'source-work/runner-common.h'):raise SystemExit('Sampler control no longer equals accepted K10')
codes=dict(line.split() for line in (out/'usage-exit-codes.txt').read_text().splitlines())
for name in ['kcov-sample-k08-ab','kcov-sample-k08-ba','kcov-execute-k09-ab','kcov-execute-k09-ba']:
 expected='--k08-baseline ab|ba NEW_DIR' if 'sample' in name else '--k09-execute ab|ba PLAN NEW_DIR'
 if codes.get(name)!='1' or expected not in (out/'logs'/f'{name}-usage.log').read_text():raise SystemExit('Native usage check failed')
effective=[dict(path=p.relative_to(out/'source-work').as_posix(),sha256=sha(p)) for p in sorted((out/'source-work').rglob('*')) if p.is_file()]
(out/'effective-sources.json').write_text(json.dumps(effective,indent=2)+'\n')
record=dict(schema_version=1,kind='kconc.regression-native.build',task='K11',profile_id='kconc.k11.regmap-repair-v1',passed=True,exit_code=0,
 inputs=inputs,binaries=binaries,effective_manifest_sha256=sha(out/'effective-sources.json'),compiler='GNU gcc/g++ 12',cxx_standard='gnu++23',
 accepted_inputs_modified=False,executor_recompiled=False,sampler_recompiled=True,scenario_recompiled=new_names,
 kernel_testcase_executed=False,usage=dict(actual_exit_codes=codes,expected_exit_code=1),
 scope='Native build and usage only. A separately bound repaired kernel, fresh samples, candidate hits and property regressions remain required.')
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(item['sha256']+'  bin/'+item['name']+'\n' for item in binaries))
print(json.dumps(record))
PY

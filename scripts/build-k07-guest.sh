#!/usr/bin/env bash
# Build the K07 baseline-only adapter and regmap clients in a new guest directory.
set -Eeuo pipefail
if [[ $# -ne 7 ]]; then
  printf 'Usage: %s K03_BUILD SCENARIO_C CLIENT_C CASES_H UAPI_H EXECUTOR_PATCH NEW_OUTPUT\n' "$0" >&2
  exit 2
fi
K03_BUILD="$(realpath -- "$1")"
SCENARIO_C="$(realpath -- "$2")"
CLIENT_C="$(realpath -- "$3")"
CASES_H="$(realpath -- "$4")"
UAPI_H="$(realpath -- "$5")"
EXECUTOR_PATCH="$(realpath -- "$6")"
OUTPUT_DIR="$(realpath -m -- "$7")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
if [[ -e "$OUTPUT_DIR" || "$OUTPUT_DIR/" == "$K03_BUILD/"* || "$K03_BUILD/" == "$OUTPUT_DIR/"* ]]; then
  printf 'Output must be a new directory separate from the accepted K03 build\n' >&2
  exit 2
fi
for file in "$SCENARIO_C" "$CLIENT_C" "$CASES_H" "$UAPI_H" "$EXECUTOR_PATCH" "$BUILD_SCRIPT"; do
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
run_logged cxx-version g++ --version
run_logged cc-predefines gcc -dM -E -x c /dev/null
run_logged cxx-predefines g++ -dM -E -x c++ /dev/null
run_logged compiler-major python3 - "$OUTPUT_DIR/logs/cc-predefines.log" "$OUTPUT_DIR/logs/cxx-predefines.log" <<'PY'
import pathlib,sys
for name in sys.argv[1:]:
 lines=pathlib.Path(name).read_text().splitlines()
 if '#define __GNUC__ 12' not in lines or any(x.startswith('#define __clang__ ') for x in lines):
  raise SystemExit('K07 guest build requires the accepted GNU gcc/g++ 12 toolchain')
PY
phase=input-identity
run_logged input-identity python3 - "$K03_BUILD" "$SCENARIO_C" "$CLIENT_C" "$CASES_H" "$UAPI_H" "$EXECUTOR_PATCH" "$OUTPUT_DIR" "$BUILD_SCRIPT" <<'PY'
import hashlib,json,pathlib,shutil,sys
old,scenario,client,cases,header,patch,out,script=map(pathlib.Path,sys.argv[1:])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
commit='c17ba2d68167d1a892dbdec326bd6cfec32ec9f1'
record=json.loads((old/'result.json').read_text())
if record.get('passed') is not True or record.get('upstream_commit')!=commit:
 raise SystemExit('K03 build record is not the accepted upstream version')
manifest=old/'effective-sources.json'
if sha(manifest)!='43790e9938df1b980f869c787a381eea4febacf04f2cd95e7f8e24dc117b18db':
 raise SystemExit('K03 effective source manifest differs from the accepted build')
sources=json.loads(manifest.read_text())
for item in sources:
 relative=pathlib.PurePosixPath(item['path'])
 if relative.is_absolute() or '..' in relative.parts:
  raise SystemExit('Invalid K03 source path')
 source=old/'source-work'/relative
 if not source.is_file() or source.is_symlink() or not source.resolve().is_relative_to((old/'source-work').resolve()) or sha(source)!=item['sha256']:
  raise SystemExit('K03 effective source differs: '+str(relative))
 target=out/'source-work'/relative;target.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(source,target)
executor=old/'bin/kcov-autorace-k03';executor_sha=sha(executor)
entries=[item for item in record['binaries'] if item['name']=='kcov-autorace-k03']
if len(entries)!=1 or entries[0]['sha256']!=executor_sha:
 raise SystemExit('Original K03 executor differs from its build record')
team=[]
for source,name in [(scenario,'regmap-k07.c'),(client,'regmap-k07-client.c'),(cases,'regmap-k07-cases.h'),(header,'kconc-regmap.h'),(patch,'k05-executor.patch')]:
 shutil.copyfile(source,out/'source-work'/name)
 team.append({'input_path':str(source),'build_copy':name,'sha256':sha(source)})
inputs={'upstream_commit':commit,'upstream_license':'Apache-2.0','k03_build':str(old),
 'k03_build_result_sha256':sha(old/'result.json'),'k03_effective_manifest_sha256':sha(manifest),
 'k03_executor_sha256':executor_sha,'k03_effective_sources':sources,'team_inputs':team,
 'scenario_sha256':sha(scenario),'client_sha256':sha(client),'cases_sha256':sha(cases),'uapi_sha256':sha(header),
 'executor_patch_sha256':sha(patch),'build_script_sha256':sha(script),
 'scope':'New baseline-only entry before candidate search; original K03 replay and trace format retained; no old control plan is reused across kernel identities'}
(out/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print(json.dumps(inputs))
PY
phase=apply-baseline-only-patch
run_logged apply-patch patch --batch --forward --fuzz=0 -p1 \
  -i "$OUTPUT_DIR/source-work/k05-executor.patch" -d "$OUTPUT_DIR/source-work"
phase=compile-executor
run_logged executor-build g++ -std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function \
  -pthread "$OUTPUT_DIR/source-work/kcov-autorace.cpp" -ldw -lcapstone -lelf -ldl \
  -o "$OUTPUT_DIR/bin/kcov-autorace-k07"
phase=compile-scenario
case_ids=(different-registers shared-register)
mode_ids=(shared per-role)
binaries=(kcov-autorace-k07 regmap-k07-client)
for case_index in "${!case_ids[@]}"; do
  for mode_index in "${!mode_ids[@]}"; do
    name="regmap-k07-${case_ids[$case_index]}-${mode_ids[$mode_index]}.so"
    binaries+=("$name")
    run_logged "$name-build" gcc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
      -pthread -I "$OUTPUT_DIR/source-work" -DKCONC_CASE_INDEX="$case_index" -DKCONC_MODE="$mode_index" \
      "$OUTPUT_DIR/source-work/regmap-k07.c" -o "$OUTPUT_DIR/bin/$name"
  done
done
phase=compile-client
run_logged client-build gcc -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread \
  -I "$OUTPUT_DIR/source-work" "$OUTPUT_DIR/source-work/regmap-k07-client.c" \
  -o "$OUTPUT_DIR/bin/regmap-k07-client"
phase=elf-and-loader
for name in "${binaries[@]}"; do
  run_logged "$name-elf" readelf -h "$OUTPUT_DIR/bin/$name"
  run_logged "$name-ldd" ldd "$OUTPUT_DIR/bin/$name"
  if [[ "$name" == *.so ]]; then
    run_logged "$name-symbols" nm -D --defined-only "$OUTPUT_DIR/bin/$name"
  fi
done
phase=usage-entrypoint
if run_logged executor-usage "$OUTPUT_DIR/bin/kcov-autorace-k07"; then usage_rc=0; else usage_rc=$?; fi
printf '{"actual_exit_code":%s,"expected_exit_code":1,"scope":"usage only, no kernel execution"}\n' "$usage_rc" > "$OUTPUT_DIR/usage.json"
phase=final-validation
run_logged final-validation python3 - "$K03_BUILD" "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
old,out=map(pathlib.Path,sys.argv[1:]);inputs=json.loads((out/'inputs.json').read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
binaries=[]
names=['kcov-autorace-k07','regmap-k07-client']+[f'regmap-k07-{case}-{mode}.so' for case in ['different-registers','shared-register'] for mode in ['shared','per-role']]
for name in names:
 elf=(out/'logs'/f'{name}-elf.log').read_text();deps=(out/'logs'/f'{name}-ldd.log').read_text()
 if 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in deps:
  raise SystemExit('Wrong ELF architecture or unresolved dependency: '+name)
 binaries.append({'name':name,'sha256':sha(out/'bin'/name)})
for name in names:
 if name.endswith('.so'):
  symbols={line.split()[-1] for line in (out/'logs'/f'{name}-symbols.log').read_text().splitlines() if line.split()}
  if not {'test_setup','test_thread1','test_thread2','test_end'}.issubset(symbols):
   raise SystemExit('Scenario does not export the four fixed executor entrypoints: '+name)
usage=json.loads((out/'usage.json').read_text());usage_text=(out/'logs/executor-usage.log').read_text()
if usage['actual_exit_code']!=1 or '--k05-baseline' not in usage_text or '--k03-replay' not in usage_text:
 raise SystemExit('Baseline and replay entrypoint usage check failed')
if sha(old/'result.json')!=inputs['k03_build_result_sha256'] or sha(old/'effective-sources.json')!=inputs['k03_effective_manifest_sha256'] or sha(old/'bin/kcov-autorace-k03')!=inputs['k03_executor_sha256']:
 raise SystemExit('Original K03 build changed during K07 build')
for item in inputs['k03_effective_sources']:
 if sha(old/'source-work'/item['path'])!=item['sha256']:
  raise SystemExit('Original K03 source changed during K07 build: '+item['path'])
for item in inputs['team_inputs']:
 if sha(pathlib.Path(item['input_path']))!=item['sha256'] or sha(out/'source-work'/item['build_copy'])!=item['sha256']:
  raise SystemExit('Team input changed during K07 build: '+item['build_copy'])
effective=[{'path':p.relative_to(out/'source-work').as_posix(),'sha256':sha(p)} for p in sorted((out/'source-work').rglob('*')) if p.is_file()]
(out/'effective-sources.json').write_text(json.dumps(effective,indent=2)+'\n')
record={'schema_version':1,'kind':'kconc.scenario.build','scenario':'regmap-mutex-v1',
 'passed':True,'exit_code':0,'inputs':inputs,'binaries':binaries,
 'compiler':'GNU gcc/g++ 12','c_standard':'gnu11','cxx_standard':'gnu++23',
 'kernel_testcase_executed':False,'upstream_input_modified':False,'usage':usage,
 'scope':'Native executor/scenario/client build and loader checks only; real regmap and reset execution must be verified separately'}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(item['sha256']+'  bin/'+item['name']+'\n' for item in binaries))
print(json.dumps(record))
PY

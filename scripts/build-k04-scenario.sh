#!/usr/bin/env bash
# Build the K04 wrapper while preserving the accepted K03 executor bytes.
set -Eeuo pipefail
if [[ $# -ne 3 ]]; then
  printf 'Usage: %s K03_BUILD SCENARIO_C NEW_OUTPUT\n' "$0" >&2
  exit 2
fi
K03_BUILD="$(realpath -- "$1")"
SCENARIO_C="$(realpath -- "$2")"
OUTPUT_DIR="$(realpath -m -- "$3")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
if [[ ! -f "$SCENARIO_C" || -e "$OUTPUT_DIR" || "$OUTPUT_DIR/" == "$K03_BUILD/"* || "$K03_BUILD/" == "$OUTPUT_DIR/"* || "$SCENARIO_C" == "$OUTPUT_DIR/"* ]]; then
  printf 'Use a regular scenario source and a new output separate from K03 inputs\n' >&2
  exit 2
fi
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
run_logged compiler-version gcc --version
run_logged compiler-predefines gcc -dM -E -x c /dev/null
run_logged compiler-major python3 - "$OUTPUT_DIR/logs/compiler-predefines.log" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text().splitlines()
if '#define __GNUC__ 12' not in lines or any(x.startswith('#define __clang__ ') for x in lines):
 raise SystemExit('K04 wrapper requires the accepted GNU gcc 12 toolchain')
PY
phase=input-identity
run_logged input-identity python3 - "$K03_BUILD" "$SCENARIO_C" "$OUTPUT_DIR" "$BUILD_SCRIPT" <<'PY'
import hashlib,json,pathlib,shutil,sys
old,wrapper,out,script=map(pathlib.Path,sys.argv[1:])
commit='c17ba2d68167d1a892dbdec326bd6cfec32ec9f1'
record=json.loads((old/'result.json').read_text())
if record.get('passed') is not True or record.get('upstream_commit')!=commit:
 raise SystemExit('K03 build record is not the accepted upstream version')
source=old/'source-work/testcase/demo-dup-vs-close.c'
data=source.read_bytes()
blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
if blob!='d2c6e1c79d0ff81a716dbb603c5c36a81ad6589e':
 raise SystemExit('Underlying dup/close testcase differs from the locked upstream source')
executor=old/'bin/kcov-autorace-k03'
executor_sha=hashlib.sha256(executor.read_bytes()).hexdigest()
entries=[item for item in record['binaries'] if item['name']=='kcov-autorace-k03']
if len(entries)!=1 or entries[0]['sha256']!=executor_sha:
 raise SystemExit('K03 executor differs from its accepted build record')
target=out/'source-work/testcase'; target.mkdir()
(target/'demo-dup-vs-close.c').write_bytes(data)
shutil.copyfile(wrapper,out/'source-work/dup-close-v1.c')
shutil.copyfile(executor,out/'bin/kcov-autorace-k03')
(out/'bin/kcov-autorace-k03').chmod(0o755)
inputs={'upstream_commit':commit,'upstream_license':'Apache-2.0',
 'k03_build':str(old),'k03_build_result_sha256':hashlib.sha256((old/'result.json').read_bytes()).hexdigest(),
 'k03_executor_sha256':executor_sha,'upstream_source_git_blob':blob,
 'upstream_source_sha256':hashlib.sha256(data).hexdigest(),
 'scenario_sha256':hashlib.sha256(wrapper.read_bytes()).hexdigest(),
 'build_script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
 'scope':'New lifecycle/oracle wrapper and explicit infrastructure fault modes; original two kernel-call operations unchanged'}
(out/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print(json.dumps(inputs))
PY
phase=compile-wrapper
run_logged compile-wrapper gcc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
  "$OUTPUT_DIR/source-work/dup-close-v1.c" -o "$OUTPUT_DIR/bin/dup-close-v1.so"
phase=elf-and-loader
for name in kcov-autorace-k03 dup-close-v1.so; do
  run_logged "$name-elf" readelf -h "$OUTPUT_DIR/bin/$name"
  run_logged "$name-ldd" ldd "$OUTPUT_DIR/bin/$name"
done
phase=final-validation
run_logged final-validation python3 - "$K03_BUILD" "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
old,out=map(pathlib.Path,sys.argv[1:]); inputs=json.loads((out/'inputs.json').read_text()); binaries=[]
for name in ['kcov-autorace-k03','dup-close-v1.so']:
 elf=(out/'logs'/f'{name}-elf.log').read_text(); deps=(out/'logs'/f'{name}-ldd.log').read_text()
 if 'ELF64' not in elf or 'X86-64' not in elf or 'not found' in deps:
  raise SystemExit('Wrong ELF architecture or unresolved dependency: '+name)
 binaries.append({'name':name,'sha256':hashlib.sha256((out/'bin'/name).read_bytes()).hexdigest()})
if binaries[0]['sha256']!=inputs['k03_executor_sha256'] or hashlib.sha256((old/'bin/kcov-autorace-k03').read_bytes()).hexdigest()!=inputs['k03_executor_sha256']:
 raise SystemExit('Executor changed during copy/build')
if hashlib.sha256((old/'source-work/testcase/demo-dup-vs-close.c').read_bytes()).hexdigest()!=inputs['upstream_source_sha256']:
 raise SystemExit('K03 testcase input changed during build')
record={'schema_version':1,'kind':'kconc.scenario.build','scenario':'dup-close-v1',
 'passed':True,'exit_code':0,'inputs':inputs,'binaries':binaries,
 'compiler':'GNU gcc 12','compiler_flags':['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared'],
 'kernel_testcase_executed':False,'fault_modes':['none','setup','hang','cleanup','property'],
 'scope':'Native wrapper build and loader checks only; lifecycle execution is separately accepted'}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(item['sha256']+'  bin/'+item['name']+'\n' for item in binaries))
print(json.dumps(record))
PY

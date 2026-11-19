#!/usr/bin/env bash
# Build the K03 adapter and checked fixtures natively in the openEuler guest.
set -Eeuo pipefail
if [[ $# -ne 5 ]]; then
  printf 'Usage: %s INPUT_SOURCE ADAPTER_HEADER PATCH_FILE CHILD_EXIT_SOURCE NEW_OUTPUT_DIR\n' "$0" >&2
  exit 2
fi
SOURCE_DIR="$(realpath -- "$1")"
ADAPTER_HEADER="$(realpath -- "$2")"
PATCH_FILE="$(realpath -- "$3")"
CHILD_EXIT_SOURCE="$(realpath -- "$4")"
OUTPUT_DIR="$(realpath -m -- "$5")"
BUILD_SCRIPT="$(realpath -- "${BASH_SOURCE[0]}")"
CC="${CC:-gcc}"
CXX="${CXX:-g++}"
if [[ -e "$OUTPUT_DIR" || "$OUTPUT_DIR/" == "$SOURCE_DIR/"* || "$SOURCE_DIR/" == "$OUTPUT_DIR/"* ]]; then
  printf 'Output must be a new directory separate from the source tree\n' >&2
  exit 2
fi
for file in "$ADAPTER_HEADER" "$PATCH_FILE" "$CHILD_EXIT_SOURCE" "$BUILD_SCRIPT"; do
  [[ -f "$file" && "$file" != "$OUTPUT_DIR/"* ]] || { printf 'Invalid input/output separation\n' >&2; exit 2; }
done
mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
mkdir -- "$OUTPUT_DIR"
mkdir -- "$OUTPUT_DIR/logs" "$OUTPUT_DIR/bin" "$OUTPUT_DIR/source-work"
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
run_logged packages rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n'
run_logged cc-version "$CC" --version
run_logged cxx-version "$CXX" --version
run_logged cxx-predefines "$CXX" -dM -E -x c++ /dev/null
run_logged compiler-major python3 - "$OUTPUT_DIR/logs/cxx-predefines.log" <<'PY'
import pathlib,sys
defines=pathlib.Path(sys.argv[1]).read_text().splitlines()
if '#define __GNUC__ 12' not in defines or any(x.startswith('#define __clang__ ') for x in defines):
 raise SystemExit('K03 guest adapter requires the selected GNU g++ 12 compiler')
print('GNU g++ major version 12 confirmed')
PY

phase=source-identity
run_logged source-identity python3 - "$SOURCE_DIR" "$ADAPTER_HEADER" "$PATCH_FILE" "$CHILD_EXIT_SOURCE" "$OUTPUT_DIR" "$BUILD_SCRIPT" <<'PY'
import hashlib,json,pathlib,sys
source,header,patch,negative,output,script=map(pathlib.Path,sys.argv[1:])
expected={
 'LICENSE':'d645695673349e3947e8e5ae42332d0ac3164cd7',
 'README.md':'885062304a5f19540deece205f0b7d9f6d830248',
 'basic.h':'0fce068b62fc9c64468f1ea6b43830df59cf28ac',
 'common.h':'0c39c0b7ed917ad39854879c6355442393423c26',
 'kcov-autorace.cpp':'f56ed7fdeb3f031f90b0eaf60fe45e1833252fc0',
 'kcov-common.h':'be7b7f995e06845c9d7218c0e660d435ed60f21b',
 'runner-common.h':'925fe1ae7842f5b12492e64a2d19a43c5ce69f84',
 'third_party/kcov.h':'3d906728a5407f87b64cd843317fd68a4397e285',
 'testcase/demo-dup-vs-close.c':'d2c6e1c79d0ff81a716dbb603c5c36a81ad6589e'}
upstream=[]
for name,blob in expected.items():
 data=(source/name).read_bytes()
 actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
 if actual!=blob: raise SystemExit('Input differs from locked MAccConc c17ba2d: '+name)
 target=output/'source-work'/name
 target.parent.mkdir(parents=True,exist_ok=True)
 target.write_bytes(data)
 upstream.append({'path':name,'git_blob':actual,'sha256':hashlib.sha256(data).hexdigest()})
# Update these only with an intentional, reviewed adapter/fixture revision.
team=[]
for original,name,wanted in [
 (header,'k03-evidence.h','c847ca9dc9178fe5442e9a6899d012ff391691bb00fa20096be144d54fce52d3'),
 (patch,'k03-evidence.patch','eca89f80e1ec9013da83f1a4859de763c907d938575820ce32f6e136430bae71'),
 (negative,'testcase/child-exit.c','d7c9bdaabc5d205cb13bfa660c139ba4e56ba1c9f292983479d6456965e0d87a')]:
 data=original.read_bytes(); actual=hashlib.sha256(data).hexdigest()
 if actual!=wanted: raise SystemExit('Unknown team input SHA256: '+str(original))
 target=output/'source-work'/name; target.parent.mkdir(parents=True,exist_ok=True)
 target.write_bytes(data)
 team.append({'input_path':str(original),'build_copy':name,'sha256':actual})
result={'upstream_commit':'c17ba2d68167d1a892dbdec326bd6cfec32ec9f1',
 'upstream_files':upstream,'team_inputs':team,'build_script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
 'negative_fixture_scope':'environment failure handling, not a product kernel scenario'}
(output/'inputs.json').write_text(json.dumps(result,indent=2)+'\n')
PY

phase=apply-evidence-patch
run_logged apply-patch patch --batch --forward --fuzz=0 -p1 \
  -i "$OUTPUT_DIR/source-work/k03-evidence.patch" -d "$OUTPUT_DIR/source-work"
phase=compile-autorace
run_logged autorace-build "$CXX" -std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function \
  -pthread "$OUTPUT_DIR/source-work/kcov-autorace.cpp" -ldw -lcapstone -lelf -ldl \
  -o "$OUTPUT_DIR/bin/kcov-autorace-k03"
phase=compile-fixtures
for name in demo-dup-vs-close child-exit; do
  run_logged "$name-build" "$CC" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
    "$OUTPUT_DIR/source-work/testcase/$name.c" -o "$OUTPUT_DIR/bin/$name.so"
done
phase=elf-and-loader
for name in kcov-autorace-k03 demo-dup-vs-close.so child-exit.so; do
  run_logged "$name-elf" readelf -h "$OUTPUT_DIR/bin/$name"
  run_logged "$name-symbol-versions" readelf --version-info "$OUTPUT_DIR/bin/$name"
  run_logged "$name-ldd" ldd "$OUTPUT_DIR/bin/$name"
done
phase=usage-entrypoint
if run_logged autorace-usage "$OUTPUT_DIR/bin/kcov-autorace-k03"; then
  usage_rc=0
else
  usage_rc=$?
fi
printf '{"actual_exit_code":%s,"expected_exit_code":1,"scope":"usage only, no kernel execution"}\n' "$usage_rc" > "$OUTPUT_DIR/usage.json"
phase=final-validation
run_logged final-validation python3 - "$SOURCE_DIR" "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
source,output=map(pathlib.Path,sys.argv[1:]); binaries=[]
for name in ['kcov-autorace-k03','demo-dup-vs-close.so','child-exit.so']:
 elf=(output/'logs'/f'{name}-elf.log').read_text()
 deps=(output/'logs'/f'{name}-ldd.log').read_text()
 if 'ELF64' not in elf or 'X86-64' not in elf: raise SystemExit('Wrong ELF architecture: '+name)
 if 'not found' in deps: raise SystemExit('Missing dynamic library: '+name)
 binaries.append({'name':name,'sha256':hashlib.sha256((output/'bin'/name).read_bytes()).hexdigest()})
usage=json.loads((output/'usage.json').read_text())
usage_text=(output/'logs/autorace-usage.log').read_text()
if usage['actual_exit_code']!=1 or '--k03-record' not in usage_text or '--k03-replay' not in usage_text:
 raise SystemExit('Evidence-enabled usage entry point check failed')
inputs=json.loads((output/'inputs.json').read_text())
for entry in inputs['upstream_files']:
 if hashlib.sha256((source/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:
  raise SystemExit('Original source input changed during build: '+entry['path'])
effective=[{'path':p.relative_to(output/'source-work').as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
           for p in sorted((output/'source-work').rglob('*')) if p.is_file()]
(output/'effective-sources.json').write_text(json.dumps(effective,indent=2)+'\n')
(output/'SHA256SUMS').write_text(''.join(x['sha256']+'  bin/'+x['name']+'\n' for x in binaries))
result={'passed':True,'scope':'native-openEuler-K03-adapter-build-and-loader',
 'upstream_commit':inputs['upstream_commit'],'upstream_input_modified':False,
 'team_inputs':inputs['team_inputs'],'binaries':binaries,
 'c_standard':'gnu11 for the two small C fixtures','cxx_standard':'gnu++23',
 'kernel_testcase_executed':False,'negative_fixture_executed':False,'usage':usage}
(output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
PY

#!/usr/bin/env bash
# Build native openEuler executors without changing the supplied upstream tree.
set -Eeuo pipefail
if [[ $# -ne 3 && $# -ne 4 ]]; then
  printf 'Usage: %s MACCCONC_SOURCE PROBES_DIR NEW_OUTPUT_DIR [COMPAT_PATCH]\n' "$0" >&2
  exit 2
fi
SOURCE_DIR="$(realpath -- "$1")"
PROBES_DIR="$(realpath -- "$2")"
OUTPUT_DIR="$(realpath -m -- "$3")"
CC="${CC:-gcc}"
CXX="${CXX:-g++}"
JOBS="${JOBS:-1}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { printf 'JOBS must be a positive integer\n' >&2; exit 2; }
if [[ -e "$OUTPUT_DIR" || "$OUTPUT_DIR/" == "$SOURCE_DIR/"* || "$SOURCE_DIR/" == "$OUTPUT_DIR/"* || "$OUTPUT_DIR/" == "$PROBES_DIR/"* || "$PROBES_DIR/" == "$OUTPUT_DIR/"* ]]; then
  printf 'Output must be a new directory, separate from both input trees\n' >&2
  exit 2
fi
mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
mkdir -- "$OUTPUT_DIR"
mkdir -- "$OUTPUT_DIR/logs" "$OUTPUT_DIR/bin" "$OUTPUT_DIR/source-work"
phase=preflight
trap 'result=$?; printf "{\"passed\":false,\"phase\":\"%s\",\"exit_code\":%s}\n" "$phase" "$result" > "$OUTPUT_DIR/result.json"; exit "$result"' ERR
run_logged() {
  local name="$1"; shift
  printf '%q ' "$@" >> "$OUTPUT_DIR/commands.log"
  printf '\n' >> "$OUTPUT_DIR/commands.log"
  local result=0
  "$@" > "$OUTPUT_DIR/logs/$name.log" 2>&1 || result=$?
  printf '%s %s\n' "$name" "$result" >> "$OUTPUT_DIR/exit-codes.txt"
  if [[ $result -ne 0 ]]; then cat "$OUTPUT_DIR/logs/$name.log" >&2; fi
  return "$result"
}
run_logged platform python3 -c 'import pathlib,platform; p=pathlib.Path("/etc/os-release").read_text(); print(p); print(platform.uname()); assert "openEuler" in p and platform.machine()=="x86_64"'
run_logged packages rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n'
run_logged cc-version "$CC" --version
run_logged cxx-version "$CXX" --version

phase=source-identity
python3 - "$SOURCE_DIR" "$OUTPUT_DIR" "$PROBES_DIR" <<'PY'
import hashlib,json,pathlib,shutil,sys
source,output,probes=map(pathlib.Path,sys.argv[1:])
expected={
 'Makefile':'246c989e4ad5c7f00140c97a57c951199d4683f0',
 'LICENSE':'d645695673349e3947e8e5ae42332d0ac3164cd7',
 'README.md':'885062304a5f19540deece205f0b7d9f6d830248',
 'basic.h':'0fce068b62fc9c64468f1ea6b43830df59cf28ac',
 'common.h':'0c39c0b7ed917ad39854879c6355442393423c26',
 'kcov-autorace.cpp':'f56ed7fdeb3f031f90b0eaf60fe45e1833252fc0',
 'kcov-common.h':'be7b7f995e06845c9d7218c0e660d435ed60f21b',
 'kcov-terminal.cpp':'e9f80c91820dfd3fa0854aacd95265ff6d945ec8',
 'kcov-vsock-client.c':'06eb34c25c4b99c510a72cb47c8643270ab64c49',
 'runner-common.h':'925fe1ae7842f5b12492e64a2d19a43c5ce69f84',
 'third_party/kcov.h':'3d906728a5407f87b64cd843317fd68a4397e285'}
records=[]
for name,blob in expected.items():
 data=(source/name).read_bytes()
 actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
 if actual!=blob: raise SystemExit('Source differs from locked commit c17ba2d: '+name)
 target=output/'source-work'/name
 target.parent.mkdir(parents=True,exist_ok=True)
 shutil.copy2(source/name,target)
 records.append({'path':name,'git_blob':blob,'sha256':hashlib.sha256(data).hexdigest()})
for name in ['kcov-probe.c','vsock-client.c']:
 data=(probes/name).read_bytes()
 records.append({'probe':name,'sha256':hashlib.sha256(data).hexdigest()})
(output/'inputs.json').write_text(json.dumps({'expected_upstream_commit':'c17ba2d68167d1a892dbdec326bd6cfec32ec9f1','verified_guest_build_input_files':records},indent=2)+'\n')
PY

phase=compatibility-patch
printf '[]\n' > "$OUTPUT_DIR/applied-patches.json"
if [[ $# -eq 4 ]]; then
  COMPAT_PATCH="$(realpath -- "$4")"
  PATCH_SHA="$(sha256sum -- "$COMPAT_PATCH" | cut -d ' ' -f1)"
  [[ "$PATCH_SHA" == '25696af1f34e321812e06d74f5e66bca6fb96fb9759def6b5bd92853749359a1' ]] || { printf 'Unknown compatibility patch\n' >&2; exit 2; }
  run_logged compatibility-patch patch --batch --forward --fuzz=0 -p1 -i "$COMPAT_PATCH" -d "$OUTPUT_DIR/source-work"
  printf '[{"sha256":"%s","scope":"terminal decimal label formatting only"}]\n' "$PATCH_SHA" > "$OUTPUT_DIR/applied-patches.json"
fi

phase=c-standard-option
printf 'int main(void) { return 0; }\n' > "$OUTPUT_DIR/standard-option.c"
C_STANDARD=gnu23
if run_logged c-option-gnu23 "$CC" -std=gnu23 -c "$OUTPUT_DIR/standard-option.c" -o "$OUTPUT_DIR/standard-option.o"; then
  C23_EXIT=0
else
  C23_EXIT=$?
  C_STANDARD=gnu2x
  run_logged c-option-gnu2x "$CC" -std=gnu2x -c "$OUTPUT_DIR/standard-option.c" -o "$OUTPUT_DIR/standard-option.o"
fi
printf '{"gnu23_exit_code":%s,"selected_option":"%s","full_c23_conformance_claimed":false}\n' "$C23_EXIT" "$C_STANDARD" > "$OUTPUT_DIR/c-standard.json"
C_FLAGS="-std=$C_STANDARD -O2 -g -Wall -Wno-unused-function"
if [[ "$C_STANDARD" == gnu2x ]]; then
  # GCC 12's draft C23 mode does not yet provide bool/true/false keywords.
  C_FLAGS+=' -include stdbool.h'
fi
CXX_FLAGS='-std=gnu++23 -O2 -g -Wall -Wformat -Wno-unused-function'
phase=executors-build
run_logged executors-make make -C "$OUTPUT_DIR/source-work" -j"$JOBS" \
  "CC=$CC" "CXX=$CXX" "CFLAGS=$C_FLAGS" "CXXFLAGS=$CXX_FLAGS" \
  'LIBS=-ldw -lcapstone -lelf' kcov-autorace kcov-terminal kcov-vsock-client
for name in kcov-autorace kcov-terminal kcov-vsock-client; do
  cp -- "$OUTPUT_DIR/source-work/$name" "$OUTPUT_DIR/bin/$name"
done
phase=probes-build
run_logged kcov-probe-build "$CC" "-std=$C_STANDARD" -O2 -g -Wall -Wextra -Werror \
  -I "$OUTPUT_DIR/source-work" "$PROBES_DIR/kcov-probe.c" -o "$OUTPUT_DIR/bin/kcov-probe"
run_logged vsock-probe-build "$CC" "-std=$C_STANDARD" -O2 -g -Wall -Wextra -Werror \
  "$PROBES_DIR/vsock-client.c" -o "$OUTPUT_DIR/bin/vsock-client"
phase=elf-and-loader
for name in kcov-autorace kcov-terminal kcov-vsock-client kcov-probe vsock-client; do
  run_logged "$name-elf" readelf -h "$OUTPUT_DIR/bin/$name"
  run_logged "$name-symbol-versions" readelf --version-info "$OUTPUT_DIR/bin/$name"
  run_logged "$name-ldd" ldd "$OUTPUT_DIR/bin/$name"
done
run_logged userspace-abi "$OUTPUT_DIR/bin/kcov-probe" --abi-only
phase=final-validation
python3 - "$OUTPUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
output=pathlib.Path(sys.argv[1]); binaries=[]
for name in ['kcov-autorace','kcov-terminal','kcov-vsock-client','kcov-probe','vsock-client']:
 elf=(output/'logs'/f'{name}-elf.log').read_text()
 deps=(output/'logs'/f'{name}-ldd.log').read_text()
 if 'ELF64' not in elf or 'X86-64' not in elf: raise SystemExit('Unexpected ELF architecture: '+name)
 if 'not found' in deps: raise SystemExit('Unresolved dynamic dependency: '+name)
 binaries.append({'name':name,'sha256':hashlib.sha256((output/'bin'/name).read_bytes()).hexdigest()})
abi=json.loads((output/'logs/userspace-abi.log').read_text())
if not abi['passed'] or abi['abi']['machine']!='x86_64': raise SystemExit('Guest ABI check failed')
(output/'SHA256SUMS').write_text(''.join(x['sha256']+'  bin/'+x['name']+'\n' for x in binaries))
result={'passed':True,'scope':'native-openEuler-build-and-link-ABI','binaries':binaries,'abi':abi,'upstream_input_modified':False,'applied_patches':json.loads((output/'applied-patches.json').read_text()),'gui_built':False,'executors_testcase_run':False,'actual_kcov_ioctl_tested':False,'vsock_transport_tested':False}
(output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
PY

"""Replay the Clang front end of the two reviewed x86 Kbuild command layouts."""
from pathlib import Path
import re
import shlex


# The order is significant. This closed profile comes from the locked normal -O2
# kernel and external-module builds, including diagnostic and target options.
PREFIX = """-D__KERNEL__ --target=x86_64-linux-gnu -fintegrated-as
-Werror=unknown-warning-option -Werror=ignored-optimization-argument
-Werror=option-ignored -Werror=unused-command-line-argument""".split()
OPTIONS = """-Werror -fshort-wchar -funsigned-char -fno-common -fno-PIE
-fno-strict-aliasing -std=gnu11 -fms-anonymous-structs -Wno-gnu -Wno-microsoft-anon-tag
-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -mno-sse4a -fcf-protection=branch
-fno-jump-tables -m64 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mstack-alignment=8
-mskip-rax-setup -march=x86-64 -mtune=generic -mno-red-zone -mcmodel=kernel
-mstack-protector-guard-reg=gs -mstack-protector-guard-symbol=__ref_stack_chk_guard
-Wno-sign-compare -fno-asynchronous-unwind-tables -mretpoline-external-thunk
-mindirect-branch-cs-prefix -mfunction-return=thunk-extern -fpatchable-function-entry=16,16
-fno-delete-null-pointer-checks -O2 -fstack-protector-strong -fomit-frame-pointer
-ftrivial-auto-var-init=zero -fexperimental-late-parse-attributes -fno-stack-clash-protection
-falign-functions=16 -fstrict-flex-arrays=3 -fno-strict-overflow -fno-stack-check
-fno-builtin-wcslen -Wall -Wextra -Wundef -Werror=implicit-function-declaration
-Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security
-Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member -Wmissing-declarations
-Wmissing-prototypes -Wframe-larger-than=2048 -Wno-format-overflow-non-kprintf
-Wno-format-truncation-non-kprintf -Wno-default-const-init-unsafe -Wno-type-limits
-Wno-pointer-sign -Wcast-function-type -Wno-unterminated-string-initialization
-Wimplicit-fallthrough -Werror=date-time -Werror=incompatible-pointer-types -Wenum-conversion
-Wunused -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-format-overflow
-Wno-override-init -Wno-pointer-to-enum-cast -Wno-tautological-constant-out-of-range-compare
-Wno-unaligned-access -Wno-enum-compare-conditional -Wno-missing-field-initializers
-Wno-shift-negative-value -Wno-enum-enum-conversion -Wno-sign-compare -Wno-unused-parameter
-g -gdwarf-5""".split()
OBJTOOL = """--hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --prefix=16
--orc --retpoline --rethunk --static-call --uaccess --link --module""".split()
SAFE_COMPONENT = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*")


def require(condition, message):
    if not condition:
        raise ValueError("unsupported Kbuild command: " + message)


def bound_path(cwd, token, expected, *, exists=True):
    path = cwd / token
    require(".." not in path.parts and path == expected and path.resolve() == expected,
            "unexpected path " + token)
    if exists:
        require(path.exists(), "missing " + token)


def command_location(root, obj, source):
    local = source.with_name("." + source.stem + ".o.cmd")
    choices = [(local, source.parent, Path(source.stem + ".o"), True)]
    if source.is_relative_to(root):
        target = source.relative_to(root).with_suffix(".o")
        choices.append((obj / target.parent / ("." + target.name + ".cmd"), obj, target, False))
    available = [(p, cwd, target, external) for p, cwd, target, external in choices if p.is_file()]
    require(len(available) == 1, "missing or ambiguous translation-unit record")
    path, cwd, target, external = available[0]
    require(path == path.resolve(), "redirected translation-unit record")
    return path, cwd, target, external


def compilation(root: Path, obj: Path, source: Path, clang: Path) -> tuple[list[str], Path]:
    """Return the recorded semantic flags and their actual working directory."""
    root, obj = Path(root).resolve(strict=True), Path(obj).resolve(strict=True)
    source = Path(source).absolute()
    require(source == source.resolve() and source.suffix == ".c" and source.is_file(),
            "invalid or redirected translation unit")
    require(bool(SAFE_COMPONENT.fullmatch(source.stem)), "unsupported source basename")
    clang = Path(clang).resolve(strict=True)
    path, cwd, target, external = command_location(root, obj, source)
    lines = path.read_text(encoding="utf-8").splitlines()
    key = target.as_posix()
    start = "savedcmd_" + key + " := "
    source_key = "source_" + key + " := "
    require(bool(lines) and lines[0].startswith(start) and
            sum(line.startswith("savedcmd_") for line in lines) == 1, "saved object identity")
    source_lines = [line for line in lines if line.startswith("source_")]
    require(len(source_lines) == 1 and source_lines[0].startswith(source_key), "source metadata")
    bound_path(cwd, source_lines[0][len(source_key):], source)
    command, sep, tail = lines[0][len(start):].partition(";")
    argv = shlex.split(command)
    # Clang selects language/driver defaults from argv[0]. A clang++ or clang-cl
    # symlink to these exact bytes would still describe a different compilation.
    require(len(argv) > 6 and Path(argv[0]) in (clang, clang.with_name("clang")) and
            Path(argv[0]).resolve() == clang, "compiler identity")
    require(argv[-4:-2] == ["-c", "-o"] and argv[-2] == key, "compile action or output")
    bound_path(cwd, argv[-2], cwd / target)
    bound_path(cwd, argv[-1], source)
    dep_prefix = "-Wp,-MMD,"
    require(argv[1].startswith(dep_prefix), "dependency arguments")
    dep = cwd / target.parent / ("." + target.name + ".d")
    bound_path(cwd, argv[1][len(dep_prefix):], dep, exists=False)
    if sep:
        expected = [str(obj / "tools/objtool/objtool"), *OBJTOOL, key]
        require(shlex.split(tail) == expected, "unrecognized compiler postprocessing")
    flags = argv[2:-4]
    require(flags[:1] == ["-nostdinc"], "system header search")
    include_paths = (root / "arch/x86/include", obj / "arch/x86/include/generated",
                     root / "include", obj / "include", root / "arch/x86/include/uapi",
                     obj / "arch/x86/include/generated/uapi", root / "include/uapi",
                     obj / "include/generated/uapi")
    require(len(flags) >= 15, "incomplete kernel includes")
    for flag, expected in zip(flags[1:9], include_paths):
        require(flag.startswith("-I"), "include order")
        bound_path(cwd, flag[2:], expected)
    for pos, header in zip((9, 11, 13), ("compiler-version.h", "kconfig.h", "compiler_types.h")):
        require(flags[pos] == "-include", "forced kernel headers")
        bound_path(cwd, flags[pos+1], root / "include/linux" / header)
    fixed = PREFIX + ([] if external else ["-fmacro-prefix-map=" + str(root) + "/="]) + OPTIONS
    require(flags[15:15+len(fixed)] == fixed, "target, optimization or front-end flags changed")
    rest = flags[15+len(fixed):]
    if rest and rest[0].startswith("-I"):
        require(len(rest) >= 2 and rest[1].startswith("-I"), "extra include directory")
        bound_path(cwd, rest[0][2:], source.parent)
        bound_path(cwd, rest[1][2:], (cwd / target).parent)
        rest = rest[2:]
    if rest[:1] == ["-DMODULE"]:
        rest = rest[1:]
    module_file = None
    if rest and rest[0].startswith("-DKBUILD_MODFILE="):
        m = re.fullmatch(r'-DKBUILD_MODFILE="([\w./-]+)"', rest[0], re.ASCII)
        require(m is not None, "KBUILD module file syntax")
        module_file = Path(m[1])
        require(module_file.parent == target.parent and all(SAFE_COMPONENT.fullmatch(p) for p in module_file.parts),
                "KBUILD module file path")
        rest = rest[1:]
    require(len(rest) == 3, "unrecognized module flags")
    normalized = source.stem.replace("-", "_").replace(".", "_")
    name = re.fullmatch(r'-DKBUILD_MODNAME="([a-zA-Z_0-9]+)"', rest[1])
    require(rest[0] == f'-DKBUILD_BASENAME="{normalized}"' and name is not None and
            rest[2] == "-D__KBUILD_MODNAME=" + name[1], "module identifiers")
    if module_file is not None:
        require(module_file.name.replace("-", "_") == name[1], "module file/name mismatch")
    # api_inputs first compares the pinned driver's normal and config-free
    # dry runs. Keep that verified invocation independent of implicit configs.
    return ["--no-default-config", *flags], cwd

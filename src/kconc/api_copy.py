"""Bind an admitted byte copy to its LLVM intrinsic and the linked x86 callback."""
import hashlib
from pathlib import Path
import re
import subprocess

from .api_inputs import file_hash


def require(condition, detail):
    if not condition:
        raise ValueError("unproved bounded copy: " + detail)


def command(argv, cwd):
    p = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True, timeout=120)
    require(p.returncode == 0, p.stderr.decode(errors="replace")[-1000:])
    return p.stdout


def copy_ir(data, name, optimized):
    text = data.decode()
    matches = re.findall(r"^define internal [^\n]*@" + re.escape(name) + r"\([^\n]*\n(.*?)^\}",
                         text, re.M | re.S)
    require(len(matches) == 1, "missing or ambiguous internal callback in LLVM IR")
    calls = [line for line in matches[0].splitlines() if re.search(r"\b(?:call|invoke|callbr)\b", line)]
    require(len(calls) == 1, "callback must lower to a single LLVM copy intrinsic")
    call = re.search(r"\bcall void @llvm\.memcpy\.p0\.p0\.i64\((ptr [^,]+), "
                     r"ptr [^,]*@([A-Za-z_][A-Za-z0-9_]*), i64 6, i1 false\)", calls[0])
    require(call is not None, "copy is not a nonvolatile six-byte intrinsic from a fixed array")
    if optimized:
        require(call[1].endswith(" %3"), "IR destination is not the fourth bus argument")
    return call[2]


def machine_effect(dump, name):
    """Decode the reviewed straight-line stores and local forward size guards."""
    lines = dump.decode().splitlines()
    starts = [i for i, line in enumerate(lines) if re.fullmatch(r"[0-9a-f]+ <" + re.escape(name) + r">:", line)]
    require(len(starts) == 1 and "elf64-x86-64" in dump.decode(), "ambiguous linked x86 function")
    instructions = []
    for line in lines[starts[0]+1:]:
        if not line.strip():
            break
        m = re.fullmatch(r"\s*([a-f0-9]+):\s+((?:[a-f0-9]{2} )+)\s*\t([^\t]+)(?:\t([^\n]+))?", line)
        require(m is not None, "unrecognized instruction record")
        instructions.append((int(m[1], 16), bytes.fromhex(m[2]), m[3].strip(), m[4]))
    require(bool(instructions), "empty callback")
    start = instructions[0][0]
    positions = {addr for addr, _, _, _ in instructions}
    covered, signatures = set(), []
    scalar = r"(?:\$0x[a-f0-9]+|%(?:rax|eax|ax|al|rdx|edx|dx|dl|r8[dwb]?|r9[dwb]?))"
    returned = False
    for addr, raw, op, reloc in instructions:
        require(not returned, "unreviewed instructions after return")
        sig = raw.hex()
        if reloc:
            target = re.fullmatch(r"([a-f0-9]+): R_X86_64_PLT32\s+__x86_return_thunk-0x4", reloc)
            require(target is not None and op.startswith(("cs jmp ", "jmp ")) and
                    raw in (bytes.fromhex("2ee900000000"), bytes.fromhex("e900000000")) and
                    int(target[1], 16) == addr + len(raw) - 4, "callback has an external reference")
            returned = True
            sig += ":__x86_return_thunk"
        elif op in ("ret", "retq"):
            returned = True
        elif op in ("endbr64", "nop"):
            pass
        elif re.fullmatch(r"(?:xor|or|and|add|sub|cmp|test|mov)\s+" + scalar + "," + scalar, op):
            pass
        elif (branch := re.fullmatch(r"j[a-z]+\s+([0-9a-f]+) <[^>]+>", op)):
            require(int(branch[1], 16) in positions and int(branch[1], 16) > addr,
                    "control flow leaves the callback")
        else:
            store = re.fullmatch(r"mov([bwlq])\s+\$0x[0-9a-f]+,(0x[0-9a-f]+)?\(%rcx\)", op)
            require(store is not None, "unrecognized callback effect: " + op)
            off = int(store[2] or "0", 16)
            end = off + {"b": 1, "w": 2, "l": 4, "q": 8}[store[1]]
            require(end <= 6, "store outside the six-byte destination")
            covered.update(range(off, end))
        signatures.append((addr-start, sig))
    require(returned and covered == set(range(6)), "incomplete local copy")
    return signatures


def check_module_copy(root, obj, source, clang, flags, cwd, row, output):
    """Bind the same callback in a fresh compile, the original object and the linked module."""
    source, cwd, out = Path(source).resolve(), Path(cwd).resolve(), Path(output)
    name = row["evidence"]["read_callback"]
    require(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is not None, "invalid callback identifier")
    require(cwd == source.parent and Path(root).resolve() / "drivers" in source.parents,
            "requires an external single-TU driver module in the inspected source tree")
    mod, original, linked = (source.with_suffix(ext) for ext in (".mod", ".o", ".ko"))
    for path in (mod, original, linked):
        require(path.resolve(strict=True) == path and path.is_file(), "redirected or missing module artifact")
    require(mod.read_text().split() in ([original.name], ["./" + original.name]), "not a single-TU module")
    out.mkdir(parents=True, exist_ok=False)
    evidence = {"callback": name, "mode": "llvm_intrinsic_to_bounded_inline_stores",
                "original_object_sha256": file_hash(original), "module_sha256": file_hash(linked)}
    arrays = []
    for label, extra in (("before", ["-Xclang", "-disable-llvm-passes"]), ("normal-O2", [])):
        data = command([clang, *flags, *extra, "-emit-llvm", "-S", "-o", "-", source], cwd)
        (out / (label + ".ll")).write_bytes(data)
        arrays.append(copy_ir(data, name, bool(not extra)))
        evidence[label + "_ir_sha256"] = hashlib.sha256(data).hexdigest()
    require(arrays[0] == arrays[1], "source array changes between IR stages")
    fresh = out / "recompiled.o"
    command([clang, *flags, "-c", "-o", fresh.resolve(), source], cwd)
    effects = []
    for label, binary in (("recompiled", fresh.resolve()), ("original", original), ("linked", linked)):
        symbols = command(["nm", "-S", binary], cwd).decode()
        require(len(re.findall(r"^[0-9a-f]+ [0-9a-f]+ t " + re.escape(name) + "$", symbols, re.M)) == 1,
                "callback is not uniquely defined with local text linkage")
        dump = command(["objdump", "-drw", "--disassemble=" + name, binary], cwd)
        (out / (label + ".asm")).write_bytes(dump)
        effect = machine_effect(dump, name)
        if any(":__x86_return_thunk" in sig for _, sig in effect):
            require(re.search(r"^\s+U __x86_return_thunk$", symbols, re.M) is not None and
                    re.search(r"^[a-f0-9]+ .* __x86_return_thunk$", symbols, re.M) is None,
                    "module supplies its own return thunk")
        effects.append(effect)
    require(effects[0] == effects[1] == effects[2], "linked callback differs from the current translation unit")
    evidence.update(source_array=arrays[0], destination_bytes=list(range(6)), instructions=effects[0])
    return evidence

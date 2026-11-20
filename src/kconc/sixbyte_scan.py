"""Find direct bulk reads and bind two SPI call sites to audited Linux source."""
import hashlib
from pathlib import Path
import re


REVISION = "2fc2e45b0cd75cd56f252a0872a6d039f46cc42b"
ACCEL = "drivers/iio/accel/"
BMA_CORE = ACCEL + "bma400_core.c"
KX_CORE = ACCEL + "kionix-kx022a.c"

# Byte identity binds the constructor, lifetime and dispatch review to the actual
# sources. A recognizable read alone does not identify its bus or object owner.
SHARED_INPUTS = {
    "drivers/base/regmap/regmap.c": "3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9",
    "drivers/base/regmap/internal.h": "ba77ebe952556f58a2814386357fdd40d08680fdc000241e2263f7dab5e18e25",
    "include/linux/regmap.h": "997a1abbc10459fd2651aadb1f8f9365633002603f2423d04108fe84be098b17",
    "drivers/base/regmap/regcache.c": "075eaa501708463495be83048ed3a6077dcfe80fd27cb3ec1b0c1c4f3bfda718",
    "drivers/base/regmap/regmap-debugfs.c": "6a3aa0eae0efa081b6612a51e2ba462607b41cdd3af92621d68a6541fcffc998",
    "drivers/base/devres.c": "71e9a931b8746a85a0c67c9f2370aace6aa2c1c67e1110cf49e157fb79522d4d",
    "drivers/spi/spi.c": "19c129f9ad7e7ebf0fb10e668e1f4e086bf4f1bb3d0a12c6cbaeb5d0fffd2c70",
    "include/linux/spi/spi.h": "f11fcffd5030470e35803043b777e594d1a31a3e2d467674de63626d7008c048",
    "drivers/iio/industrialio-core.c": "46fd57c3ab7e99a9f15a3a2466e27d93854f5aab28886f68f4815cef38f5179c",
    "drivers/iio/industrialio-trigger.c": "cb8379dafb180288411b608e78fb0332a258700ff845f8c89573f5c601da95b3",
    "drivers/iio/industrialio-buffer.c": "566d083142922a269d96b7e0c8ad8abc34ab1e55c15ca7fd6b4ab80d563ecc99",
    "drivers/iio/buffer/industrialio-triggered-buffer.c": "ed29a509f5646bd44d0083153ed5654ed49c8cebc9d1d6954a1244a1dcd75227",
    "drivers/iio/accel/Kconfig": "c9fc4a7e32d67c91fda3f2e536ec3bf80380d1deb924cc9dc7a2b5f98ff46c5a",
    "drivers/iio/accel/Makefile": "029911b13fc79ccd8225bc7da29ddd1e26528c842bd4f20facb367b39eabc71c",
}
PROFILE_INPUTS = {
    "bma400-spi": {
        BMA_CORE: "9b26e0a96e5b371d99d5cd849dd2465ed1bbe7565e9304cc6fdedb329869dc6d",
        ACCEL + "bma400.h": "36837246ac0313b42b30e8de995c278037c4f5b6d1e57bfac5b50847b2a5cf61",
        ACCEL + "bma400_spi.c": "d0c9f63e1317e6fa0ee8f413b2ffbf57087e845fa44cd2eee5d918bb28159933",
    },
    "kx022a-spi": {
        KX_CORE: "e34f60667020b7f8ccf67994b1209c0d4bbd287e560b15738b3546b0d767a5da",
        ACCEL + "kionix-kx022a.h": "183243ad117ede80c0ad04991ca2fb2ae074e83c04212063a159006e4e4157ea",
        ACCEL + "kionix-kx022a-spi.c": "728f652a0c5919960863c6c71d4ef77c7c43ec6acfb835b9f6c85991f96776e5",
        "drivers/base/regmap/regmap-spi.c": "239404fff12be8c1c3c0b0b92ab23c860ff88b7306713bef45b0dd4d2379cb6d",
    },
}
SITES = {
    BMA_CORE: ("bma400-spi", "bma400_trigger_handler", 0x04,
               ("data->regmap", "BMA400_ACC_X_LSB_REG", "&data->buffer.buff", "sizeof(data->buffer.buff)")),
    KX_CORE: ("kx022a-spi", "kx022a_trigger_handler", 0x06,
              ("data->regmap", "data->chip_info->xout_l", "data->buffer", "KX022A_FIFO_SAMPLES_SIZE_BYTES")),
}


def input_hashes(kernel, expected):
    """Hash ordinary input files under the kernel root, including their path binding."""
    kernel = Path(kernel).resolve()
    result = {}
    for relative in sorted(expected):
        path = kernel / relative
        if path.resolve() != path or not path.is_file():
            result[relative] = None
        else:
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


# Blanking comments/literals preserves offsets and lines, including non-ASCII
# comments (the source is decoded one byte per code point).
_TRIVIA = re.compile(r'''/\*[\s\S]*?\*/|//(?:\\\r?\n|[^\n])*|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*' ''', re.X)
_CALL = re.compile(r"\bregmap_bulk_read\s*\(")
_PUNCT = re.compile(r"[()\[\]{},]")
_NUMBER = r"(0[xX][\da-fA-F]+|[1-9]\d*|0)[ulUL]*"
_DEFINE = re.compile(r"^\s*#\s*define[ \t]+(\w+)[ \t]+\(?[ \t]*" + _NUMBER + r"[ \t]*\)?[ \t]*$", re.M)


def _calls(source):
    for call in _CALL.finditer(source):
        depth = 1
        begin = call.end()
        args = []
        for token in _PUNCT.finditer(source, begin):
            value = token.group()
            pos = token.start()
            if value in "([{":
                depth += 1
            elif value in ")]}":
                depth -= 1
            if depth == 0 or (value == "," and depth == 1):
                args.append(source[begin:pos].strip())
                begin = pos + 1
            if depth == 0:
                if len(args) == 4:
                    yield call.start(), pos + 1, args
                break


def _integer(expr, definitions):
    match = re.fullmatch(_NUMBER, expr.strip())
    if match:
        return int(match[1], 0)
    return definitions.get(expr)


def _scan_file(source, relative, mismatches, content_hash, coverage):
    code = _TRIVIA.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), source)
    defines = {}
    for name, value in _DEFINE.findall(code):
        defines[name] = None if name in defines else int(value, 0)
    site = SITES.get(relative)
    for offset, end, args in _calls(code):
        coverage["direct_four_argument_sites"] += 1
        simple = tuple(re.sub(r"\s", "", arg) for arg in args)
        count = _integer(simple[3], defines)
        recognizable = site is not None and simple == site[3]
        if not recognizable and count is not None and count != 6:
            coverage["other_value_counts"] += 1
            continue
        row = dict(source=relative, line=code.count("\n", 0, offset)+1,
                   line_end=code.count("\n", 0, end)+1, offset=offset, end_offset=end,
                   args=args, length=count, profile=None, decision="keep_original",
                   reason="unresolved_value_count" if count is None else "unreviewed_map_and_caller",
                   byte_length=None)
        if recognizable:
            profile, function, register, _ = site
            problems = list(mismatches[profile])
            if content_hash != PROFILE_INPUTS[profile][relative] and relative not in problems:
                problems.append(relative)
            row.update(profile=profile, function=function)
            if problems:
                row.update(reason="source_binding_mismatch", mismatched_inputs=problems)
            else:
                row.update(length=6, byte_length=6, start_register=register, decision="matched",
                           reason="reviewed_spi_object_and_exact_call_site")
        yield row


def scan(kernel, drivers="drivers"):
    """Scan driver sources; 'matched' is a source match, conditional on proof and runtime admission."""
    root = Path(kernel).resolve(strict=True)
    scope = root / drivers
    if scope.resolve() != scope or root / "drivers" not in (scope, *scope.parents):
        raise ValueError("Scan scope must name ordinary files or directories under drivers/")
    if not scope.is_dir() and not scope.is_file():
        raise FileNotFoundError(scope)
    expected = dict(SHARED_INPUTS)
    for files in PROFILE_INPUTS.values():
        expected.update(files)
    observed = input_hashes(root, expected)
    mismatches = {p: sorted(k for k, v in {**SHARED_INPUTS, **deps}.items() if observed[k] != v)
                  for p, deps in PROFILE_INPUTS.items()}
    rows = []
    files_read = 0
    coverage = {"direct_four_argument_sites": 0, "other_value_counts": 0}
    paths = sorted(scope.rglob("*")) if scope.is_dir() else [scope]
    for path in paths:
        if path.suffix not in (".c", ".h") or path.is_symlink() or not path.is_file():
            continue
        raw = path.read_bytes()
        files_read += 1
        if b"regmap_bulk_read" not in raw:
            continue
        relative = path.relative_to(root).as_posix()
        content_hash = hashlib.sha256(raw).hexdigest() if relative in SITES else None
        rows.extend(_scan_file(raw.decode("latin1"), relative, mismatches, content_hash, coverage))
    coverage["unresolved_value_counts"] = sum(row["length"] is None for row in rows)
    return {"revision_of_review": REVISION, "scope": scope.relative_to(root).as_posix(),
            "files_read": files_read, "inputs": observed, "mismatched_inputs": mismatches,
            "coverage": coverage, "candidates": rows}

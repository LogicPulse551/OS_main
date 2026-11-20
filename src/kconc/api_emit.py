"""Lower proved, still-current AST call sites to one shared local-map read."""
import hashlib
from pathlib import Path, PurePosixPath
import re

from .sixbyte_emit import GUARDED_LOOP, LOOP
from .sixbyte_scan import SHARED_INPUTS


REGMAP = "drivers/base/regmap/regmap.c"
HEADER = "include/linux/regmap.h"
ORIGINAL = b"regmap_bulk_read"
ENTRY = b"kconc_local_sixbyte_read"
EXPORT = b"EXPORT_SYMBOL_GPL(regmap_bulk_read);"
PUBLIC_DECL = (b"int regmap_bulk_read(struct regmap *map, unsigned int reg, void *val,\n"
               b"\t\t     size_t val_count);")
ARGUMENTS = b"(struct regmap *map, unsigned int reg, void *val,\n\t\t     size_t val_count)"
GATE = b"""
static bool kconc_keep_callback_entries __ro_after_init;

static int __init kconc_read_observation(char *mode)
{
	bool enabled;

	/* An unknown boot setting preserves observable callback entries. */
	kconc_keep_callback_entries = kstrtobool(mode, &enabled) || enabled;
	return 1;
}
__setup("kconc.observe_callbacks=", kconc_read_observation);

int kconc_local_sixbyte_read(struct regmap *map, unsigned int reg, void *val,
			     size_t val_count)
{
	if (kconc_keep_callback_entries || val_count != 6 ||
	    map->format.val_bytes != 1 ||
	    map->format.parse_inplace != regmap_parse_inplace_noop)
		return regmap_bulk_read(map, reg, val, val_count);

	return kconc_sixbyte_guarded(map, reg, val, val_count);
}
EXPORT_SYMBOL_GPL(kconc_local_sixbyte_read);
"""


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _read(kernel, name, expected):
    path = kernel / name
    if path.resolve() != path or not path.is_file():
        raise ValueError("Source is missing or redirected: " + name)
    value = path.read_bytes()
    if _digest(value) != expected:
        raise ValueError("Source changed after analysis: " + name)
    return value


def _replace_once(data, anchor, new):
    if data.count(anchor) != 1:
        raise ValueError("Kernel source no longer has the reviewed definition")
    return data.replace(anchor, new, 1)


def framework_overlay(kernel_root):
    """Only the kernel library is pinned; callers are identified by their analyzed bytes."""
    kernel = Path(kernel_root).resolve(strict=True)
    original = _read(kernel, REGMAP, SHARED_INPUTS[REGMAP])
    header = _read(kernel, HEADER, SHARED_INPUTS[HEADER])
    start = original.index(b"\nint " + ORIGINAL + b"(") + 1
    end = original.index(EXPORT, start)
    public = original[start:end].rstrip()
    private = _replace_once(public, b"int " + ORIGINAL + b"(", b"static int kconc_sixbyte_guarded(")
    private = _replace_once(private, LOOP.encode(), GUARDED_LOOP.encode())
    includes = b'#include "internal.h"'
    core = _replace_once(original, includes, includes + b"\n#include <linux/init.h>\n#include <linux/kstrtox.h>")
    core = _replace_once(core, EXPORT, EXPORT + b"\n\n" + private + b"\n" + GATE.rstrip())
    declared = _replace_once(header, PUBLIC_DECL, PUBLIC_DECL + b"\nint " + ENTRY + ARGUMENTS + b";")
    # A tree reused with regmap disabled still reaches Linux's matching inline stub.
    start = declared.index(b"static inline int regmap_bulk_read(")
    end = declared.index(b"\n}\n", start) + 3
    stub = (b"\nstatic inline int " + ENTRY + ARGUMENTS +
            b"\n{\n\treturn regmap_bulk_read(map, reg, val, val_count);\n}\n")
    return {REGMAP: core, HEADER: declared[:end] + stub + declared[end:]}


def emit_overlay(kernel_root, admitted):
    """Replace only the callee token at each proved direct spelling location."""
    kernel = Path(kernel_root).resolve(strict=True)
    for row in admitted:
        if type(row.get("register")) != int or not 0 <= row["register"] <= 0xffffffff:
            raise ValueError("Call site lacks a proved admission or address")
    return driver_overlay(kernel, admitted, framework_overlay(kernel), ENTRY) if admitted else {}


def driver_overlay(kernel, admitted, framework, entry):
    """Copy the four argument expressions verbatim, including dynamic registers."""
    groups = {}
    for row in admitted:
        name = row["source"]
        rel = PurePosixPath(name)
        if (rel.as_posix() != name or not name.startswith("drivers/") or
                rel.suffix != ".c" or ".." in rel.parts or "\\" in name):
            raise ValueError("Expected an in-tree driver C source")
        if row.get("decision") != "admit" or type(row.get("offset")) != int:
            raise ValueError("Call site lacks a proved admission or address")
        groups.setdefault(name, []).append(row)
    if not groups:
        return {}
    overlay = dict(framework)
    for name, rows in groups.items():
        if name in overlay:
            raise ValueError("The optimizer runtime cannot be a driver call site")
        original = _read(kernel, name, rows[0]["source_sha256"])
        parts = []
        cursor = 0
        for row in sorted(rows, key=lambda item: item["offset"]):
            off = row["offset"]
            end = off + len(ORIGINAL)
            if (row["source_sha256"] != rows[0]["source_sha256"] or off < cursor or
                    original[off:end] != ORIGINAL or
                    (off and re.match(rb"[a-zA-Z_0-9]", original[off-1:off])) or
                    re.match(rb"[a-zA-Z_0-9]", original[end:end+1])):
                raise ValueError("Call-site byte range no longer matches the direct callee")
            parts.extend([original[cursor:off], entry])
            cursor = end
        overlay[name] = b"".join([*parts, original[cursor:]])
    return overlay

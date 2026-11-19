"""Generate the built-in, fixture-owned BMA400 six-byte read for the pinned kernel."""
import hashlib


REGMAP_SHA256 = "3d4b622a577f2a008539727d9d26b422112da67dcea170e05ba9d567e2f5a7a9"
FIXTURE_SHA256 = "0cb34466830fa4ad55463c8fb3eade6b3ef2e0fff486d120bbe91bb69015e4fb"


def _replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError("missing or ambiguous source anchor: " + old.splitlines()[0])
    return source.replace(old, new)


def _definition(source, start, symbol):
    if source.count(start) != 1:
        raise ValueError("unexpected function declaration: " + symbol)
    end = "\nEXPORT_SYMBOL_GPL(" + symbol + ");"
    return source[source.index(start):source.index(end, source.index(start))]


_LOOP = """\t\tfor (i = 0; i < val_count * val_bytes; i += val_bytes)
\t\t\tmap->format.parse_inplace(val + i);"""
_GUARDED_LOOP = """\t\tif (map->format.parse_inplace != regmap_parse_inplace_noop) {
\t\t\tfor (i = 0; i < val_count * val_bytes; i += val_bytes)
\t\t\t\tmap->format.parse_inplace(val + i);
\t\t}"""


def _private_functions(regmap, variant):
    # Keep the shipped constructors/readers verbatim. Derive the private bodies
    # from those same pinned definitions so changes to the upstream ABI fail closed.
    declaration = "struct regmap *__regmap_init(struct device *dev,"
    ctor = _definition(regmap, declaration, "__regmap_init")
    ctor = _replace(ctor, declaration, "static struct regmap *kconc_bma400_create_map(struct device *dev,")
    ctor = _replace(ctor, "\tret = regmap_set_name(map, config);",
                    "\tregmap_debugfs_disable(map);\n\n\tret = regmap_set_name(map, config);")
    declaration = "int regmap_bulk_read(struct regmap *map,"
    read = _definition(regmap, declaration, "regmap_bulk_read")
    read = _replace(read, declaration, "static int kconc_bma400_bulk_read(struct regmap *map,")
    if variant == "optimized":
        read = _replace(read, _LOOP, _GUARDED_LOOP)
    regmap = _replace(regmap, "EXPORT_SYMBOL_GPL(__regmap_init);", "EXPORT_SYMBOL_GPL(__regmap_init);\n\n" + ctor)
    return _replace(regmap, "EXPORT_SYMBOL_GPL(regmap_bulk_read);", "EXPORT_SYMBOL_GPL(regmap_bulk_read);\n\n" + read)


_PRIVATE_OPEN = """\tconst struct regmap_bus *bus = checking ? &check_bus : &measurement_bus;
\tstruct regmap *map;

\t/* The foreign control has a real map but never receives an owner binding. */
\tif (!strcmp(mode, "foreign"))
\t\treturn regmap_init(NULL, bus, t, &config);
\tmap = __regmap_lockdep_wrapper(kconc_bma400_create_map, "BMA400 fixture",
\t\t\t\t      NULL, bus, t, &config);
\tt->use_private_read = !strcmp(mode, "bench") || !strcmp(mode, "check");
\tif (!IS_ERR(map))
\t\tt->owned_map = map;
\treturn map;"""

_DISPATCH = """static int kconc_bma400_read(struct transport *owner, struct regmap *map,
\t\t\t     unsigned int reg, u8 *data, size_t count)
{
\tif (owner->owned_map != map || owner->value_bytes != 1 ||
\t    reg != FIRST_REG || count != BYTES ||
\t    !owner->use_private_read || map->bus_context != owner ||
\t    (map->bus != &measurement_bus && map->bus != &check_bus))
\t\treturn regmap_bulk_read(map, reg, data, count);
\treturn kconc_bma400_bulk_read(map, reg, data, count);
}

"""


def _fixture_body(fixture):
    fixture = _replace(fixture, 'static char *mode = "check";',
                       '#undef MODULE_PARAM_PREFIX\n#define MODULE_PARAM_PREFIX "kconc_bma400."\n'
                       'static char *mode = "off";')
    fixture = _replace(fixture, "struct transport {", "struct transport {\n\tstruct regmap *owned_map;\n\tbool use_private_read;")
    fixture = _replace(fixture, "\treturn regmap_init(NULL, checking ? &check_bus : &measurement_bus, t, &config);",
                       _PRIVATE_OPEN)
    fixture = _replace(fixture, "static int check_read(", _DISPATCH+"static int check_read(")
    fixture = _replace(fixture, "c->rc = regmap_bulk_read(map,", "c->rc = kconc_bma400_read(t, map,")
    fixture = _replace(fixture, "r->result = regmap_bulk_read(map,", "r->result = kconc_bma400_read(t, map,")
    fixture = _replace(fixture, "\tif (!calls ||", '\tif (!strcmp(mode, "off"))\n\t\treturn 0;\n\tif (!calls ||')
    fixture = _replace(fixture, 'if (!strcmp(mode, "check"))\n\t\tret = run_checks();',
                       'if (!strcmp(mode, "check") || !strcmp(mode, "foreign"))\n\t\tret = run_checks();')
    fixture = _replace(fixture, 'else if (!strcmp(mode, "bench") || !strcmp(mode, "raw"))',
                       'else if (!strcmp(mode, "bench") || !strcmp(mode, "raw") || !strcmp(mode, "observe"))')
    fixture = _replace(fixture, 'debugfs_create_dir("kconc-c02-bulk", NULL)', 'debugfs_create_dir("kconc-bma400", NULL)')
    fixture = fixture[:fixture.index("static void __exit bulk_exit(void)")] + "late_initcall(bulk_init);\n"
    # The built-in TU already emitted regmap trace definitions.
    return "\n#undef CREATE_TRACE_POINTS\n" + fixture


def generate(regmap: bytes, fixture: bytes, variant: str) -> bytes:
    """Return one complete drivers/base/regmap/regmap.c for a private comparison."""
    if variant not in ("original", "optimized"):
        raise ValueError("unsupported BMA400 build variant")
    if hashlib.sha256(regmap).hexdigest() != REGMAP_SHA256:
        raise ValueError("unrecognized regmap.c")
    if hashlib.sha256(fixture).hexdigest() != FIXTURE_SHA256:
        raise ValueError("unrecognized BMA400 fixture")
    source = _private_functions(regmap.decode("utf8"), variant)
    return (source + _fixture_body(fixture.decode("utf8"))).encode("utf8")

"""Generate a source overlay for admitted SPI reads from byte-bound Linux inputs."""
import hashlib
from pathlib import Path

from .sixbyte_scan import ACCEL, BMA_CORE, KX_CORE, PROFILE_INPUTS, SHARED_INPUTS


REGMAP = "drivers/base/regmap/regmap.c"
INTERNAL = "drivers/base/regmap/internal.h"
HEADER = "include/linux/kconc-regmap.h"
BOARD_INPUTS = {
    "bma400-spi": {"kernel/sixbyte-boards/bma400_board.c":
                   "4aa991e39d9d6c2728aea7f4f34dc26bf99039566d54ac14fd5340bd6b665830"},
    "kx022a-spi": {"kernel/sixbyte-boards/kx022a_lab.c":
                   "d942c8a0ac7e231a4ee05d6656e0f72dbef96bfe2f7a9ba6c0dc0646be9789fd"},
}
BOARD_MAKEFILE = {"kernel/sixbyte-boards/Makefile":
                  "bec6aea16c1e9a82dd8ced3d3faee457dc53076f8deff6406bac36c452c176fc"}

# Probe registration, controller identity and fallback precede the Clight cut.
# Pin those reviewed generated translation units independently of the emitter.
REVIEWED_SHARED = {
    HEADER: "2808ba19b1412cca553a98aa5721bb09e6b0cbff3fd95d442a3620bd4b59fbf2",
    INTERNAL: "0d51817d8b562d27e80638f32f43815fc3eb01d30f14216aea9247f792d15291",
}
REVIEWED_DRIVERS = {
    "bma400-spi": {
        BMA_CORE: "5b6f205c2075ef09dfeab31fc2455e1c4a3a31d15fd9e2790dd4addf92e6b276",
        ACCEL + "bma400_spi.c": "937858ee723336c7f17b6761335778b23332da2781632b637d2a5640a48f8102",
    },
    "kx022a-spi": {
        KX_CORE: "e7f98123ca6fa4540b818271bf26d5116fe179b0894f6896925f6522dcdea672",
        ACCEL + "kionix-kx022a-spi.c": "3c37c85babead29c6a897c810df5119eee91b413317e5bda9f838a981b0dfb6c",
    },
}
REVIEWED_REGMAP = {
    ("bma400-spi",): "a7e7cdb7c897f0bbfad098e5b53670620122930fd2c79af0e7fe99cd31294a2a",
    ("kx022a-spi",): "d543ba85b0a6e780a7a5c1066db8450647cc3469257060047d431b1baba61f6c",
    ("bma400-spi", "kx022a-spi"): "1a4fa64bbd166d284b56c47d0202fa7c46166a18f0dfb927c00497897dba67d3",
}
PROTOTYPES = """/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KCONC_REGMAP_H
#define _LINUX_KCONC_REGMAP_H

#include <linux/regmap.h>

struct spi_controller;
bool kconc_bma400_spi_controller(const struct spi_controller *candidate);
bool kconc_kx022a_spi_controller(const struct spi_controller *candidate);
void kconc_sixbyte_register(struct regmap *map, unsigned int start);
int kconc_sixbyte_bulk_read(struct regmap *map, unsigned int reg, void *val,
			    size_t val_count);

#endif
"""
LOOP = """		for (i = 0; i < val_count * val_bytes; i += val_bytes)
			map->format.parse_inplace(val + i);"""
GUARDED_LOOP = """		if (map->format.parse_inplace != regmap_parse_inplace_noop) {
			for (i = 0; i < val_count * val_bytes; i += val_bytes)
				map->format.parse_inplace(val + i);
		}"""
GATES = """
static bool kconc_observe_callbacks __ro_after_init;

static int __init kconc_callback_observation(char *value)
{
	bool observe;

	/* An unrecognized observation setting conservatively keeps every call. */
	kconc_observe_callbacks = kstrtobool(value, &observe) || observe;
	return 1;
}
__setup("kconc.observe_callbacks=", kconc_callback_observation);

void kconc_sixbyte_register(struct regmap *map, unsigned int start)
{
	/* The SPI probe owns this new map. Its IIO handler is not registered yet. */
	if (kconc_observe_callbacks || !map->read || map->use_single_read ||
	    map->format.val_bytes != 1 || map->reg_stride != 1 ||
	    map->format.parse_inplace != regmap_parse_inplace_noop)
		return;
	if ((start == 4 && map->max_raw_read == 2) ||
	    (start == 6 && (!map->max_raw_read || map->max_raw_read >= 6)))
		WRITE_ONCE(map->kconc_sixbyte_start, start);
}
EXPORT_SYMBOL_FOR_MODULES(kconc_sixbyte_register, "SPI_MODULES");

int kconc_sixbyte_bulk_read(struct regmap *map, unsigned int reg, void *val,
			    size_t val_count)
{
	if (val_count != 6 || !reg || READ_ONCE(map->kconc_sixbyte_start) != reg ||
	    map->format.val_bytes != 1)
		return regmap_bulk_read(map, reg, val, val_count);
	return kconc_sixbyte_guarded(map, reg, val, val_count);
}
EXPORT_SYMBOL_FOR_MODULES(kconc_sixbyte_bulk_read, "CORE_MODULES");
"""
PROFILE_EDITS = {
    "bma400-spi": (
        BMA_CORE, "regmap_bulk_read(data->regmap, BMA400_ACC_X_LSB_REG,",
        ACCEL + "bma400_spi.c",
        "\treturn bma400_probe(&spi->dev, regmap, spi->irq, id->name);",
        """	if (id && !strcmp(id->name, "bma400") && kconc_reviewed_controller(spi) &&
	    spi_max_transfer_size(spi) >= 3 && spi_max_message_size(spi) >= 4)
		kconc_sixbyte_register(regmap, BMA400_ACC_X_LSB_REG);

""",
    ),
    "kx022a-spi": (
        KX_CORE, "regmap_bulk_read(data->regmap, data->chip_info->xout_l, data->buffer,",
        ACCEL + "kionix-kx022a-spi.c",
        "\treturn kx022a_probe_internal(dev, chip_info);",
        """	if (chip_info == &kx022a_chip_info && kconc_reviewed_controller(spi) &&
	    spi_max_transfer_size(spi) >= 6 && spi_max_message_size(spi) >= 7)
		kconc_sixbyte_register(regmap, KX022A_REG_XOUT_L);

""",
    ),
}


def _once(source, anchor, replacement):
    if source.count(anchor) != 1:
        raise ValueError("Expected one source anchor: " + anchor)
    return source.replace(anchor, replacement)


def _include_private_api(source):
    return _once(source, "#include <linux/regmap.h>", "#include <linux/kconc-regmap.h>")


def _controller_check(source, profile):
    model = profile.removesuffix("-spi")
    symbol = "kconc_" + model + "_spi_controller"
    probe = "static int " + model + "_spi_probe("
    validator = f"""static bool kconc_reviewed_controller(struct spi_device *spi)
{{
	bool (*check)(const struct spi_controller *) = symbol_get({symbol});
	bool matched;

	if (!check)
		return false;
	matched = check(spi->controller);
	symbol_put({symbol});
	return matched;
}}

"""
    return _once(source, probe, validator + probe)


def _regmap_overlay(source, selected):
    start = source.index("int regmap_bulk_read(")
    export = "EXPORT_SYMBOL_GPL(regmap_bulk_read);"
    old = source[start:source.index(export, start)].rstrip()
    guarded = _once(old, "int regmap_bulk_read(", "static int kconc_sixbyte_guarded(")
    guarded = _once(guarded, LOOP, GUARDED_LOOP)
    source = _once(source, '#include "internal.h"',
                   '#include "internal.h"\n#include <linux/init.h>\n#include <linux/kstrtox.h>\n#include <linux/kconc-regmap.h>')
    cores = ",".join(Path(PROFILE_EDITS[p][0]).stem for p in selected)
    buses = ",".join(Path(PROFILE_EDITS[p][2]).stem for p in selected)
    gates = GATES.replace("SPI_MODULES", buses).replace("CORE_MODULES", cores)
    return _once(source, export, export + "\n\n" + guarded + "\n" + gates.rstrip())


def checked_boards(repository, profiles):
    """Bind the board-side identity check and the software SPI transfer implementation."""
    root = Path(repository).resolve(strict=True)
    expected = dict(BOARD_MAKEFILE)
    for profile in profiles:
        expected.update(BOARD_INPUTS[profile])
    for name, locked in expected.items():
        path = root / name
        if (path.resolve() != path or not path.is_file() or
                hashlib.sha256(path.read_bytes()).hexdigest() != locked):
            raise ValueError("Unreviewed controller provider: " + name)
    return expected


def check_reviewed_overlay(profiles, overlay):
    """Reject missing, extra or unreviewed output before it is written or certified."""
    selected = tuple(sorted(set(profiles)))
    if not selected and not overlay:
        return {}
    if selected not in REVIEWED_REGMAP:
        raise ValueError("No reviewed output for these SPI admissions")
    expected = {**REVIEWED_SHARED, REGMAP: REVIEWED_REGMAP[selected]}
    for profile in selected:
        expected.update(REVIEWED_DRIVERS[profile])
    actual = {name: hashlib.sha256(data).hexdigest() for name, data in overlay.items()}
    if actual != expected:
        raise ValueError("Generated kernel overlay differs from the reviewed SPI gates")
    return actual


def emit_overlay(source_root, admitted):
    """Return replacement bytes; a changed dependency invalidates the admission."""
    selected = sorted(set(admitted))
    if not selected:
        return {}
    if set(selected) - PROFILE_INPUTS.keys():
        raise ValueError("Unknown SPI admission")
    checked_boards(Path(__file__).resolve().parents[2], selected)
    root = Path(source_root).resolve(strict=True)
    new_header = root / HEADER
    if new_header.resolve() != new_header or new_header.exists():
        raise ValueError("Private header path is already occupied")
    expected = dict(SHARED_INPUTS)
    for profile in selected:
        expected.update(PROFILE_INPUTS[profile])
    # Transform the very bytes whose hash was checked, including when an input
    # changes between scanning and generating the overlay.
    inputs = {}
    for name, locked in expected.items():
        path = root / name
        if path.resolve() != path or not path.is_file():
            raise ValueError("Missing or redirected source: " + name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != locked:
            raise ValueError("Source changed before emission: " + name)
        inputs[name] = data.decode("latin-1")
    end = "\tstruct hwspinlock *hwlock;\n};"
    generated = {
        HEADER: PROTOTYPES,
        INTERNAL: _once(inputs[INTERNAL], end,
                        "\tstruct hwspinlock *hwlock;\n\tu8 kconc_sixbyte_start;\n};"),
        REGMAP: _regmap_overlay(inputs[REGMAP], selected),
    }
    for profile in selected:
        core, call, spi, handoff, register = PROFILE_EDITS[profile]
        generated[core] = _once(_include_private_api(inputs[core]), call,
                                call.replace("regmap_bulk_read", "kconc_sixbyte_bulk_read", 1))
        frontend = _controller_check(_include_private_api(inputs[spi]), profile)
        generated[spi] = _once(frontend, handoff, register + handoff)
    return {name: contents.encode("latin-1") for name, contents in generated.items()}

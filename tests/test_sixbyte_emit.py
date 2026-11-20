import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import sixbyte_emit as emit


class SixByteOverlayTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tree = Path(tmp.name).resolve()

        def add(name, data):
            path = self.tree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data.encode("ascii"))
            return hashlib.sha256(path.read_bytes()).hexdigest()

        self.bulk = ("int regmap_bulk_read(struct regmap *map, unsigned int reg, "
                     "void *val, size_t val_count)\n{\n" + emit.LOOP + "\n\treturn 0;\n}")
        shared = {
            emit.REGMAP: add(emit.REGMAP, '#include "internal.h"\n' + self.bulk +
                             "\nEXPORT_SYMBOL_GPL(regmap_bulk_read);\n"),
            emit.INTERNAL: add(emit.INTERNAL, "struct regmap {\n\tstruct hwspinlock *hwlock;\n};\n"),
            "include/linux/regmap.h": add("include/linux/regmap.h", "/* public header */\n"),
        }
        profiles = {}
        for profile, (core, call, spi, handoff, _) in emit.PROFILE_EDITS.items():
            profiles[profile] = {
                core: add(core, "#include <linux/regmap.h>\n" + call + " six);\n"),
                spi: add(spi, "#include <linux/regmap.h>\nstatic int " +
                         profile.removesuffix("-spi") + "_spi_probe(void) {\n" + handoff + "\n}\n"),
            }
        for variable, values in (("SHARED_INPUTS", shared), ("PROFILE_INPUTS", profiles)):
            binding = patch.object(emit, variable, values)
            binding.start()
            self.addCleanup(binding.stop)

    def test_single_profile_keeps_original_and_limits_registration(self):
        result = emit.emit_overlay(self.tree, ["bma400-spi"])
        self.assertNotIn(emit.KX_CORE, result)
        source = result[emit.REGMAP].decode()
        self.assertIn(self.bulk + "\nEXPORT_SYMBOL_GPL(regmap_bulk_read);", source)
        self.assertEqual(source.count(emit.GUARDED_LOOP), 1)
        self.assertIn('EXPORT_SYMBOL_FOR_MODULES(kconc_sixbyte_register, "bma400_spi")', source)
        self.assertIn('EXPORT_SYMBOL_FOR_MODULES(kconc_sixbyte_bulk_read, "bma400_core")', source)
        self.assertFalse((self.tree / emit.HEADER).exists())

    def test_chip_identity_and_transport_limits_precede_core(self):
        result = emit.emit_overlay(self.tree, ["kx022a-spi", "bma400-spi"])
        for profile, (_, _, spi, handoff, _) in emit.PROFILE_EDITS.items():
            source = result[spi].decode()
            self.assertLess(source.index("kconc_sixbyte_register("), source.index(handoff))
            symbol = "kconc_" + profile.removesuffix("-spi") + "_spi_controller"
            self.assertIn("symbol_get(" + symbol + ")", source)
            self.assertIn("symbol_put(" + symbol + ")", source)
            self.assertIn("if (!check)\n\t\treturn false;", source)
            self.assertIn("matched = check(spi->controller);", source)
            self.assertLess(source.index("kconc_reviewed_controller(spi)"),
                            source.index("spi_max_transfer_size(spi)"))
            if profile == "bma400-spi":
                self.assertIn('!strcmp(id->name, "bma400")', source)
                self.assertIn("spi_max_message_size(spi) >= 4", source)
            else:
                self.assertIn("chip_info == &kx022a_chip_info", source)
                self.assertIn("spi_max_message_size(spi) >= 7", source)
        self.assertIn(b"READ_ONCE(map->kconc_sixbyte_start) != reg", result[emit.REGMAP])
        self.assertIn(b"return regmap_bulk_read(map, reg, val, val_count);", result[emit.REGMAP])

    def test_changed_dependency_aborts_before_writing(self):
        header = self.tree / "include/linux/regmap.h"
        header.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Source changed"):
            emit.emit_overlay(self.tree, ["kx022a-spi"])
        self.assertFalse((self.tree / emit.HEADER).exists())

    def test_occupied_header_is_never_overwritten(self):
        header = self.tree / emit.HEADER
        header.write_bytes(b"owned by project")
        with self.assertRaisesRegex(ValueError, "already occupied"):
            emit.emit_overlay(self.tree, ["bma400-spi"])
        self.assertEqual(header.read_bytes(), b"owned by project")

    def test_unreviewed_board_source_is_rejected(self):
        repo = Path(emit.__file__).resolve().parents[2]
        sources = emit.checked_boards(repo, ["kx022a-spi"])
        for name in sources:
            target = self.tree / name
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes((repo / name).read_bytes())
        board = self.tree / "kernel/sixbyte-boards/kx022a_lab.c"
        board.write_bytes(board.read_bytes().replace(b"== lab_transfer", b"!= lab_transfer"))
        with self.assertRaisesRegex(ValueError, "Unreviewed controller"):
            emit.checked_boards(self.tree, ["kx022a-spi"])

    def test_empty_admission_and_unknown_names(self):
        self.assertEqual(emit.emit_overlay(self.tree, []), {})
        with self.assertRaisesRegex(ValueError, "Unknown SPI admission"):
            emit.emit_overlay(self.tree, ["unreviewed-device"])


if __name__ == "__main__":
    unittest.main()

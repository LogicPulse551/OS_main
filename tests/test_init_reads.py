"""A reviewed converter is insufficient when the kernel boot ordering changes."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc import valid_opt


class InitializationPolicyTests(unittest.TestCase):
    def test_changed_boot_source_rejects_even_with_a_valid_format_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            boot = root / "init/main.c"
            boot.parent.mkdir()
            boot.write_text("int main(void) { return 0; }")
            with patch.object(valid_opt, "slot_contract", return_value={}):
                with self.assertRaisesRegex(ValueError, "boot argument and initcall ordering"):
                    valid_opt.init_contract(root)

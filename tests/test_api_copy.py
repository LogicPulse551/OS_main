from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc.api_copy import copy_ir, machine_effect


class BoundedCopyTest(unittest.TestCase):
    # Small instruction fragments in objdump's format, independent of device data.
    dump = (b"unit.o: file format elf64-x86-64\n"
            b"0000000000000000 <bus_read>:\n"
            b"   0:\tc7 01 00 00 00 00    \tmovl   $0x0,(%rcx)\n"
            b"   6:\t66 c7 41 04 00 00    \tmovw   $0x0,0x4(%rcx)\n"
            b"   c:\t2e e9 00 00 00 00    \tcs jmp 12 <bus_read+0x12>\te: R_X86_64_PLT32\t__x86_return_thunk-0x4\n")
    ir = (b"define internal i32 @bus_read(ptr %0, ptr %1, i64 %2, ptr %3, i64 %4) {\n"
          b"  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %3, ptr align 1 @wire, i64 6, i1 false)\n"
          b"  ret i32 0\n}")

    def test_six_bytes_and_true_return_thunk(self):
        self.assertEqual(len(machine_effect(self.dump, "bus_read")), 3)
        self.assertEqual(copy_ir(self.ir, "bus_read", True), "wire")

    def test_external_or_mismatched_machine_effects(self):
        for altered in (self.dump.replace(b"__x86_return_thunk", b"memcpy"),
                        self.dump.replace(b"0x4(%rcx)", b"0x5(%rcx)"),
                        self.dump.replace(b"(%rcx)", b"(%rsi)"),
                        self.dump.replace(b"<bus_read>:", b"<unrelated>:"),
                        self.dump.replace(b"e: R_X86", b"d: R_X86")):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                machine_effect(altered, "bus_read")

    def test_pre_or_post_ir_must_bind_a_six_byte_intrinsic(self):
        for altered in (self.ir.replace(b"@llvm.memcpy.p0.p0.i64", b"@memcpy"),
                        self.ir.replace(b"%3, ptr align 1", b"%1, ptr align 1"),
                        self.ir.replace(b"i64 6,", b"i64 7,"),
                        self.ir.replace(b"ret i32 0", b"call void @unknown()\n  ret i32 0")):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                copy_ir(altered, "bus_read", True)


if __name__ == "__main__":
    unittest.main()

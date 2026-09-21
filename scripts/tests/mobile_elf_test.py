"""Regress APK dependencies with 16 KiB LOADs but 4 KiB RELRO boundaries."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("qualify_android", Path(__file__).resolve().parents[1] / "qualify-android.py")
qualify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualify)


def library(relro_size, alignment=0x4000):
    # Layout observed in DataStore 1.1.7's ARM64 shared counter. LOAD alignment
    # alone passes, while the old RELRO ends at 0x6000 instead of a 16 KiB boundary.
    segments = [
        (1, 5, 0, 0, 0, 0x11C0, 0x11C0, alignment),
        (1, 6, 0x11C0, 0x51C0, 0x51C0, 0x268, 0x268, alignment),
        (0x6474E552, 4, 0x11C0, 0x51C0, 0x51C0, 0x268, relro_size, 1),
    ]
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 3, 183, 1,
        0, 64, 0, 0, 64, 56, len(segments), 0, 0, 0)
    return header + b"".join(struct.pack("<IIQQQQQQ", *segment) for segment in segments)


class MobileElfTests(unittest.TestCase):
    def test_rejects_transitive_library_with_unaligned_relro(self):
        with self.assertRaisesRegex(RuntimeError, "RELRO"):
            qualify.elf_alignment(library(0xE40))

    def test_accepts_aligned_load_and_relro_boundaries(self):
        self.assertEqual(qualify.elf_alignment(library(0x2E40)),
            {"elf_load_alignment": 16384, "elf_relro_aligned": True})

    def test_rejects_four_kib_load_alignment(self):
        with self.assertRaisesRegex(RuntimeError, "LOAD"):
            qualify.elf_alignment(library(0x2E40, 0x1000))

    def test_rejects_truncated_program_headers(self):
        with self.assertRaisesRegex(RuntimeError, "program headers"):
            qualify.elf_alignment(library(0x2E40)[:-1])


if __name__ == "__main__":
    unittest.main()

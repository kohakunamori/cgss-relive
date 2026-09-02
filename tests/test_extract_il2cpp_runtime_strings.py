from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "extract-il2cpp-runtime-strings.py"
SPEC = importlib.util.spec_from_file_location("extract_runtime_strings", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class RuntimeStringReferenceTests(unittest.TestCase):
    def test_decode_string_literal_usage(self) -> None:
        literals = ["zero", "data", "common_define"]
        # Usage kind 5 in the high bits; literal index is stored shifted left by one.
        encoded = (5 << 29) | (2 << 1)
        self.assertEqual(MODULE.decode_metadata_usage(encoded, literals), "common_define")
        self.assertIsNone(MODULE.decode_metadata_usage((3 << 29) | (1 << 1), literals))

    def test_collect_adrp_ldr_pointer_slots(self) -> None:
        lines = [
            " 491f3a4: f001c680      adrp x0, 0x81f2000",
            " 491f3a8: f9445800      ldr x0, [x0, #0x8b0]",
            " 491f40c: 9001c978      adrp x24, 0x824b000",
            " 491f418: f940df18      ldr x24, [x24, #0x1b8]",
        ]
        self.assertEqual(
            MODULE.collect_pointer_slots(lines),
            [(0x491F3A8, 0x81F28B0), (0x491F418, 0x824B1B8)],
        )

    def test_filter_refs_by_address_and_literal(self) -> None:
        refs = [
            {"instruction": 0x1000, "slot": 1, "literal": "noise"},
            {"instruction": 0x1010, "slot": 2, "literal": "data"},
            {"instruction": 0x1020, "slot": 3, "literal": "common_define"},
            {"instruction": 0x1030, "slot": 4, "literal": "data"},
        ]
        self.assertEqual(
            MODULE.filter_refs(refs, start=0x1010, end=0x1030, literals=["data", "common_define"]),
            refs[1:3],
        )
        self.assertEqual(MODULE.filter_refs(refs, literals=["common_define"]), [refs[2]])

    def test_parse_address_accepts_decimal_and_hex(self) -> None:
        self.assertEqual(MODULE.parse_address("4096"), 0x1000)
        self.assertEqual(MODULE.parse_address("0x4852398"), 0x4852398)


if __name__ == "__main__":
    unittest.main()

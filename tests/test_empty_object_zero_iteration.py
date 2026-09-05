from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-empty-object-zero-iteration.py"
SPEC = importlib.util.spec_from_file_location("empty_object_zero_iteration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EmptyObjectZeroIterationTests(unittest.TestCase):
    def test_call_semantic_recognizes_iteration_primitives(self) -> None:
        self.assertEqual(MODULE.call_semantic(["System.Collections.Generic.List$$get_Count"]), "count")
        self.assertEqual(MODULE.call_semantic(["Foo$$GetEnumerator"]), "get-enumerator")
        self.assertEqual(MODULE.call_semantic(["Foo$$MoveNext"]), "move-next")
        self.assertEqual(MODULE.call_semantic(["Foo$$get_Current"]), "current")

    def test_path_to_exit_can_avoid_forbidden_loop_body(self) -> None:
        blocks = {
            0x1000: MODULE.Block(0x1000, [0x1000], {0x1010, 0x1020}),
            0x1010: MODULE.Block(0x1010, [0x1010], {0x1030}),
            0x1020: MODULE.Block(0x1020, [0x1020], {0x1030}),
            0x1030: MODULE.Block(0x1030, [0x1030], set(), terminal="return"),
        }
        cfg = {
            "blocks": blocks,
            "addr_block": {0x1000: 0x1000, 0x1010: 0x1010, 0x1020: 0x1020, 0x1030: 0x1030},
            "reachable": set(blocks),
            "known_exits": {0x1030},
        }
        proof = MODULE.path_to_exit_avoiding(cfg, 0x1010, {0x1020})
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof["exit_block"], 0x1030)
        self.assertEqual(proof["path_blocks"], [0x1010, 0x1030])

    def test_no_path_when_zero_successor_enters_forbidden_index_block(self) -> None:
        blocks = {
            0x1000: MODULE.Block(0x1000, [0x1000], {0x1010}),
            0x1010: MODULE.Block(0x1010, [0x1010], {0x1020}),
            0x1020: MODULE.Block(0x1020, [0x1020], set(), terminal="return"),
        }
        cfg = {
            "blocks": blocks,
            "addr_block": {0x1000: 0x1000, 0x1010: 0x1010, 0x1020: 0x1020},
            "reachable": set(blocks),
            "known_exits": {0x1020},
        }
        self.assertIsNone(MODULE.path_to_exit_avoiding(cfg, 0x1010, {0x1010}))


if __name__ == "__main__":
    unittest.main()

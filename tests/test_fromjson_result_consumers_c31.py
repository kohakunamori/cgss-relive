from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-fromjson-result-consumers-c31.py"
SPEC = importlib.util.spec_from_file_location("c31_fromjson_result", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def _row(route: str, endpoint_id: int, *, target: int = MOD.FROMJSON_SHARED_RVA) -> dict:
    return {
        "route": route,
        "endpoint_id": endpoint_id,
        "task": f"Stage.Task{endpoint_id}",
        "method": f"Stage.Task{endpoint_id}$$Parse",
        "method_rva": 0x1000 + endpoint_id * 0x100,
        "semantic_sinks": [
            {
                "kind": "call-argument",
                "call_kind": "direct",
                "argument_positions": [0],
                "rva": 0x1010 + endpoint_id * 0x100,
                "target_rva": target,
            }
        ],
    }


class FromJsonResultConsumersC31Tests(unittest.TestCase):
    def test_exact_three_shared_fromjson_targets_are_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c28.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_route_count": 3,
                        "routes": [_row("/a", 1), _row("/b", 2), _row("/c", 3)],
                    }
                ),
                encoding="utf-8",
            )
            rows = MOD.load_targets(path)
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row["fromjson_target_rva"] == MOD.FROMJSON_SHARED_RVA for row in rows))

    def test_wrong_fromjson_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c28.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_route_count": 3,
                        "routes": [_row("/a", 1), _row("/b", 2, target=0xDEAD), _row("/c", 3)],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(MOD.C31Error):
                MOD.load_targets(path)


if __name__ == "__main__":
    unittest.main()

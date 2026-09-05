from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-tojson-string-consumer-c29.py"
SPEC = importlib.util.spec_from_file_location("c29_shared_consumer", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def _row(route: str, endpoint_id: int, target: int = 0x9000) -> dict:
    return {
        "route": route,
        "endpoint_id": endpoint_id,
        "method": f"Stage.Task{endpoint_id}$$Parse",
        "semantic_sinks": [
            {
                "kind": "call-argument",
                "call_kind": "direct",
                "argument_positions": [0],
                "rva": 0x1000 + endpoint_id,
                "target_rva": target,
            }
        ],
    }


class ToJsonStringConsumerC29Tests(unittest.TestCase):
    def test_three_routes_must_share_one_direct_x0_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c28.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_route_count": 3,
                        "routes": [
                            _row("/a", 1),
                            _row("/b", 2),
                            _row("/c", 3),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            target, routes = MOD.load_target(path)
            self.assertEqual(target, 0x9000)
            self.assertEqual([row["route"] for row in routes], ["/a", "/b", "/c"])

    def test_distinct_targets_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c28.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_route_count": 3,
                        "routes": [
                            _row("/a", 1),
                            _row("/b", 2, 0xA000),
                            _row("/c", 3),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(MOD.C29Error):
                MOD.load_target(path)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-tojson-result-liveness-c28.py"
SPEC = importlib.util.spec_from_file_location("c28_tojson_liveness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def _route(index: int, *, tojson: bool = True) -> dict:
    target_name = "LitJson.JsonData$$ToJson" if tojson else "Stage.Other$$Use"
    return {
        "route": f"/route/{index}",
        "endpoint_id": index,
        "task": f"Stage.Task{index}",
        "method": f"Stage.Task{index}$$Parse",
        "method_rva": 0x1000 + index * 0x100,
        "data_access_rva": 0x1010 + index * 0x100,
        "consumer_resolution": "direct-managed-consumer",
        "first_direct_managed_consumer": {
            "callsite_rva": 0x1020 + index * 0x100,
            "target_rva": 0x9000 if tojson else 0xA000,
            "target_methods": [{"name": target_name, "signature": "synthetic"}],
        },
    }


class ToJsonResultLivenessC28Tests(unittest.TestCase):
    def test_load_targets_selects_exact_three_tojson_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c20.json"
            rows = [_route(1), _route(2), _route(3), _route(4, tojson=False)]
            rows.extend(
                {
                    "route": f"/other/{i}",
                    "endpoint_id": 100 + i,
                    "consumer_resolution": "no-consumer-recovered",
                }
                for i in range(11)
            )
            path.write_text(
                json.dumps({"schema": 1, "target_route_count": 15, "routes": rows}),
                encoding="utf-8",
            )
            targets = MOD.load_targets(path)
            self.assertEqual([row["route"] for row in targets], ["/route/1", "/route/2", "/route/3"])
            self.assertTrue(all(row["tojson_target_rva"] == 0x9000 for row in targets))

    def test_wrong_tojson_target_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c20.json"
            rows = [_route(1), _route(2)]
            rows.extend(
                {
                    "route": f"/other/{i}",
                    "endpoint_id": 100 + i,
                    "consumer_resolution": "no-consumer-recovered",
                }
                for i in range(13)
            )
            path.write_text(
                json.dumps({"schema": 1, "target_route_count": 15, "routes": rows}),
                encoding="utf-8",
            )
            with self.assertRaises(MOD.C28Error):
                MOD.load_targets(path)


if __name__ == "__main__":
    unittest.main()

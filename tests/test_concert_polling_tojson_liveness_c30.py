from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-concert-polling-tojson-liveness-c30.py"
SPEC = importlib.util.spec_from_file_location("c30_polling_tojson", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class ConcertPollingToJsonC30Tests(unittest.TestCase):
    def _write(self, path: Path, *, op: str = "json-to-json") -> None:
        rows = []
        for i in range(14):
            rows.append({"route": f"/other/{i}", "endpoint_id": i})
        rows.append(
            {
                "route": "/concert/mv_polling",
                "endpoint_id": 306,
                "first_direct_consumer": {
                    "target_rva": 0x2000,
                    "target_methods": [
                        {"name": "Stage.ConcertMVPollingTask$$CheckJson", "signature": "synthetic"}
                    ],
                },
                "helper_json_operations": [
                    {
                        "operation": op,
                        "callsite_rva": 0x2010,
                        "target_rva": 0x9000,
                        "target_methods": [
                            {"name": "LitJson.JsonData$$ToJson", "signature": "synthetic"}
                        ],
                    }
                ],
            }
        )
        path.write_text(
            json.dumps({"schema": 1, "target_route_count": 15, "routes": rows}),
            encoding="utf-8",
        )

    def test_exact_checkjson_tojson_target_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c21.json"
            self._write(path)
            target = MOD.load_target(path)
            self.assertEqual(target["helper_rva"], 0x2000)
            self.assertEqual(target["tojson_callsite_rva"], 0x2010)
            self.assertEqual(target["tojson_target_rva"], 0x9000)

    def test_missing_tojson_operation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c21.json"
            self._write(path, op="json-count")
            with self.assertRaises(MOD.C30Error):
                MOD.load_target(path)


if __name__ == "__main__":
    unittest.main()
